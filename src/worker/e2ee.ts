import log, { setLogLevel } from '../logger';

// TODO: not sure if there's a way to properly share this with the parent/non-worker library 😬
setLogLevel('debug');

// Large parts of this e2ee code is borrowed from jitsi's implementation:
// https://github.com/jitsi/lib-jitsi-meet/blob/84277e1ff3fa925b60d70fe76aea57e8bf182843/modules/e2ee/Context.js#L11-L20
//
// Documentation/comments are kept inline here for easier reference

const ENCRYPTION_ALGORITHM = 'AES-GCM';

/* We use a 96 bit IV for AES GCM. This is signalled in plain together with the
 packet. See https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams */
const IV_LENGTH = 12;

// Our encoded frame with frame trailer:
//
// ---------+-------------------------+-+---------+----
// payload  |IV...(length = IV_LENGTH)|R|IV_LENGTH|KID |
// ---------+-------------------------+-+---------+----
//
// The trailer is similar to the frame header described in
// https://tools.ietf.org/html/draft-omara-sframe-00#section-4.2
// but we put it at the end.

// We copy the first bytes of the VP8 payload unencrypted.
// For keyframes this is 10 bytes, for non-keyframes (delta) 3. See
//   https://tools.ietf.org/html/rfc6386#section-9.1
// This allows the bridge to continue detecting keyframes (only one byte needed in the JVB)
// and is also a bit easier for the VP8 decoder (i.e. it generates funny garbage pictures
// instead of being unable to decode).
// This is a bit for show and we might want to reduce to 1 unconditionally in the final version.
//
// For audio (where frame.type is not set) we do not encrypt the opus TOC byte:
//   https://tools.ietf.org/html/rfc6716#section-3.1
const UNENCRYPTED_BYTES = {
  key: 10,
  delta: 3,
  undefined: 1, // frame.type is not set on audio
};

// We use a single byte for the key identifier in the frame trailer so we can have a
// circular array of one byte's worth of keys
const KEY_RING_SIZE = 256;

type Chunk = {
  synchronizationSource: number;
  data: ArrayBuffer;
  type: keyof typeof UNENCRYPTED_BYTES;
  timestamp: number;
  getMetadata: () => {
    synchronizationSource: number;
    payloadType: string;
  };
};

export function dump(encodedFrame: Chunk, direction: string, max = 16) {
  const data = new Uint8Array(encodedFrame.data);
  let bytes = '';
  for (let j = 0; j < data.length && j < max; j++) {
    bytes += (data[j] < 16 ? '0' : '') + data[j].toString(16) + ' ';
  }
  log.trace('e2ee frame dump', {
    performance: performance.now().toFixed(2),
    direction,
    bytes: bytes.trim(),
    len: encodedFrame.data.byteLength,
    frameType: encodedFrame.type || 'audio',
    timestamp: encodedFrame.timestamp,
    synchronizationSource: encodedFrame.getMetadata().synchronizationSource,
    payloadType: encodedFrame.getMetadata().payloadType || '(unknown)',
  });
}

async function generatePresharedKey(password: string) {
  const passwordBytes = new TextEncoder().encode(password);
  const presharedKey = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, [
    'deriveBits',
    'deriveKey',
  ]);

  log.debug('generated preshared key', { presharedKey });
  return presharedKey;
}

export default class E2EEManager {
  keyRing: Array<CryptoKey>;

  currentKeyId: number;

  sendCounts: Map<number, number>;

  presharedKey: CryptoKey | undefined;

  constructor() {
    this.keyRing = new Array(KEY_RING_SIZE);
    this.currentKeyId = 0;
    this.sendCounts = new Map();
  }

  async setPassword(password: string) {
    if (password !== '') {
      this.presharedKey = await generatePresharedKey(password);
      this.currentKeyId = 0;

      await this.prefillKeyRing();

      log.debug('prefilled key ring', { keyRing: this.keyRing });
    }
  }

  async generateNextKeyForId(id: number): Promise<CryptoKey> {
    if (!this.presharedKey) {
      throw new Error('presharedKey must be set');
    }
    const alg = { name: ENCRYPTION_ALGORITHM, length: 256 };
    const nextKeyId = (id + 1) % this.keyRing.length;
    const keyIdSalt = new Int8Array(1);
    keyIdSalt[0] = nextKeyId;
    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: keyIdSalt,
        iterations: 1,
        hash: 'SHA-256',
      },
      this.presharedKey,
      alg,
      false,
      ['encrypt', 'decrypt'],
    );
    return key;
  }

  async prefillKeyRing() {
    for (let i = 0; i < this.keyRing.length; i++) {
      const key = await this.generateNextKeyForId(i);
      const nextKeyId = (i + 1) % this.keyRing.length;
      this.keyRing[nextKeyId] = key;
    }
  }

  get currentCryptoKey() {
    return this.keyRing[this.currentKeyId];
  }

  async rotateKey() {
    log.debug('rotating key', { currentCryptoKey: this.currentCryptoKey });
    try {
      if (this.currentCryptoKey) {
        const nextKeyId = (this.currentKeyId + 1) % this.keyRing.length;
        this.currentKeyId = nextKeyId;
        log.debug('rotated key', {
          currentCryptoKey: this.currentCryptoKey,
          currentKeyId: this.currentKeyId,
        });
      }
    } catch (error) {
      log.error('failed to rotate key', { error });
    }
  }

  getKeyForId(id: number) {
    const key = this.keyRing[id];
    if (!key) {
      throw new Error(`key for id: ${id} not found`);
    }
    return key;
  }

  /**
   * The VP8 payload descriptor described in
   * https://tools.ietf.org/html/rfc7741#section-4.2
   * is part of the RTP packet and not part of the frame and is not controllable by us.
   * This is fine as the SFU keeps having access to it for routing.
   *
   * The encrypted frame is formed as follows:
   * 1) Leave the first (10, 3, 1) bytes unencrypted, depending on the frame type and kind.
   * 2) Form the GCM IV for the frame as described above.
   * 3) Encrypt the rest of the frame using AES-GCM.
   * 4) Allocate space for the encrypted frame.
   * 5) Copy the unencrypted bytes to the start of the encrypted frame.
   * 6) Append the ciphertext to the encrypted frame.
   * 7) Append the IV.
   * 8) Append a single byte for the key identifier.
   * 9) Enqueue the encrypted frame for sending.
   */
  encodeFunction(encodedFrame: Chunk, controller: TransformStreamDefaultController) {
    // if (scount++ < 30) {
    //   dump(encodedFrame, 'send');
    // }
    if (this.currentCryptoKey && encodedFrame.data.byteLength > 0) {
      try {
        const iv = this.makeIV(
          encodedFrame.getMetadata().synchronizationSource,
          encodedFrame.timestamp,
        );

        // Thіs is not encrypted and contains the VP8 payload descriptor or the Opus TOC byte.
        const frameHeader = new Uint8Array(
          encodedFrame.data,
          0,
          UNENCRYPTED_BYTES[encodedFrame.type],
        );

        // Frame trailer contains the R|IV_LENGTH and key index
        const frameTrailer = new Uint8Array(2);

        frameTrailer[0] = IV_LENGTH;
        frameTrailer[1] = this.currentKeyId;

        return crypto.subtle
          .encrypt(
            {
              name: ENCRYPTION_ALGORITHM,
              iv,
              additionalData: new Uint8Array(encodedFrame.data, 0, frameHeader.byteLength),
            },
            this.currentCryptoKey,
            new Uint8Array(encodedFrame.data, UNENCRYPTED_BYTES[encodedFrame.type]),
          )
          .then(
            (cipherText) => {
              const newData = new ArrayBuffer(
                frameHeader.byteLength +
                  cipherText.byteLength +
                  iv.byteLength +
                  frameTrailer.byteLength,
              );
              const newUint8 = new Uint8Array(newData);

              newUint8.set(frameHeader); // copy first bytes.
              newUint8.set(new Uint8Array(cipherText), frameHeader.byteLength); // add ciphertext.
              newUint8.set(new Uint8Array(iv), frameHeader.byteLength + cipherText.byteLength); // append IV.
              newUint8.set(
                frameTrailer,
                frameHeader.byteLength + cipherText.byteLength + iv.byteLength,
              ); // append frame trailer.

              encodedFrame.data = newData;

              return controller.enqueue(encodedFrame);
            },
            (error) => {
              // TODO: surface this to the app.
              log.error('error encrypting', { error });

              // We are not enqueuing the frame here on purpose.
            },
          );
      } catch (error) {
        // TODO: surface this to the app?
        log.error('error encoding/encrypting', { error });
      }
    }
    controller.enqueue(encodedFrame);
  }

  async decodeFunction(encodedFrame: Chunk, controller: TransformStreamDefaultController) {
    // if (rcount++ < 30) {
    //   dump(encodedFrame, 'recv');
    // }
    if (this.currentCryptoKey && encodedFrame.data.byteLength > 0) {
      try {
        const frameHeader = new Uint8Array(
          encodedFrame.data,
          0,
          UNENCRYPTED_BYTES[encodedFrame.type],
        );
        const frameTrailer = new Uint8Array(encodedFrame.data, encodedFrame.data.byteLength - 2, 2);

        const ivLength = frameTrailer[0];
        const iv = new Uint8Array(
          encodedFrame.data,
          encodedFrame.data.byteLength - ivLength - frameTrailer.byteLength,
          ivLength,
        );

        const keyId = frameTrailer[1];
        const key = this.getKeyForId(keyId);

        const cipherTextStart = frameHeader.byteLength;
        const cipherTextLength =
          encodedFrame.data.byteLength -
          (frameHeader.byteLength + ivLength + frameTrailer.byteLength);

        const plainText = await crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv,
            additionalData: new Uint8Array(encodedFrame.data, 0, frameHeader.byteLength),
          },
          key,
          new Uint8Array(encodedFrame.data, cipherTextStart, cipherTextLength),
        );

        const newData = new ArrayBuffer(frameHeader.byteLength + plainText.byteLength);
        const newUint8 = new Uint8Array(newData);

        newUint8.set(new Uint8Array(encodedFrame.data, 0, frameHeader.byteLength));
        newUint8.set(new Uint8Array(plainText), frameHeader.byteLength);

        encodedFrame.data = newData;
      } catch (error) {
        log.error('error decoding/decrypting', { error });
      }
    }
    controller.enqueue(encodedFrame);
  }

  /**
   * Construct the IV used for AES-GCM and sent (in plain) with the packet similar to
   * https://tools.ietf.org/html/rfc7714#section-8.1
   * It concatenates
   * - the 32 bit synchronization source (SSRC) given on the encoded frame,
   * - the 32 bit rtp timestamp given on the encoded frame,
   * - a send counter that is specific to the SSRC. Starts at a random number.
   * The send counter is essentially the pictureId but we currently have to implement this ourselves.
   * There is no XOR with a salt. Note that this IV leaks the SSRC to the receiver but since this is
   * randomly generated and SFUs may not rewrite this is considered acceptable.
   * The SSRC is used to allow demultiplexing multiple streams with the same key, as described in
   *   https://tools.ietf.org/html/rfc3711#section-4.1.1
   * The RTP timestamp is 32 bits and advances by the codec clock rate (90khz for video, 48khz for
   * opus audio) every second. For video it rolls over roughly every 13 hours.
   * The send counter will advance at the frame rate (30fps for video, 50fps for 20ms opus audio)
   * every second. It will take a long time to roll over.
   *
   * See also https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams
   */
  makeIV(synchronizationSource: number, timestamp: number) {
    const iv = new ArrayBuffer(IV_LENGTH);
    const ivView = new DataView(iv);

    // having to keep our own send count (similar to a picture id) is not ideal.
    if (!this.sendCounts.has(synchronizationSource)) {
      // Initialize with a random offset, similar to the RTP sequence number.
      this.sendCounts.set(synchronizationSource, Math.floor(Math.random() * 0xffff));
    }

    const sendCount = this.sendCounts.get(synchronizationSource) || 0;

    ivView.setUint32(0, synchronizationSource);
    ivView.setUint32(4, timestamp);
    ivView.setUint32(8, sendCount % 0xffff);

    this.sendCounts.set(synchronizationSource, sendCount + 1);

    return iv;
  }
}
