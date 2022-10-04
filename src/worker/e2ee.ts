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
const ENCRYPTION_ALGORITHM = 'AES-GCM';

/* We use a 96 bit IV for AES GCM. This is signalled in plain together with the
 packet. See https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams */
const IV_LENGTH = 12;

export function dump(encodedFrame: any, direction: any, max = 16) {
  const data = new Uint8Array(encodedFrame.data);
  let bytes = '';
  for (let j = 0; j < data.length && j < max; j++) {
    bytes += (data[j] < 16 ? '0' : '') + data[j].toString(16) + ' ';
  }
  console.log(
    performance.now().toFixed(2),
    direction,
    bytes.trim(),
    'len=' + encodedFrame.data.byteLength,
    'type=' + (encodedFrame.type || 'audio'),
    'ts=' + encodedFrame.timestamp,
    'ssrc=' + encodedFrame.getMetadata().synchronizationSource,
    'pt=' + (encodedFrame.getMetadata().payloadType || '(unknown)'),
  );
}

async function generateKey(password: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const alg = { name: ENCRYPTION_ALGORITHM, iv };
  const passwordBytes = new TextEncoder().encode(password);
  const passwordHash = await crypto.subtle.digest('SHA-256', passwordBytes);
  const key = await crypto.subtle.importKey('raw', passwordHash, alg, false, [
    'encrypt',
    'decrypt',
  ]);
  return key;
}

export default class E2EEManager {
  currentCryptoKey?: CryptoKey;

  currentPassword?: string;

  useCryptoOffset: Boolean;

  currentKeyIdentifier: number;

  sendCounts: Map<number, number>;

  constructor() {
    this.useCryptoOffset = true;
    this.currentKeyIdentifier = 0;
    this.sendCounts = new Map();
    console.log('in the e2ee constructor');
    // this.rcount = 0;
    // this.scount = 0;
  }

  async setKey(password: string) {
    if (password !== '') {
      console.log('setKey', password);
      const key = await generateKey(password);
      this.currentCryptoKey = key;
      this.currentPassword = password;
    } else {
      delete this.currentCryptoKey;
    }
  }

  // @ts-expect-error
  encodeFunction(encodedFrame, controller) {
    // if (scount++ < 30) {
    //   dump(encodedFrame, 'send');
    // }
    // console.log('encodeFunction', this.currentPassword);
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
          // @ts-expect-error
          UNENCRYPTED_BYTES[encodedFrame.type],
        );

        // Frame trailer contains the R|IV_LENGTH and key index
        const frameTrailer = new Uint8Array(2);

        frameTrailer[0] = IV_LENGTH;
        frameTrailer[1] = this.currentKeyIdentifier;

        // Construct frame trailer. Similar to the frame header described in
        // https://tools.ietf.org/html/draft-omara-sframe-00#section-4.2
        // but we put it at the end.
        //
        // ---------+-------------------------+-+---------+----
        // payload  |IV...(length = IV_LENGTH)|R|IV_LENGTH|KID |
        // ---------+-------------------------+-+---------+----

        return crypto.subtle
          .encrypt(
            {
              name: ENCRYPTION_ALGORITHM,
              iv,
              additionalData: new Uint8Array(encodedFrame.data, 0, frameHeader.byteLength),
            },
            this.currentCryptoKey,
            // @ts-expect-error
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
            (e) => {
              // TODO: surface this to the app.
              console.error(e);

              // We are not enqueuing the frame here on purpose.
            },
          );
      } catch (e) {
        // TODO: surface??
        console.error(e);
      }
    }
    controller.enqueue(encodedFrame);
  }

  async decodeFunction(encodedFrame: any, controller: any) {
    // if (rcount++ < 30) {
    //   dump(encodedFrame, 'recv');
    // }
    // const view = new DataView(encodedFrame.data);
    // const checksum =
    // encodedFrame.data.byteLength > 4 ? view.getUint32(encodedFrame.data.byteLength - 4) : false;
    // console.log('decodeFunction', this.currentPassword);
    if (this.currentCryptoKey && encodedFrame.data.byteLength > 0) {
      try {
        const frameHeader = new Uint8Array(
          encodedFrame.data,
          0,
          // @ts-expect-error
          UNENCRYPTED_BYTES[encodedFrame.type],
        );
        const frameTrailer = new Uint8Array(encodedFrame.data, encodedFrame.data.byteLength - 2, 2);

        const ivLength = frameTrailer[0];
        const iv = new Uint8Array(
          encodedFrame.data,
          encodedFrame.data.byteLength - ivLength - frameTrailer.byteLength,
          ivLength,
        );

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
          this.currentCryptoKey,
          new Uint8Array(encodedFrame.data, cipherTextStart, cipherTextLength),
        );

        const newData = new ArrayBuffer(frameHeader.byteLength + plainText.byteLength);
        const newUint8 = new Uint8Array(newData);

        newUint8.set(new Uint8Array(encodedFrame.data, 0, frameHeader.byteLength));
        newUint8.set(new Uint8Array(plainText), frameHeader.byteLength);

        encodedFrame.data = newData;
      } catch (error) {
        console.error(error);
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
