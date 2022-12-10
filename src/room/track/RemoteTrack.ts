import { TrackEvent } from '../events';
import { TrackInvalidError } from '../errors';
import { monitorFrequency } from '../stats';
import { Track } from './Track';
import log from '../../logger';
// @ts-ignore
import Worker from '../../worker/worker?worker';
import { keyRotationMs } from '../defaults';

export default abstract class RemoteTrack extends Track {
  /** @internal */
  receiver?: RTCRtpReceiver;

  worker: any;

  e2eePassword?: string;

  constructor(
    mediaTrack: MediaStreamTrack,
    sid: string,
    kind: Track.Kind,
    receiver?: RTCRtpReceiver,
  ) {
    super(mediaTrack, kind);
    this.sid = sid;
    this.receiver = receiver;
    this.worker = new Worker();
  }

  initializeEncryption(password: string) {
    this.setPassword(password);
    this.decryptTrack();
    setInterval(() => {
      this.worker.postMessage({ operation: 'rotateKey' });
    }, keyRotationMs);
  }

  decryptTrack() {
    if (!this.receiver) {
      throw new TrackInvalidError('unable to decrypt non-existent track');
    }

    try {
      // @ts-expect-error
      if (window.RTCRtpScriptTransform) {
        const options = {
          operation: 'decode',
        };

        // @ts-expect-error
        this.receiver.transform = new RTCRtpScriptTransform(this.worker, options);
      } else {
        // @ts-expect-error
        const { readable, writable } = this.receiver.createEncodedStreams();
        this.worker.postMessage({ operation: 'decode', readable, writable }, [readable, writable]);
      }
    } catch (error) {
      log.error('error creating encoded streams or posting message to worker', { error });
    }
  }

  setPassword(password: string) {
    this.e2eePassword = password;
    this.worker.postMessage({ operation: 'setPassword', password });
  }

  /** @internal */
  setMuted(muted: boolean) {
    if (this.isMuted !== muted) {
      this.isMuted = muted;
      this._mediaStreamTrack.enabled = !muted;
      this.emit(muted ? TrackEvent.Muted : TrackEvent.Unmuted, this);
    }
  }

  /** @internal */
  setMediaStream(stream: MediaStream) {
    // this is needed to determine when the track is finished
    // we send each track down in its own MediaStream, so we can assume the
    // current track is the only one that can be removed.
    this.mediaStream = stream;
    stream.onremovetrack = () => {
      this.receiver = undefined;
      this._currentBitrate = 0;
      this.emit(TrackEvent.Ended, this);
    };
  }

  start() {
    this.startMonitor();
    // use `enabled` of track to enable re-use of transceiver
    super.enable();
  }

  stop() {
    this.stopMonitor();
    // use `enabled` of track to enable re-use of transceiver
    super.disable();
  }

  /* @internal */
  startMonitor() {
    if (!this.monitorInterval) {
      this.monitorInterval = setInterval(() => this.monitorReceiver(), monitorFrequency);
    }
  }

  protected abstract monitorReceiver(): void;
}
