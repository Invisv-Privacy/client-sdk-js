import EventEmitter from 'events';
import type TypedEmitter from 'typed-emitter';
import { KEY_PROVIDER_DEFAULTS } from './constants';
import type { KeyProviderCallbacks, KeyInfo, KeyProviderOptions } from './types';
import { createKeyMaterialFromString } from './utils';

export class BaseKeyProvider extends (EventEmitter as new () => TypedEmitter<KeyProviderCallbacks>) {
  private keyInfoMap: Map<string, KeyInfo>;

  private options: KeyProviderOptions;

  constructor(options: Partial<KeyProviderOptions> = {}) {
    super();
    this.keyInfoMap = new Map();
    this.options = { ...KEY_PROVIDER_DEFAULTS, ...options };
    this.on('keyRatcheted', this.onKeyRatcheted);
  }

  /**
   * callback to invoke once a key has been set for a participant
   * @param key
   * @param participantId
   * @param keyIndex
   */
  protected onSetEncryptionKey(key: CryptoKey, participantId?: string, keyIndex?: number) {
    const keyInfo: KeyInfo = { key, participantId, keyIndex };
    this.keyInfoMap.set(`${participantId ?? 'shared'}-${keyIndex ?? 0}`, keyInfo);
    this.emit('setKey', keyInfo);
  }

  /**
   * callback being invoked after a ratchet request has been performed on the local participant
   * that surfaces the new key material. participant id will be `undefined`
   * @param material
   * @param participantId
   * @param keyIndex
   */
  protected onKeyRatcheted = (material: CryptoKey, keyIndex?: number) => {
    console.debug('key ratcheted event received', material, keyIndex);
  };

  getKeys() {
    return Array.from(this.keyInfoMap.values());
  }

  getOptions() {
    return this.options;
  }

  ratchetKey(participantId?: string, keyIndex?: number) {
    this.emit('ratchetRequest', participantId, keyIndex);
  }
}

/**
 * A basic KeyProvider implementation intended for a single shared
 * passphrase between all participants
 */
export class ExternalE2EEKeyProvider extends BaseKeyProvider {
  ratchetInterval: number | undefined;

  constructor(options: Partial<KeyProviderOptions> = { sharedKey: true }) {
    super(options);
  }

  /**
   * Accepts a passphrase that's used to create the crypto keys
   * @param key
   */
  async setKey(key: string) {
    const derivedKey = await createKeyMaterialFromString(key);
    this.onSetEncryptionKey(derivedKey);
    // setTimeout(() => {
    //   clearInterval(this.ratchetInterval);
    //   this.ratchetInterval = setInterval(() => {
    //     this.ratchetKey();
    //   }, 5000) as unknown as number;
    // }, 5000);
  }
}