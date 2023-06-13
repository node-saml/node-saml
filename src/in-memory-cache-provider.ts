/**
 * Simple in memory cache provider.  To be used to store state of requests that needs
 * to be validated/checked when a response is received.
 *
 * This is the default implementation of a cache provider used by Node SAML.  For
 * multiple server instances/load balanced scenarios (I.e. the SAML request could have
 * been generated from a different server/process handling the SAML response) this
 * implementation will NOT be sufficient.
 *
 * The caller should provide their own implementation for a cache provider as defined
 * in the config options.
 */

import { CacheItem, CacheProvider } from "./types";

interface CacheProviderOptions {
  keyExpirationPeriodMs: number;
}

export class InMemoryCacheProvider implements CacheProvider {
  private cacheKeys: Record<string, CacheItem>;
  private options: CacheProviderOptions;
  private lastPrune = 0;
  private prune: () => void;
  private removeKeyIfExpired: (key: keyof typeof this.cacheKeys, nowMs: number) => Promise<void>;

  constructor(options: Partial<CacheProviderOptions>) {
    this.cacheKeys = {};

    this.options = {
      ...options,
      keyExpirationPeriodMs: options.keyExpirationPeriodMs ?? 28800000, // 8 hours,
    };

    // Remove expired cache keys
    this.prune = () => {
      const nowMs = new Date().getTime();

      // Don't call this function more than is needed in high-load environments
      if (nowMs > this.lastPrune + this.options.keyExpirationPeriodMs) {
        const keys = Object.keys(this.cacheKeys);
        const keysToRemove: (keyof typeof this.cacheKeys)[] = [];
        keys.forEach((key) => {
          if (nowMs >= this.cacheKeys[key].createdAt + this.options.keyExpirationPeriodMs) {
            keysToRemove.push(key);
          }
        });

        // No need to await this because we don't care when it gets done
        keysToRemove.forEach((key) => this.removeAsync(key));
        this.lastPrune = nowMs;
      }
    };

    this.removeKeyIfExpired = async (key: keyof typeof this.cacheKeys, nowMs: number) => {
      if (
        this.cacheKeys[key] &&
        nowMs >= this.cacheKeys[key].createdAt + this.options.keyExpirationPeriodMs
      ) {
        await this.removeAsync(key);
      }
    };
  }

  /**
   * Store an item in the cache, using the specified key and value.
   * Internally will keep track of the time the item was added to the cache
   */
  async saveAsync(key: string, value: string): Promise<CacheItem | null> {
    // Remove all expired keys at a later time
    this.prune();

    // Remove the key if it is expired
    const nowMs = new Date().getTime();
    await this.removeKeyIfExpired(key, nowMs);

    if (!this.cacheKeys[key]) {
      this.cacheKeys[key] = {
        createdAt: nowMs,
        value: value,
      };
      return this.cacheKeys[key];
    } else {
      return null;
    }
  }

  /**
   * Returns the value of the specified key in the cache
   */
  async getAsync(key: string): Promise<string | null> {
    // Remove all expired keys at a later time
    this.prune();

    // Remove the key if it is expired
    const nowMs = new Date().getTime();
    await this.removeKeyIfExpired(key, nowMs);

    if (this.cacheKeys[key]) {
      return this.cacheKeys[key].value;
    } else {
      return null;
    }
  }

  /**
   * Removes an item from the cache if it exists
   */
  async removeAsync(key: string | null): Promise<string | null> {
    if (key != null && this.cacheKeys[key]) {
      delete this.cacheKeys[key];
      return key;
    } else {
      return null;
    }
  }
}
