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
 * @param options
 * @constructor
 */

import { CacheItem, CacheProvider } from "./types";

interface CacheProviderOptions {
  keyExpirationPeriodMs: number;
}

export class InMemoryCacheProvider implements CacheProvider {
  private cacheKeys: Record<string, CacheItem>;
  private options: CacheProviderOptions;

  constructor(options: Partial<CacheProviderOptions>) {
    this.cacheKeys = {};

    this.options = {
      ...options,
      keyExpirationPeriodMs: options?.keyExpirationPeriodMs ?? 28800000, // 8 hours,
    };

    // Expire old cache keys
    const expirationTimer = setInterval(() => {
      const nowMs = new Date().getTime();
      const keys = Object.keys(this.cacheKeys);
      keys.forEach((key) => {
        if (
          nowMs >=
          new Date(this.cacheKeys[key].createdAt).getTime() + this.options.keyExpirationPeriodMs
        ) {
          this.removeAsync(key);
        }
      });
    }, this.options.keyExpirationPeriodMs);

    // we only want this to run if the process is still open; it shouldn't hold the process open (issue #68)
    expirationTimer.unref();
  }

  /**
   * Store an item in the cache, using the specified key and value.
   * Internally will keep track of the time the item was added to the cache
   * @param id
   * @param value
   */
  async saveAsync(key: string, value: string): Promise<CacheItem | null> {
    if (!this.cacheKeys[key]) {
      this.cacheKeys[key] = {
        createdAt: new Date().getTime(),
        value: value,
      };
      return this.cacheKeys[key];
    } else {
      return null;
    }
  }

  /**
   * Returns the value of the specified key in the cache
   * @param id
   * @returns {boolean}
   */
  async getAsync(key: string): Promise<string | null> {
    if (this.cacheKeys[key]) {
      return this.cacheKeys[key].value;
    } else {
      return null;
    }
  }

  /**
   * Removes an item from the cache if it exists
   * @param key
   */
  async removeAsync(key: string): Promise<string | null> {
    if (this.cacheKeys[key]) {
      delete this.cacheKeys[key];
      return key;
    } else {
      return null;
    }
  }
}
