import { CacheItem, CacheProvider } from "./types";

interface CacheProviderOptions {
  /**
   * How long a key lasts after it is saved, in milliseconds. Defaults to 8 hours. Set it to the
   * `requestIdExpirationPeriodMs` of the `SAML` instances that use this cache.
   */
  keyExpirationPeriodMs: number;
}

/**
 * The `cacheProvider` a `SAML` instance creates when given none. It keeps keys in this process's
 * memory, so it cannot serve request IDs across servers or processes; supply a shared store there.
 *
 * Within one process, pass the same instance to every `SAML` instance that has to recognize the
 * request IDs of the others, such as ones constructed per request.
 */
export class InMemoryCacheProvider implements CacheProvider {
  private cacheKeys: Record<string, CacheItem>;
  private options: CacheProviderOptions;
  private lastPrune = 0;
  private prune: () => void;
  private removeKeyIfExpired: (key: keyof typeof this.cacheKeys, nowMs: number) => Promise<void>;

  constructor(options: Partial<CacheProviderOptions> = {}) {
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
   * Removes an item from the cache and returns its value, or null if it was absent or expired
   */
  async consumeAsync(key: string): Promise<string | null> {
    const item = this.cacheKeys[key];
    if (item == null) {
      return null;
    }

    delete this.cacheKeys[key];
    const nowMs = new Date().getTime();
    return nowMs < item.createdAt + this.options.keyExpirationPeriodMs ? item.value : null;
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
