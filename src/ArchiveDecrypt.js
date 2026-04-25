// Archive file decryption base class

const MAX_CACHE_SIZE = 1000;

const CHARSET_PRESETS = {
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:\'",./<>?',
    all: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:\'",./<>?',
    alphanumeric: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
};

class ArchiveDecrypt {
    constructor(archivePath) {
        this.archivePath = archivePath;
        this.currentDecryptingMode = null;
        this.extractorCache = new Map();
        this.options = {};
        this.targetFile = null;
        this.targetFileNotFound = false;
        this.startTime = null;
        this.stats = null;
    }

    async tryPassword(password) {
        throw new Error('Not implemented');
    }

    checkOptions(options) {
        if (Object.prototype.toString.call(options) !== '[object Object]') {
            throw new Error('Options must be an object');
        }
        if (options.minLength !== undefined && options.maxLength !== undefined) {
            if (options.minLength > options.maxLength) {
                throw new Error('minLength must be less than or equal to maxLength');
            }
        }
        if (options.charset && CHARSET_PRESETS[options.charset]) {
            options.charset = CHARSET_PRESETS[options.charset];
        }
    }

    async initializeTargetFile() {
        // Base class doesn't need to do anything, let subclasses override
    }

    setCache(password, result) {
        if (this.extractorCache.size >= MAX_CACHE_SIZE) {
            const firstKey = this.extractorCache.keys().next().value;
            this.extractorCache.delete(firstKey);
        }
        this.extractorCache.set(password, result);
    }

    getCachedResult(password) {
        if (this.currentDecryptingMode !== 'bruteForce' && this.extractorCache.has(password)) {
            return this.extractorCache.get(password);
        }
        return undefined;
    }

    validateDelay(delay) {
        return Math.max(delay, 0);
    }

    isPasswordError(error) {
        return error.message && (error.message.includes('bad password') ||
            error.message.includes('Bad password') ||
            error.message.includes('not found in archive') === false);
    }

    isTargetFileError(error) {
        return error.message && error.message.includes('not found in archive');
    }

    startTiming() {
        this.startTime = Date.now();
        this.stats = {
            startTime: this.startTime,
            attempts: 0,
            success: null
        };
    }

    getElapsedTime() {
        return Date.now() - this.startTime;
    }

    getSpeed(attempts) {
        const elapsed = this.getElapsedTime() / 1000;
        return elapsed > 0 ? (attempts / elapsed).toFixed(1) : 0;
    }

    getETA(attempts, total) {
        if (!total || total === Infinity) return null;
        const speed = attempts / (this.getElapsedTime() / 1000);
        const remaining = total - attempts;
        if (speed <= 0) return null;
        return Math.ceil(remaining / speed);
    }

    formatTime(seconds) {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins > 0 ? `${mins}m ` : ''}${secs}s`;
    }

    async dictionaryAttack(options = {}) {
        this.checkOptions(options);
        this.options = options;
        const {
            maxAttempts = Infinity,
            dictionary = [],
            delay = 0,
            onAttempt = null,
            onSuccess = null,
            onFailure = null
        } = options;
        this.currentDecryptingMode = 'dictionary';
        const safeDelay = this.validateDelay(delay);

        await this.initializeTargetFile();

        let attempts = 0;
        this.startTiming();
        const total = Math.min(dictionary.length, maxAttempts);
        for (const password of dictionary) {
            if (attempts >= maxAttempts) break;

            attempts++;
            this.stats.attempts = attempts;

            if (onAttempt) {
                const speed = this.getSpeed(attempts);
                const eta = this.getETA(attempts, total);
                onAttempt(password, attempts, { speed, eta, total });
            }

            try {
                const result = await this.tryPassword(password);
                if (result) {
                    const trimmedPassword = password.trim();
                    this.stats.success = true;
                    if (onSuccess) {
                        const elapsed = this.getElapsedTime() / 1000;
                        const speed = this.getSpeed(attempts);
                        onSuccess(trimmedPassword, attempts, { elapsed, speed });
                    }
                    return trimmedPassword;
                }
            } catch (error) {
                if (this.isTargetFileError(error)) {
                    console.error(error.message);
                    if (onFailure) onFailure();
                    return null;
                }
            }

            if (safeDelay > 0) {
                await new Promise(resolve => setTimeout(resolve, safeDelay));
            }
        }

        this.stats.success = false;
        if (onFailure) {
            const elapsed = this.getElapsedTime() / 1000;
            const speed = this.getSpeed(attempts);
            onFailure({ elapsed, speed, attempts });
        }
        return null;
    }

    async bruteForceAttack(options = {}) {
        throw new Error('Not implemented');
    }

    async hybridAttack(options = {}) {
        this.checkOptions(options);
        this.options = options;
        this.currentDecryptingMode = 'hybrid';
        const dictResult = await this.dictionaryAttack(Object.assign({}, this.options, {
            dictionary: options.dictionary,
            delay: options.delay,
            maxAttempts: options.maxAttempts,
            onAttempt: options.onAttempt,
            onSuccess: options.onSuccess,
            onFailure: null
        }));

        if (dictResult) {
            return dictResult;
        }

        return this.bruteForceAttack(options);
    }

    clearCache() {
        this.extractorCache.clear();
    }
}

module.exports = ArchiveDecrypt;
