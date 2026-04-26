// Archive file decryption base class

const utils = require('./utils');
const MAX_CACHE_SIZE = 10000;

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
        this.passwordCache = new utils.Cache(MAX_CACHE_SIZE);
        this.options = {
            targetFileName: null,
            charset: null,
            minLength: null,
            maxLength: null,
            maxAttempts: null,
            multiFileValidate: false,
            ignoreUnexpectedError: true
        };
        this.targetFile = null;
        this.targetFileNotFound = false;
        this.startTime = null;
        this.stats = null;
        // to avoid directly exit while mode is hybrid but dictionary attack failed
        this.failureModeCount = 0;
        this.failureModeLimit = 1;
    }

    async tryPassword(password) {
        if (this.currentDecryptingMode !== 'bruteForce') {
            const cached = this.passwordCache.get(password);
            if (cached !== undefined) {
                return cached;
            }
        }

        if (this.targetFileNotFound) {
            throw new Error(`Target file ${this.options.targetFileName} not found in archive`);
        }

        try {
            let result = await this.decryptFile(this.targetFile, password);
            if (result.status === true) {
                this.passwordCache.set(password, result);
                return result;
            }
            if (result.status === false) {
                if (result.message === 'password_error') {
                    if (this.currentDecryptingMode !== 'bruteForce') {
                        this.passwordCache.set(password, result);
                    }
                    return result;
                } else if (result.message === 'unexpected_error' && !this.options.ignoreUnexpectedError) {
                    console.error(`Unexpected error occurred while decrypting file with password ${password}: ${result.extra}`);
                    return result;
                }
            }
        } catch (error) {
            console.error(error);
        }
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

    validateDelay(delay) {
        return Math.max(delay, 0);
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

    /**
     * Common attack method for dictionary and brute force attacks
     * @param {Object} options - Attack options
     * @param {string} mode - Attack mode ('dictionary' or 'bruteForce')
     * @param {Function} passwordGenerator - Password generator function, returns an iterable object
     * @param {number} total - Total attempts to make
     * @private
     */
    async _attack(options, mode, passwordGenerator, total) {
        this.checkOptions(options);
        this.options = Object.assign({}, this.options, options);
        const {
            maxAttempts = Infinity,
            delay = 0,
            onAttempt = null,
            onSuccess = null,
            onFailure = null
        } = options;
        this.currentDecryptingMode = mode;
        const safeDelay = this.validateDelay(delay);

        await this.initializeTargetFile();
        if (this.targetFileNotFound) {
            console.error(`Target file ${this.options.targetFileName} not found in archive`);
            if (onFailure) onFailure();
            return null;
        }

        let attempts = 0;
        this.startTiming();
        const actualTotal = Math.min(total, maxAttempts);

        for (const password of passwordGenerator()) {
            if (attempts >= maxAttempts) break;

            attempts++;
            this.stats.attempts = attempts;

            if (onAttempt) {
                const speed = this.getSpeed(attempts);
                const eta = this.getETA(attempts, actualTotal);
                onAttempt(password, attempts, { speed, eta, total: actualTotal });
            }

            try {
                const result = await this.tryPassword(password);
                if (result && result.status === true) {
                    this.stats.success = true;
                    if (onSuccess) {
                        const elapsed = this.getElapsedTime() / 1000;
                        const speed = this.getSpeed(attempts);
                        onSuccess(password, attempts, { elapsed, speed });
                    }
                    return password;
                }
                if (result && result.message === 'unexpected_error') {
                    if (this.options.ignoreUnexpectedError) {
                        continue;
                    } else {
                        throw new Error(`Unexpected error: ${result.extra}`);
                    }
                }
            } catch (error) {
                console.error("ArchiveDecrypt encounter attack error:", error);
                if (onFailure) onFailure();
                return null;
            }

            if (safeDelay > 0) {
                await new Promise(resolve => setTimeout(resolve, safeDelay));
            }
        }
        this.failureModeCount++;
        if (this.failureModeCount >= this.failureModeLimit) {
            this.stats.success = false;
            if (onFailure) {
                const elapsed = this.getElapsedTime() / 1000;
                const speed = this.getSpeed(attempts);
                onFailure({ elapsed, speed, attempts });
            }
            return null;
        }
    }

    async dictionaryAttack(options = {}) {
        const { dictionary = [], maxAttempts = Infinity } = options;
        const total = dictionary.length;

        const passwordGenerator = () => {
            let index = 0;
            return {
                [Symbol.iterator]: () => ({
                    next: () => {
                        if (index < dictionary.length && index < maxAttempts) {
                            return { value: dictionary[index++], done: false };
                        }
                        return { done: true };
                    }
                })
            };
        };

        return this._attack(options, 'dictionary', passwordGenerator, total);
    }

    async bruteForceAttack(options = {}) {
        const {
            charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
            minLength = 1,
            maxLength = 10,
            maxAttempts = Infinity
        } = options;
        let total = 0;
        for (let i = minLength; i <= maxLength; i++) {
            total += Math.pow(charset.length, i);
        }

        const passwordGenerator = () => {
            return utils.generatePasswords(charset, minLength, maxLength, maxAttempts);
        };

        return this._attack(options, 'bruteForce', passwordGenerator, total);
    }

    async hybridAttack(options = {}) {
        this.currentDecryptingMode = 'hybrid';
        this.failureModeLimit = 2;
        const dictResult = await this.dictionaryAttack(options);
        if (dictResult) {
            return dictResult;
        }
        return this.bruteForceAttack(options);
    }
}

module.exports = ArchiveDecrypt;
