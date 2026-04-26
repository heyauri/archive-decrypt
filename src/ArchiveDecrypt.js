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
            multiFileValidate: false
        };
        this.targetFile = null;
        this.targetFileNotFound = false;
        this.startTime = null;
        this.stats = null;
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
                } else if (result.message === 'unexpected_error') {
                    throw new Error(`Unexpected error: ${result.extra}`);
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
                if (result.status === true) {
                    this.stats.success = true;
                    if (onSuccess) {
                        const elapsed = this.getElapsedTime() / 1000;
                        const speed = this.getSpeed(attempts);
                        onSuccess(password, attempts, { elapsed, speed });
                    }
                    return password;
                }
            } catch (error) {
                console.error(error);
                if (onFailure) onFailure();
                return null;
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
        this.checkOptions(options);
        this.options = options;
        const {
            charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
            minLength = 1,
            maxLength = 10,
            maxAttempts = Infinity,
            delay = 0,
            onAttempt = null,
            onSuccess = null,
            onFailure = null
        } = options;
        this.currentDecryptingMode = 'bruteForce';
        const safeDelay = this.validateDelay(delay);

        await this.initializeTargetFile();
        if (this.targetFileNotFound) {
            console.error(`Target file ${this.options.targetFileName} not found in archive`);
            if (onFailure) onFailure();
            return null;
        }

        let attempts = 0;
        this.startTiming();

        let total = 0;
        for (let i = minLength; i <= maxLength; i++) {
            total += Math.pow(charset.length, i);
        }
        total = Math.min(total, maxAttempts);

        for (const password of utils.generatePasswords(charset, minLength, maxLength, maxAttempts)) {
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
                    this.stats.success = true;
                    if (onSuccess) {
                        const elapsed = this.getElapsedTime() / 1000;
                        const speed = this.getSpeed(attempts);
                        onSuccess(password, attempts, { elapsed, speed });
                    }
                    return password;
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
}

module.exports = ArchiveDecrypt;
