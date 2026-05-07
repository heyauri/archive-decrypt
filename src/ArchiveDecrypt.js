// Archive file decryption base class

const utils = require('./utils');
const ProgressManager = require('./progress');
const commonPasswords = require('./commonPasswords');
const crypto = require('crypto');
const MAX_CACHE_SIZE = 10000;

const CHARSET_PRESETS = {
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    numbers: '0123456789',
    symbols: ' !@#$%^&*()_+-=[]{}|;:\'",./<>?',
    all: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@#$%^&*()_+-=[]{}|;:\'",./<>?',
    alphanumeric: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
};

const DEFAULT_OPTIONS = {
    targetFileName: null,
    charset: null,
    minLength: 1,
    maxLength: 10,
    maxAttempts: Infinity,
    multiFileValidate: false,
    ignoreUnexpectedError: true,
    saveProgress: true,
    loadProgress: true,
    progressInterval: 60000,
    includeCommonPasswords: true,
    commonPasswordsOptions: {
        sequential: true,
        repeated: true,
        birthdays: true,
        patterns: true,
        commonWords: true
    },
    delay: 0
};

class ArchiveDecrypt {
    constructor(archivePath) {
        this.archivePath = archivePath;
        this.decryptMode = null;
        this.decryptPhase = null;
        this.passwordCache = new utils.Cache(MAX_CACHE_SIZE);
        this.progressManager = new ProgressManager(archivePath);
        this.options = { ...DEFAULT_OPTIONS };
        this._internal = {
            dictionaryInfo: {
                hash: null,
                length: null,
            },
            attempts: {
                dictionary: 0,
                bruteForce: 0,
            },
            total: {
                dictionary: 0,
                bruteForce: 0,
            }
        };
        this.targetFile = null;
        this.targetFileNotFound = false;
        this.startTime = null;
        this.stats = null;
        this.lastProgressSave = 0;
        // to avoid directly exit while mode is hybrid but dictionary attack failed
        this.failureModeCount = 0;
        this.failureModeLimit = 1;
    }

    _calculateDictionaryHash(dictionary = [], includeCommonPasswords = true, commonPasswordsOptions = {}) {
        let combinedPasswords = dictionary;
        if (includeCommonPasswords) {
            const commonPwds = [...commonPasswords.generateCommonPasswords(commonPasswordsOptions)];
            const allPasswords = new Set([...combinedPasswords, ...commonPwds]);
            combinedPasswords = [...allPasswords];
        }
        this._internal.dictionaryInfo.hash = crypto.createHash('md5').update(combinedPasswords.join('\n')).digest('hex');
        this._internal.dictionaryInfo.length = dictionary.length; // Only include original dictionary length, not commonPassword
        this._internal.total.dictionary = combinedPasswords.length; // Total includes all passwords
    }

    _normalizeCharset(charset) {
        if (!charset) return charset;
        if (CHARSET_PRESETS[charset]) return CHARSET_PRESETS[charset];
        for (const [, presetValue] of Object.entries(CHARSET_PRESETS)) {
            if (charset === presetValue) return presetValue;
        }
        return charset;
    }

    _validateProgress(loadedProgress, expectedMode, options, validateBoth = false) {
        if (!loadedProgress) return false;
        if (loadedProgress.mode !== expectedMode) return false;

        const checkDictionary = () => {
            const loadedDictInfo = loadedProgress.data?.dictionaryInfo || loadedProgress.dictionaryInfo;
            if (!loadedDictInfo || loadedDictInfo.hash !== this._internal.dictionaryInfo.hash) {
                console.warn('Dictionary has changed, cannot resume progress');
                return false;
            }
            if (!loadedDictInfo || loadedDictInfo.length !== this._internal.dictionaryInfo.length) {
                console.warn('Dictionary length has changed, cannot resume progress');
                return false;
            }
            return true;
        };

        const checkBruteForce = () => {
            const loadedCharset = this._normalizeCharset(loadedProgress.options?.charset);
            const currentCharset = this._normalizeCharset(options.charset);

            if (loadedCharset !== currentCharset) {
                console.warn('Charset has changed, cannot resume progress');
                return false;
            }
            if (loadedProgress.options?.minLength !== options.minLength) {
                console.warn('minLength has changed, cannot resume progress');
                return false;
            }
            if (loadedProgress.options?.maxLength !== options.maxLength) {
                console.warn('maxLength has changed, cannot resume progress');
                return false;
            }
            return true;
        };

        if (expectedMode === 'hybrid' || validateBoth) {
            return checkDictionary() && checkBruteForce();
        }

        if (expectedMode === 'dictionary') {
            return checkDictionary();
        }

        if (expectedMode === 'bruteForce') {
            return checkBruteForce();
        }

        return true;
    }

    _createProgressData(options) {
        const safeOptions = { ...options };
        delete safeOptions.dictionary;

        // Save original charset preset name instead of resolved charset for validation
        const saveOptions = { ...safeOptions };
        if (saveOptions.charset && !CHARSET_PRESETS[saveOptions.charset]) {
            for (const [presetName, presetValue] of Object.entries(CHARSET_PRESETS)) {
                if (saveOptions.charset === presetValue) {
                    saveOptions.charset = presetName;
                    break;
                }
            }
        }

        const progressData = {
            mode: this.decryptMode,
            decryptPhase: this.decryptPhase,
            options: saveOptions,
            data: this._internal
        };

        return progressData;
    }

    async tryPassword(password) {
        if (this.decryptMode !== 'bruteForce') {
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
                    if (this.decryptMode !== 'bruteForce') {
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

    async _attack(options, passwordGenerator, total) {
        this.checkOptions(options);
        this.options = Object.assign({}, this.options, options);
        const { maxAttempts = Infinity, delay = 0, onAttempt, onSuccess, onFailure } = options;
        const safeDelay = this.validateDelay(delay);
        const mode = this.decryptPhase || this.decryptMode;

        await this.initializeTargetFile();
        if (this.targetFileNotFound) {
            console.error(`Target file ${this.options.targetFileName} not found in archive`);
            if (onFailure) onFailure();
            return null;
        }

        let startAttempts = 0;

        if (this.decryptMode === 'hybrid') {
            startAttempts = this._internal.attempts[mode] || 0;
        } else if (this.options.loadProgress) {
            const loadedProgress = this.progressManager.loadProgress();
            if (this._validateProgress(loadedProgress, mode, options)) {
                this._internal = { ...this._internal, ...loadedProgress.data };
                startAttempts = this._internal.attempts[mode] || 0;
                console.log(`Resuming from progress: ${startAttempts} attempts done`);
            } else if (loadedProgress) {
                console.warn('Progress validation failed, starting from scratch');
                this.progressManager.clearProgress();
                this._internal.attempts[mode] = 0;
            } else {
                this._internal.attempts[mode] = 0;
            }
        } else {
            this._internal.attempts[mode] = 0;
        }

        this.startTiming();
        const actualTotal = Math.min(total, maxAttempts);
        const generator = passwordGenerator(startAttempts);
        let currentPasswordIndex = 0;

        for (const password of generator) {
            if (currentPasswordIndex < startAttempts) {
                currentPasswordIndex++;
                continue;
            }

            if (this._internal.attempts[mode] >= maxAttempts) break;

            this._internal.attempts[mode]++;
            currentPasswordIndex++;
            this.stats.attempts = this._internal.attempts[mode];

            if (onAttempt) {
                const speed = this.getSpeed(this._internal.attempts[mode] - startAttempts);
                const eta = this.getETA(this._internal.attempts[mode], actualTotal);
                onAttempt(password, this._internal.attempts[mode], { speed, eta, total: actualTotal });
            }

            try {
                const result = await this.tryPassword(password);
                if (result?.status === true) {
                    this.stats.success = true;
                    if (onSuccess) {
                        const elapsed = this.getElapsedTime() / 1000;
                        const speed = this.getSpeed(this._internal.attempts[mode] - startAttempts);
                        onSuccess(password, this._internal.attempts[mode], { elapsed, speed });
                    }
                    if (this.options.saveProgress) this.progressManager.clearProgress();
                    return password;
                }
                if (result?.message === 'unexpected_error' && !this.options.ignoreUnexpectedError) {
                    throw new Error(`Unexpected error: ${result.extra}`);
                }
            } catch (error) {
                console.error("ArchiveDecrypt encountered attack error:", error);
                if (this.options.saveProgress) {
                    const progressData = this._createProgressData(this.options);
                    this.progressManager.saveProgress(progressData);
                }
                if (onFailure) onFailure();
                return null;
            }

            if (this.options.saveProgress && Date.now() - this.lastProgressSave > this.options.progressInterval) {
                const progressData = this._createProgressData(this.options);
                this.progressManager.saveProgress(progressData);
                this.lastProgressSave = Date.now();
            }

            if (safeDelay > 0) await new Promise(r => setTimeout(r, safeDelay));
        }

        this.failureModeCount++;
        if (this.failureModeCount >= this.failureModeLimit) {
            this.stats.success = false;
            if (onFailure) {
                const elapsed = this.getElapsedTime() / 1000;
                const speed = this.getSpeed(this._internal.attempts[mode] - startAttempts);
                onFailure({ elapsed, speed, attempts: this._internal.attempts[mode] });
            }
            if (this.options.saveProgress) {
                if (this.decryptMode === 'hybrid' && mode === 'dictionary') {
                    const progressData = this._createProgressData(this.options);
                    this.progressManager.saveProgress(progressData);
                } else {
                    this.progressManager.clearProgress();
                }
            }
            return null;
        }
    }

    async dictionaryAttack(options = {}) {
        const {
            dictionary = [],
            maxAttempts = Infinity,
            includeCommonPasswords = true,
            commonPasswordsOptions = {}
        } = options;

        if (this.decryptMode !== 'hybrid') {
            this.decryptMode = 'dictionary';
            this._internal.attempts.dictionary = 0;
            this._internal.attempts.bruteForce = 0;
        }
        this.decryptPhase = 'dictionary';

        let combinedPasswords;
        if (includeCommonPasswords) {
            const commonPwds = commonPasswords.generateCommonPasswords(commonPasswordsOptions);
            combinedPasswords = new Set([...dictionary, ...commonPwds]);
        } else {
            combinedPasswords = new Set(dictionary);
        }

        const passwordArray = [...combinedPasswords];
        const total = passwordArray.length;

        if (!this._internal.dictionaryInfo.hash) {
            this._calculateDictionaryHash(dictionary, includeCommonPasswords, commonPasswordsOptions);
        } else {
            this._internal.total.dictionary = total;
        }

        const passwordGenerator = (startIndex = 0) => {
            let index = startIndex;
            return {
                [Symbol.iterator]: () => ({
                    next: () => {
                        if (index < passwordArray.length && index < maxAttempts + startIndex) {
                            return { value: passwordArray[index++], done: false };
                        }
                        return { done: true };
                    }
                })
            };
        };
        return this._attack(options, passwordGenerator, total);
    }

    async bruteForceAttack(options = {}) {
        this.checkOptions(options);
        if (this.decryptMode !== 'hybrid') {
            this.decryptMode = 'bruteForce';
            this._internal.attempts.dictionary = 0;
            this._internal.attempts.bruteForce = 0;
        }
        this.decryptPhase = 'bruteForce';

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
        this._internal.total.bruteForce = total;

        const passwordGenerator = (startIndex = 0) => {
            return utils.generatePasswords(charset, minLength, maxLength, maxAttempts + startIndex, startIndex);
        };

        return this._attack(options, passwordGenerator, total);
    }

    async hybridAttack(options = {}) {
        this.decryptMode = 'hybrid';
        this.failureModeLimit = 2;
        this.checkOptions(options);

        const { dictionary = [], includeCommonPasswords = true, commonPasswordsOptions = {} } = options;
        this._calculateDictionaryHash(dictionary, includeCommonPasswords, commonPasswordsOptions);


        let hasValidProgress = false;
        if (this.options.loadProgress) {
            const loadedProgress = this.progressManager.loadProgress();
            if (loadedProgress?.mode === 'hybrid') {
                if (this._validateProgress(loadedProgress, 'hybrid', options)) {
                    // Restore complete internal data
                    if (loadedProgress.data) {
                        this._internal = { ...this._internal, ...loadedProgress.data };
                        this.decryptPhase = loadedProgress.decryptPhase || 'dictionary';
                    } else {
                        // Backward compatibility
                        this.decryptPhase = loadedProgress.decryptPhase || 'dictionary';
                        this._internal.attempts.dictionary = loadedProgress.dictAttempts || 0;
                        this._internal.attempts.bruteForce = loadedProgress.bruteAttempts || 0;
                    }
                    hasValidProgress = true;
                    console.log(`Resuming hybrid attack from ${this.decryptPhase} phase (dictionary: ${this._internal.attempts.dictionary}, bruteForce: ${this._internal.attempts.bruteForce})`);
                } else if (loadedProgress) {
                    console.warn('Hybrid progress validation failed, starting from scratch');
                    this.progressManager.clearProgress();
                }
            }
        }

        if (!hasValidProgress) {
            this._internal.attempts.dictionary = 0;
            this._internal.attempts.bruteForce = 0;
        }

        if (!this.decryptPhase) {
            this.decryptPhase = 'dictionary';
        }

        if (this.decryptPhase === 'dictionary') {
            const dictResult = await this.dictionaryAttack(options);
            if (dictResult) return dictResult;
        }

        this.decryptPhase = 'bruteForce';
        return this.bruteForceAttack(options);
    }
}

module.exports = ArchiveDecrypt;
module.exports.CHARSET_PRESETS = CHARSET_PRESETS;
module.exports.DEFAULT_OPTIONS = DEFAULT_OPTIONS;
