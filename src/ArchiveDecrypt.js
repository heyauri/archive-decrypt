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
        this.currentDecryptingMode = null;
        this.passwordCache = new utils.Cache(MAX_CACHE_SIZE);
        this.progressManager = new ProgressManager(archivePath);
        this.options = { ...DEFAULT_OPTIONS };
        this._internal = {};
        this.targetFile = null;
        this.targetFileNotFound = false;
        this.startTime = null;
        this.stats = null;
        this.lastProgressSave = 0;
        // to avoid directly exit while mode is hybrid but dictionary attack failed
        this.failureModeCount = 0;
        this.failureModeLimit = 1;
    }

    _initializeAttackState(options, isHybridMode = false, hybridPhase = null) {
        if (isHybridMode) {
            this._internal._hybridMode = true;
            if (hybridPhase === 'dictionary') {
                this._internal._hybridDictAttempts = options._hybridDictAttempts || 0;
            } else if (hybridPhase === 'bruteForce') {
                this._internal._hybridBruteAttempts = options._hybridBruteAttempts || 0;
            }
        } else {
            this._internal._hybridMode = false;
            this._internal._hybridDictAttempts = 0;
            this._internal._hybridBruteAttempts = 0;
        }
    }

    _createCleanOptions(options) {
        const cleanOptions = { ...options };
        delete cleanOptions._hybridMode;
        delete cleanOptions._hybridDictAttempts;
        delete cleanOptions._hybridBruteAttempts;
        return cleanOptions;
    }

    _calculateDictionaryHash(dictionary = [], includeCommonPasswords = true, commonPasswordsOptions = {}) {
        let combinedPasswords = dictionary;
        if (includeCommonPasswords) {
            const commonPwds = [...commonPasswords.generateCommonPasswords(commonPasswordsOptions)];
            const allPasswords = new Set([...combinedPasswords, ...commonPwds]);
            combinedPasswords = [...allPasswords];
        }
        this._internal._dictHash = crypto.createHash('md5').update(combinedPasswords.join('\n')).digest('hex');
        this._internal._dictLength = combinedPasswords.length;
    }

    _validateProgress(loadedProgress, mode, options) {
        if (!loadedProgress) return false;
        if (loadedProgress.mode !== mode) return false;

        if (mode === 'dictionary') {
            if (!loadedProgress.internal || loadedProgress.internal._dictHash !== this._internal._dictHash) {
                console.warn('Dictionary has changed, cannot resume progress');
                return false;
            }
            if (!loadedProgress.internal || loadedProgress.internal._dictLength !== this._internal._dictLength) {
                console.warn('Dictionary length has changed, cannot resume progress');
                return false;
            }
        } else if (mode === 'bruteForce') {
            // Normalize both charsets for comparison
            const normalizeCharset = (charset) => {
                if (charset && CHARSET_PRESETS[charset]) {
                    return CHARSET_PRESETS[charset];
                }
                if (charset) {
                    for (const [presetName, presetValue] of Object.entries(CHARSET_PRESETS)) {
                        if (charset === presetValue) {
                            return presetValue;
                        }
                    }
                }
                return charset;
            };

            const loadedCharset = normalizeCharset(loadedProgress.options?.charset);
            const currentCharset = normalizeCharset(options.charset);

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
        }

        return true;
    }

    _validateHybridProgress(loadedProgress, options) {
        if (!loadedProgress) return false;
        if (loadedProgress.mode !== 'hybrid') return false;

        if (!loadedProgress.internal || loadedProgress.internal._dictHash !== this._internal._dictHash) {
            console.warn('Dictionary has changed, cannot resume progress');
            return false;
        }
        if (!loadedProgress.internal || loadedProgress.internal._dictLength !== this._internal._dictLength) {
            console.warn('Dictionary length has changed, cannot resume progress');
            return false;
        }

        // Normalize both charsets for comparison
        const normalizeCharset = (charset) => {
            if (charset && CHARSET_PRESETS[charset]) {
                return CHARSET_PRESETS[charset];
            }
            if (charset) {
                for (const [presetName, presetValue] of Object.entries(CHARSET_PRESETS)) {
                    if (charset === presetValue) {
                        return presetValue;
                    }
                }
            }
            return charset;
        };

        const loadedCharset = normalizeCharset(loadedProgress.options?.charset);
        const currentCharset = normalizeCharset(options.charset);

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
    }

    _createProgressData(mode, attempts, options, _hybridMode, currentPhase, hybridDictAttempts, hybridBruteAttempts) {
        const safeOptions = { ...options };
        delete safeOptions.dictionary;

        // Save original charset preset name instead of resolved charset for validation
        const saveOptions = { ...safeOptions };
        if (saveOptions.charset && CHARSET_PRESETS[saveOptions.charset]) {
            // Already using preset name, leave as is
        } else {
            // Check if it's actually a resolved preset value and find the original preset name
            for (const [presetName, presetValue] of Object.entries(CHARSET_PRESETS)) {
                if (saveOptions.charset === presetValue) {
                    saveOptions.charset = presetName;
                    break;
                }
            }
        }

        let progressData;
        if (_hybridMode) {
            progressData = {
                mode: 'hybrid',
                currentPhase: currentPhase || mode,
                dictAttempts: mode === 'dictionary' ? attempts : hybridDictAttempts,
                bruteAttempts: mode === 'bruteForce' ? attempts : hybridBruteAttempts,
                options: saveOptions,
                internal: {
                    _dictHash: this._internal._dictHash,
                    _dictLength: this._internal._dictLength
                }
            };
        } else {
            progressData = {
                mode,
                attempts,
                options: saveOptions
            };
            if (mode === 'dictionary') {
                progressData.internal = {
                    _dictHash: this._internal._dictHash,
                    _dictLength: this._internal._dictLength
                };
            }
        }
        return progressData;
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
        const {
            _hybridMode = false,
            _hybridDictAttempts = 0,
            _hybridBruteAttempts = 0
        } = this._internal;
        this.currentDecryptingMode = mode;
        const safeDelay = this.validateDelay(delay);

        await this.initializeTargetFile();
        if (this.targetFileNotFound) {
            console.error(`Target file ${this.options.targetFileName} not found in archive`);
            if (onFailure) onFailure();
            return null;
        }

        let startAttempts = 0;
        let loadedProgress = null;
        let hybridDictAttempts = _hybridDictAttempts;
        let hybridBruteAttempts = _hybridBruteAttempts;

        if (this.options.loadProgress && !_hybridMode) {
            loadedProgress = this.progressManager.loadProgress();
            if (this._validateProgress(loadedProgress, mode, options)) {
                startAttempts = loadedProgress.attempts || 0;
                console.log(`Resuming from progress: ${startAttempts} attempts done`);
            } else if (loadedProgress) {
                console.warn('Progress validation failed, starting from scratch');
                // Clear incompatible progress
                this.progressManager.clearProgress();
            }
        } else if (_hybridMode) {
            // Use specified start attempts for hybrid mode
            if (mode === 'dictionary') {
                startAttempts = _hybridDictAttempts;
            } else {
                startAttempts = _hybridBruteAttempts;
            }
        }

        let attempts = startAttempts;
        this.startTiming();
        const actualTotal = Math.min(total, maxAttempts);

        const generator = passwordGenerator(startAttempts);
        let currentPasswordIndex = 0;

        for (const password of generator) {
            if (currentPasswordIndex < startAttempts) {
                currentPasswordIndex++;
                continue;
            }

            if (attempts >= maxAttempts) break;

            attempts++;
            currentPasswordIndex++;
            this.stats.attempts = attempts;

            if (onAttempt) {
                const speed = this.getSpeed(attempts - startAttempts);
                const eta = this.getETA(attempts, actualTotal);
                onAttempt(password, attempts, { speed, eta, total: actualTotal });
            }

            try {
                const result = await this.tryPassword(password);
                if (result && result.status === true) {
                    this.stats.success = true;
                    if (onSuccess) {
                        const elapsed = this.getElapsedTime() / 1000;
                        const speed = this.getSpeed(attempts - startAttempts);
                        onSuccess(password, attempts, { elapsed, speed });
                    }
                    if (this.options.saveProgress) {
                        this.progressManager.clearProgress();
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
                console.error("ArchiveDecrypt encountered attack error:", error);
                if (this.options.saveProgress) {
                    const progressData = this._createProgressData(mode, attempts, this.options, _hybridMode, mode, hybridDictAttempts, hybridBruteAttempts);
                    this.progressManager.saveProgress(progressData);
                }
                if (onFailure) onFailure();
                return null;
            }

            if (this.options.saveProgress && Date.now() - this.lastProgressSave > this.options.progressInterval) {
                const progressData = this._createProgressData(mode, attempts, this.options, _hybridMode, mode, hybridDictAttempts, hybridBruteAttempts);
                this.progressManager.saveProgress(progressData);
                this.lastProgressSave = Date.now();
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
                const speed = this.getSpeed(attempts - startAttempts);
                onFailure({ elapsed, speed, attempts });
            }
            if (this.options.saveProgress) {
                if (_hybridMode) {
                    // One phase completed in hybrid mode, save progress for next phase
                    const nextPhase = mode === 'dictionary' ? 'bruteForce' : null;
                    if (nextPhase) {
                        const progressData = this._createProgressData(mode, attempts, this.options, _hybridMode, nextPhase, hybridDictAttempts, hybridBruteAttempts);
                        this.progressManager.saveProgress(progressData);
                    } else {
                        this.progressManager.clearProgress();
                    }
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

        let combinedPasswords;
        if (includeCommonPasswords) {
            const commonPwds = commonPasswords.generateCommonPasswords(commonPasswordsOptions);
            combinedPasswords = new Set([...dictionary, ...commonPwds]);
        } else {
            combinedPasswords = new Set(dictionary);
        }

        // Convert to array for hashing and total count
        const passwordArray = [...combinedPasswords];
        const total = passwordArray.length;

        if (!options._hybridMode || !this._internal._dictHash) {
            this._internal._dictHash = crypto.createHash('md5').update(passwordArray.join('\n')).digest('hex');
            this._internal._dictLength = passwordArray.length;
        }

        this._initializeAttackState(options, !!options._hybridMode, 'dictionary');

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

        const cleanOptions = this._createCleanOptions(options);
        return this._attack(cleanOptions, 'dictionary', passwordGenerator, total);
    }

    async bruteForceAttack(options = {}) {
        // Parse charset preset first
        this.checkOptions(options);

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

        const passwordGenerator = (startIndex = 0) => {
            return utils.generatePasswords(charset, minLength, maxLength, maxAttempts + startIndex, startIndex);
        };

        this._initializeAttackState(options, !!options._hybridMode, 'bruteForce');
        const cleanOptions = this._createCleanOptions(options);
        return this._attack(cleanOptions, 'bruteForce', passwordGenerator, total);
    }

    async hybridAttack(options = {}) {
        this.currentDecryptingMode = 'hybrid';
        this.failureModeLimit = 2;

        // Parse charset preset first
        this.checkOptions(options);

        const { dictionary = [], includeCommonPasswords = true, commonPasswordsOptions = {} } = options;
        this._calculateDictionaryHash(dictionary, includeCommonPasswords, commonPasswordsOptions);

        let loadedProgress = null;
        let currentPhase = 'dictionary';
        let dictAttempts = 0;
        let bruteAttempts = 0;

        if (this.options.loadProgress) {
            loadedProgress = this.progressManager.loadProgress();
            if (loadedProgress && loadedProgress.mode === 'hybrid') {
                if (this._validateHybridProgress(loadedProgress, options)) {
                    currentPhase = loadedProgress.currentPhase || 'dictionary';
                    dictAttempts = loadedProgress.dictAttempts || 0;
                    bruteAttempts = loadedProgress.bruteAttempts || 0;
                    console.log(`Resuming hybrid attack from ${currentPhase} phase (dict: ${dictAttempts}, brute: ${bruteAttempts})`);
                } else if (loadedProgress) {
                    console.warn('Hybrid progress validation failed, starting from scratch');
                    this.progressManager.clearProgress();
                }
            }
        }

        // Execute dictionary attack phase
        let dictResult = null;
        if (currentPhase === 'dictionary') {
            const dictOptions = {
                ...options,
                _hybridMode: true,
                _hybridDictAttempts: dictAttempts
            };
            dictResult = await this.dictionaryAttack(dictOptions);
            if (dictResult) {
                return dictResult;
            }
        }

        // Execute brute force attack phase
        const bruteOptions = {
            ...options,
            _hybridMode: true,
            _hybridBruteAttempts: bruteAttempts
        };
        return this.bruteForceAttack(bruteOptions);
    }
}

module.exports = ArchiveDecrypt;
module.exports.CHARSET_PRESETS = CHARSET_PRESETS;
module.exports.DEFAULT_OPTIONS = DEFAULT_OPTIONS;
