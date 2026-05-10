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
        this._signalHandlersSetup = false;

        this._setupSignalHandlers();
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

    /**
     * Normalize charset to preset name if possible
     */
    _normalizeCharset(charset) {
        if (!charset) return charset;
        if (CHARSET_PRESETS[charset]) return CHARSET_PRESETS[charset];
        for (const [, presetValue] of Object.entries(CHARSET_PRESETS)) {
            if (charset === presetValue) return presetValue;
        }
        return charset;
    }

    /**
     * Get charset preset name from value
     */
    _getCharsetPresetName(charset) {
        if (!charset) return charset;
        if (CHARSET_PRESETS[charset]) return charset;
        for (const [presetName, presetValue] of Object.entries(CHARSET_PRESETS)) {
            if (charset === presetValue) return presetName;
        }
        return charset;
    }

    /**
     * Validate dictionary info from progress
     */
    _validateDictionaryProgress(loadedProgress) {
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
    }

    /**
     * Validate brute force parameters from progress
     */
    _validateBruteForceProgress(loadedProgress, options) {
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
    }

    /**
     * Validate loaded progress
     */
    _validateProgress(loadedProgress, expectedMode, options, validateBoth = false) {
        if (!loadedProgress) return false;
        if (loadedProgress.mode !== expectedMode) return false;

        if (expectedMode === 'hybrid' || validateBoth) {
            return this._validateDictionaryProgress(loadedProgress) &&
                this._validateBruteForceProgress(loadedProgress, options);
        }

        if (expectedMode === 'dictionary') {
            return this._validateDictionaryProgress(loadedProgress);
        }

        if (expectedMode === 'bruteForce') {
            return this._validateBruteForceProgress(loadedProgress, options);
        }

        return true;
    }

    /**
     * Create progress data object
     */
    _createProgressData(options) {
        const safeOptions = { ...options };
        delete safeOptions.dictionary;

        const saveOptions = { ...safeOptions };
        saveOptions.charset = this._getCharsetPresetName(saveOptions.charset);
        // Handle Infinity for JSON serialization
        if (saveOptions.maxAttempts === Infinity) {
            saveOptions.maxAttempts = null;
        }

        return {
            mode: this.decryptMode,
            decryptPhase: this.decryptPhase,
            options: saveOptions,
            data: this._internal
        };
    }

    /**
     * Reset attack attempts for non-hybrid mode
     */
    _resetAttemptsIfNotHybrid() {
        if (this.decryptMode !== 'hybrid') {
            this._internal.attempts.dictionary = 0;
            this._internal.attempts.bruteForce = 0;
        }
    }

    /**
     * Validate attack options
     */
    _validateAttackOptions(options) {
        this.checkOptions(options);

        if (options.minLength !== undefined && options.maxLength !== undefined) {
            if (options.minLength < 1) {
                throw new Error('minLength must be at least 1');
            }
            if (options.maxLength > 100) {
                throw new Error('maxLength must be at most 100');
            }
        }

        if (options.maxAttempts !== undefined && options.maxAttempts !== Infinity) {
            if (!Number.isInteger(options.maxAttempts) || options.maxAttempts < 1) {
                throw new Error('maxAttempts must be a positive integer');
            }
        }

        if (options.delay !== undefined) {
            if (!Number.isFinite(options.delay) || options.delay < 0) {
                throw new Error('delay must be a non-negative number');
            }
        }

        return true;
    }

    /**
     * Save progress and handle errors
     */
    _saveProgress() {
        try {
            const progressData = this._createProgressData(this.options);
            this.progressManager.saveProgress(progressData);
            this.lastProgressSave = Date.now();
        } catch (err) {
            console.warn('Failed to save progress:', err.message);
        }
    }

    /**
     * Setup signal handlers for pause/resume
     */
    _setupSignalHandlers() {
        if (this._signalHandlersSetup) return;

        this._signalHandlersSetup = true;
        let saveInProgress = false;

        const handleSignal = (signal) => {
            if (saveInProgress) return;
            saveInProgress = true;

            console.log(`\n\nReceived ${signal}, saving progress...`);

            if (this.options.saveProgress) {
                try {
                    this._saveProgress();
                    console.log('Progress saved. Next run will resume from here.');
                } catch (error) {
                    console.error('Error saving progress:', error);
                }
            }

            process.exit(0);
        };

        // Handle all possible interrupt signals
        process.on('SIGINT', handleSignal);  // Ctrl+C
        process.on('SIGTERM', handleSignal); // Terminate
        process.on('SIGBREAK', handleSignal); // Ctrl+Break (Windows)

        // Windows-specific: listen for keypress events (more reliable)
        if (process.platform === 'win32') {
            const readline = require('readline');
            const rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout
            });

            rl.on('SIGINT', () => {
                handleSignal('SIGINT (readline)');
            });
        }

        // Prevent uncaught exceptions from crashing without saving progress
        process.on('uncaughtException', (error) => {
            console.error('\n\nUncaught exception:', error);
            if (this.options.saveProgress) {
                console.log('Saving progress before exit...');
                this._saveProgress();
            }
            process.exit(1);
        });

        // Also handle exit event as a fallback
        process.on('exit', (code) => {
            if (code !== 0 && this.options.saveProgress && !saveInProgress) {
                // Only save if exiting with an error code and not already saved
                console.log('\nProcess exiting with code', code);
                this._saveProgress();
            }
        });
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
            // Add a tiny timeout to ensure signal handlers can run
            await new Promise(resolve => setImmediate(resolve));

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

    getETA(attempts, total, offset = 0) {
        if (!total || total === Infinity) return null;
        const actualAttempts = attempts - offset;
        const speed = actualAttempts / (this.getElapsedTime() / 1000);
        const remaining = total - attempts;
        if (speed <= 0 || remaining <= 0) return null;
        const seconds = Math.ceil(remaining / speed);

        // Format to readable time string
        let result = '';
        if (seconds >= 86400) {
            const days = Math.floor(seconds / 86400);
            result += `${days}d `;
        }
        if (seconds >= 3600) {
            const hours = Math.floor((seconds % 86400) / 3600);
            result += `${hours}h `;
        }
        if (seconds >= 60) {
            const minutes = Math.floor((seconds % 3600) / 60);
            result += `${minutes}m `;
        }
        const secs = seconds % 60;
        result += `${secs}s`;

        return result.trim();
    }

    async _attack(options, passwordGenerator, total) {
        this._validateAttackOptions(options);
        this.options = Object.assign({}, this.options, options);
        const { maxAttempts: _maxAttempts = Infinity, delay = 0, onAttempt, onSuccess, onFailure } = options;
        // Fix: handle null or undefined from JSON serialization
        const maxAttempts = (_maxAttempts === null || _maxAttempts === undefined || _maxAttempts === Infinity) ? Infinity : _maxAttempts;
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
                // Restore complete internal data
                if (loadedProgress.data) {
                    this._internal = { ...this._internal, ...loadedProgress.data };
                    startAttempts = this._internal.attempts[mode] || 0;
                } else {
                    // Backward compatibility
                    startAttempts = loadedProgress.attempts || 0;
                    this._internal.attempts[mode] = startAttempts;
                }
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
        let currentPasswordIndex = startAttempts;

        for (const password of generator) {
            if (this._internal.attempts[mode] >= maxAttempts) break;

            this._internal.attempts[mode]++;
            currentPasswordIndex++;
            this.stats.attempts = this._internal.attempts[mode];

            if (onAttempt) {
                const speed = this.getSpeed(this._internal.attempts[mode] - startAttempts);
                const eta = this.getETA(this._internal.attempts[mode], actualTotal, startAttempts);
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
                    this._saveProgress();
                }
                if (onFailure) onFailure();
                return null;
            }

            if (this.options.saveProgress && Date.now() - this.lastProgressSave > this.options.progressInterval) {
                this._saveProgress();
            }

            if (safeDelay > 0) await new Promise(r => setTimeout(r, safeDelay));
        }

        // Only count as failure mode if it's not hybrid mode's dictionary phase
        if (!(this.decryptMode === 'hybrid' && mode === 'dictionary')) {
            this.failureModeCount++;
        }

        if (this.failureModeCount >= this.failureModeLimit) {
            this.stats.success = false;
            if (onFailure) {
                const elapsed = this.getElapsedTime() / 1000;
                const speed = this.getSpeed(this._internal.attempts[mode] - startAttempts);
                onFailure({ elapsed, speed, attempts: this._internal.attempts[mode] });
            }
            if (this.options.saveProgress) {
                if (this.decryptMode === 'hybrid' && mode === 'dictionary') {
                    this._saveProgress();
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
        }
        this.decryptPhase = 'dictionary';
        this._resetAttemptsIfNotHybrid();

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
            const actualMaxAttempts = (maxAttempts === null || maxAttempts === undefined || maxAttempts === Infinity) ? Infinity : maxAttempts;
            return {
                [Symbol.iterator]: () => ({
                    next: () => {
                        const maxIndex = actualMaxAttempts === Infinity ? Infinity : actualMaxAttempts + startIndex;
                        if (index < passwordArray.length && (actualMaxAttempts === Infinity || index < maxIndex)) {
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
        if (this.decryptMode !== 'hybrid') {
            this.decryptMode = 'bruteForce';
        }
        this.decryptPhase = 'bruteForce';
        this._resetAttemptsIfNotHybrid();

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
            const actualMaxAttempts = (maxAttempts === null || maxAttempts === undefined || maxAttempts === Infinity) ? Infinity : maxAttempts;
            const maxPasswords = actualMaxAttempts === Infinity ? Infinity : actualMaxAttempts + startIndex;
            return utils.generatePasswords(charset, minLength, maxLength, maxPasswords, startIndex);
        };

        return this._attack(options, passwordGenerator, total);
    }

    async hybridAttack(options = {}) {
        this.decryptMode = 'hybrid';
        this.failureModeLimit = 2;

        const { dictionary = [], includeCommonPasswords = true, commonPasswordsOptions = {} } = options;
        this._calculateDictionaryHash(dictionary, includeCommonPasswords, commonPasswordsOptions);

        let hasValidProgress = false;
        if (this.options.loadProgress) {
            const loadedProgress = this.progressManager.loadProgress();
            if (loadedProgress?.mode === 'hybrid') {
                if (this._validateProgress(loadedProgress, 'hybrid', options)) {
                    if (loadedProgress.data) {
                        this._internal = { ...this._internal, ...loadedProgress.data };
                        this.decryptPhase = loadedProgress.decryptPhase || 'dictionary';
                    } else {
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

        // Check if dictionary attack was not completed even if decryptPhase says bruteForce
        if (this._internal.attempts.dictionary < this._internal.total.dictionary) {
            console.log(`Dictionary attack not completed (${this._internal.attempts.dictionary}/${this._internal.total.dictionary}), finishing it first...`);
            this.decryptPhase = 'dictionary';
        } else if (!this.decryptPhase) {
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
