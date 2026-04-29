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
    symbols: '!@#$%^&*()_+-=[]{}|;:\'",./<>?',
    all: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:\'",./<>?',
    alphanumeric: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
};

class ArchiveDecrypt {
    constructor(archivePath) {
        this.archivePath = archivePath;
        this.currentDecryptingMode = null;
        this.passwordCache = new utils.Cache(MAX_CACHE_SIZE);
        this.progressManager = new ProgressManager(archivePath);
        this.options = {
            targetFileName: null,
            charset: null,
            minLength: null,
            maxLength: null,
            maxAttempts: null,
            multiFileValidate: false,
            ignoreUnexpectedError: true,
            saveProgress: true,
            loadProgress: true,
            progressInterval: 60000
        };
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
     * Validate if progress can be safely resumed
     * @param {Object} loadedProgress - Loaded progress data
     * @param {string} mode - Current attack mode
     * @param {Object} options - Current options (user input)
     * @returns {boolean} Whether can resume
     */
    _validateProgress(loadedProgress, mode, options) {
        if (!loadedProgress) return false;
        if (loadedProgress.mode !== mode) return false;

        if (mode === 'dictionary') {
            // Validate dictionary hash and length from internal object
            if (!loadedProgress.internal || loadedProgress.internal._dictHash !== this._internal._dictHash) {
                console.warn('Dictionary has changed, cannot resume from progress');
                return false;
            }
            if (!loadedProgress.internal || loadedProgress.internal._dictLength !== this._internal._dictLength) {
                console.warn('Dictionary length has changed, cannot resume from progress');
                return false;
            }
        } else if (mode === 'bruteForce') {
            // Validate charset, minLength, maxLength
            if (loadedProgress.options?.charset !== options.charset) {
                console.warn('Charset has changed, cannot resume from progress');
                return false;
            }
            if (loadedProgress.options?.minLength !== options.minLength) {
                console.warn('minLength has changed, cannot resume from progress');
                return false;
            }
            if (loadedProgress.options?.maxLength !== options.maxLength) {
                console.warn('maxLength has changed, cannot resume from progress');
                return false;
            }
        }

        return true;
    }

    /**
     * Create progress data object
     * @param {string} mode - Attack mode
     * @param {number} attempts - Current attempt count
     * @param {Object} options - Options object (user input only)
     * @param {boolean} _hybridMode - Whether in hybrid mode
     * @param {string} currentPhase - Current phase (hybrid mode)
     * @param {number} hybridDictAttempts - Dictionary attempts (hybrid mode)
     * @param {number} hybridBruteAttempts - Brute force attempts (hybrid mode)
     * @returns {Object} Progress data object
     */
    _createProgressData(mode, attempts, options, _hybridMode, currentPhase, hybridDictAttempts, hybridBruteAttempts) {
        // Create safe options object (without dictionary array)
        const safeOptions = { ...options };
        delete safeOptions.dictionary;

        let progressData;
        if (_hybridMode) {
            // Save complete progress for hybrid mode
            progressData = {
                mode: 'hybrid',
                currentPhase: currentPhase || mode,
                dictAttempts: mode === 'dictionary' ? attempts : hybridDictAttempts,
                bruteAttempts: mode === 'bruteForce' ? attempts : hybridBruteAttempts,
                options: safeOptions,
                internal: {
                    _dictHash: this._internal._dictHash,
                    _dictLength: this._internal._dictLength
                }
            };
        } else {
            // Save progress for single mode
            progressData = {
                mode,
                attempts,
                options: safeOptions
            };
            // Save dictionary validation info in internal object
            if (mode === 'dictionary') {
                progressData.internal = {
                    _dictHash: this._internal._dictHash,
                    _dictLength: this._internal._dictLength
                };
            }
        }
        return progressData;
    }

    /**
     * Common attack method for dictionary and brute force attacks
     * @param {Object} options - Attack options (user input only)
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
                console.error("ArchiveDecrypt encounter attack error:", error);
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

        // Create combined password set
        let combinedPasswords;
        if (includeCommonPasswords) {
            const commonPwds = commonPasswords.generateCommonPasswords(commonPasswordsOptions);
            // Combine both sources in one Set operation
            combinedPasswords = new Set([...dictionary, ...commonPwds]);
        } else {
            combinedPasswords = new Set(dictionary);
        }

        // Convert to array for hashing and total count
        const passwordArray = [...combinedPasswords];
        const total = passwordArray.length;

        // Calculate dictionary hash for validation and store in this._internal
        this._internal._dictHash = crypto.createHash('md5').update(passwordArray.join('\n')).digest('hex');
        this._internal._dictLength = passwordArray.length;

        // Set hybrid mode data if present
        if (options._hybridMode) {
            this._internal._hybridMode = true;
            this._internal._hybridDictAttempts = options._hybridDictAttempts || 0;
        } else {
            // Clear hybrid mode data for single mode
            this._internal._hybridMode = false;
            this._internal._hybridDictAttempts = 0;
            this._internal._hybridBruteAttempts = 0;
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

        // Create clean options without internal properties
        const cleanOptions = { ...options };
        delete cleanOptions._hybridMode;
        delete cleanOptions._hybridDictAttempts;
        delete cleanOptions._hybridBruteAttempts;

        return this._attack(cleanOptions, 'dictionary', passwordGenerator, total);
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

        const passwordGenerator = (startIndex = 0) => {
            return utils.generatePasswords(charset, minLength, maxLength, maxAttempts + startIndex, startIndex);
        };

        // Set internal data
        if (options._hybridMode) {
            this._internal._hybridMode = true;
            this._internal._hybridDictAttempts = options._hybridDictAttempts || 0;
            this._internal._hybridBruteAttempts = options._hybridBruteAttempts || 0;
        } else {
            // Clear hybrid mode data for single mode
            this._internal._hybridMode = false;
            this._internal._hybridDictAttempts = 0;
            this._internal._hybridBruteAttempts = 0;
        }

        // Create clean options without internal properties
        const cleanOptions = { ...options };
        delete cleanOptions._hybridMode;
        delete cleanOptions._hybridDictAttempts;
        delete cleanOptions._hybridBruteAttempts;

        return this._attack(cleanOptions, 'bruteForce', passwordGenerator, total);
    }

    async hybridAttack(options = {}) {
        this.currentDecryptingMode = 'hybrid';
        this.failureModeLimit = 2;

        // Calculate dictionary hash for validation and store in this._internal
        const { dictionary = [] } = options;
        this._internal._dictHash = crypto.createHash('md5').update(dictionary.join('\n')).digest('hex');
        this._internal._dictLength = dictionary.length;

        // Check if there is saved progress
        let loadedProgress = null;
        let currentPhase = 'dictionary';
        let dictAttempts = 0;
        let bruteAttempts = 0;

        if (this.options.loadProgress) {
            loadedProgress = this.progressManager.loadProgress();
            if (loadedProgress && loadedProgress.mode === 'hybrid') {
                // Validate hybrid mode progress
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

    /**
     * Validate hybrid mode progress
     * @param {Object} loadedProgress - Loaded progress data
     * @param {Object} options - Current options (user input)
     * @returns {boolean} Whether can resume
     */
    _validateHybridProgress(loadedProgress, options) {
        if (!loadedProgress) return false;
        if (loadedProgress.mode !== 'hybrid') return false;

        // Validate dictionary parameters from internal object
        if (!loadedProgress.internal || loadedProgress.internal._dictHash !== this._internal._dictHash) {
            console.warn('Dictionary has changed, cannot resume hybrid progress');
            return false;
        }
        if (!loadedProgress.internal || loadedProgress.internal._dictLength !== this._internal._dictLength) {
            console.warn('Dictionary length has changed, cannot resume hybrid progress');
            return false;
        }

        // Validate brute force parameters
        if (loadedProgress.options?.charset !== options.charset) {
            console.warn('Charset has changed, cannot resume hybrid progress');
            return false;
        }
        if (loadedProgress.options?.minLength !== options.minLength) {
            console.warn('minLength has changed, cannot resume hybrid progress');
            return false;
        }
        if (loadedProgress.options?.maxLength !== options.maxLength) {
            console.warn('maxLength has changed, cannot resume hybrid progress');
            return false;
        }

        return true;
    }
}

module.exports = ArchiveDecrypt;
