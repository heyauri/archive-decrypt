// Archive file decryption base class

const MAX_CACHE_SIZE = 1000;

class ArchiveDecrypt {
    constructor(archivePath) {
        this.archivePath = archivePath;
        this.currentDecryptingMode = null;
        this.extractorCache = new Map();
        this.options = {};
        this.targetFile = null;
        this.targetFileNotFound = false;
    }

    async tryPassword(password) {
        throw new Error('Not implemented');
    }

    checkOptions(options) {
        if (Object.prototype.toString.call(options) !== '[object Object]') {
            throw new Error('Options must be an object');
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
        for (const password of dictionary) {
            if (attempts >= maxAttempts) break;

            attempts++;
            if (onAttempt) onAttempt(password, attempts);

            try {
                const result = await this.tryPassword(password);
                if (result) {
                    const trimmedPassword = password.trim();
                    if (onSuccess) onSuccess(trimmedPassword, attempts);
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

        if (onFailure) onFailure();
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
            onFailure: options.onFailure
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
