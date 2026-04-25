// Archive file decryption base class

class ArchiveDecrypt {
    constructor(archivePath) {
        this.archivePath = archivePath;
        this.currentDecryptingMode = null;
        this.extractorCache = new Map(); // Cache extractor instances
        this.options = {};
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
                if (error.message && error.message.includes('not found in archive')) {
                    console.error(error.message);
                    if (onFailure) onFailure();
                    return null;
                }
            }

            if (delay > 0) {
                await new Promise(resolve => setTimeout(resolve, delay));
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
