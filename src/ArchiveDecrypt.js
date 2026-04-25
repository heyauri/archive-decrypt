// Archive file decryption base class

class ArchiveDecrypt {
    constructor(archivePath) {
        this.archivePath = archivePath;
        this.currentDecryptingMode = null;
        this.extractorCache = new Map(); // Cache extractor instances
    }

    // Try to decrypt with password
    async tryPassword(password) {
        throw new Error('Not implemented');
    }

    // Dictionary attack
    async dictionaryAttack(options = {}) {
        const {
            maxAttempts = Infinity,
            dictionary = [],
            delay = 0,
            onAttempt = null,
            onSuccess = null,
            onFailure = null
        } = options;
        this.currentDecryptingMode = 'dictionary';

        let attempts = 0;
        for (const password of dictionary) {
            if (attempts >= maxAttempts) break;

            attempts++;
            if (onAttempt) onAttempt(password, attempts);

            try {
                const result = await this.tryPassword(password);
                if (result) {
                    // Remove any trailing whitespace (like \r from Windows line endings)
                    const trimmedPassword = password.trim();
                    if (onSuccess) onSuccess(trimmedPassword, attempts);
                    return trimmedPassword;
                }
            } catch (error) {
                // Password error will throw exception, continue trying
            }

            if (delay > 0) {
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }

        if (onFailure) onFailure();
        return null;
    }

    // Brute force attack
    async bruteForceAttack(options = {}) {
        throw new Error('Not implemented');
    }

    // Hybrid attack (dictionary + brute force)
    async hybridAttack(options = {}) {
        this.currentDecryptingMode = 'hybrid';
        // Try dictionary attack first
        const dictResult = await this.dictionaryAttack({
            dictionary: options.dictionary,
            delay: options.delay,
            maxAttempts: options.maxAttempts,
            onAttempt: options.onAttempt,
            onSuccess: options.onSuccess,
            onFailure: options.onFailure
        });

        if (dictResult) {
            return dictResult;
        }

        // Try brute force attack if dictionary attack fails
        return this.bruteForceAttack(options);
    }

    // Clear cache
    clearCache() {
        this.extractorCache.clear();
    }
}

module.exports = ArchiveDecrypt;