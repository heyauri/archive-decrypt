// Archive file decryption base class

class ArchiveDecrypt {
    constructor(archivePath) {
        this.archivePath = archivePath;
        this.extractorCache = new Map(); // Cache extractor instances
    }

    // Try to decrypt with password
    async tryPassword(password) {
        throw new Error('Not implemented');
    }

    // Dictionary attack
    async dictionaryAttack(dictionary, options = {}) {
        const {
            maxAttempts = Infinity,
            delay = 0,
            onAttempt = null,
            onSuccess = null,
            onFailure = null
        } = options;

        let attempts = 0;
        for (const password of dictionary) {
            if (attempts >= maxAttempts) break;

            attempts++;
            if (onAttempt) onAttempt(password, attempts);

            try {
                const result = await this.tryPassword(password);
                if (result) {
                    if (onSuccess) onSuccess(password, attempts);
                    return password;
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
    async hybridAttack(dictionary, bruteForceOptions = {}) {
        // Try dictionary attack first
        const dictResult = await this.dictionaryAttack(dictionary, {
            onAttempt: bruteForceOptions.onAttempt,
            onSuccess: bruteForceOptions.onSuccess
        });

        if (dictResult) {
            return dictResult;
        }

        // Try brute force attack if dictionary attack fails
        return this.bruteForceAttack(bruteForceOptions);
    }

    // Clear cache
    clearCache() {
        this.extractorCache.clear();
    }
}

module.exports = ArchiveDecrypt;