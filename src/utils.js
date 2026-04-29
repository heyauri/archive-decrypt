// Utility functions module

/**
 * Iteratively generate passwords to avoid memory issues
 * @param {string} charset - Character set
 * @param {number} minLength - Minimum password length
 * @param {number} maxLength - Maximum password length
 * @param {number} maxAttempts - Maximum number of attempts
 * @returns {Generator<string>} - Password generator
 */
function* generatePasswords(charset, minLength, maxLength, maxAttempts, startIndex = 0) {
    let generatedCount = 0;

    for (let length = minLength; length <= maxLength; length++) {
        const passwordIndices = Array(length).fill(0);
        const charsetLength = charset.length;
        let hasMorePasswords = true;
        const passwordChars = new Array(length);

        while (hasMorePasswords) {
            if (generatedCount >= maxAttempts) break;

            for (let i = 0; i < length; i++) {
                passwordChars[i] = charset[passwordIndices[i]];
            }
            const password = passwordChars.join('');

            if (generatedCount >= startIndex) {
                yield password;
            }
            generatedCount++;

            let position = length - 1;
            while (position >= 0) {
                passwordIndices[position]++;
                if (passwordIndices[position] < charsetLength) {
                    break;
                } else {
                    passwordIndices[position] = 0;
                    position--;
                }
            }
            if (position < 0) {
                hasMorePasswords = false;
            }
        }

        if (generatedCount >= maxAttempts) break;
    }
}

function formatTime(seconds) {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins > 0 ? `${mins}m ` : ''}${secs}s`;
}

class Cache {
    constructor(maxSize) {
        this.cache = new Map();
        this.maxSize = maxSize;
    }
    set(key, value) {
        if (this.cache.has(key)) {
            this.cache.delete(key);
        }
        if (this.cache.size >= this.maxSize) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }
        this.cache.set(key, value);
    }
    get(key) {
        if (!this.cache.has(key)) {
            return undefined;
        }
        const value = this.cache.get(key);
        this.cache.delete(key);
        this.cache.set(key, value);
        return value;
    }
    has(key) {
        return this.cache.has(key);
    }
    clear() {
        this.cache.clear();
    }
}

module.exports = {
    generatePasswords,
    formatTime,
    Cache
};
