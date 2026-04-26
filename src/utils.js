// Utility functions module

/**
 * Iteratively generate passwords to avoid memory issues
 * @param {string} charset - Character set
 * @param {number} minLength - Minimum password length
 * @param {number} maxLength - Maximum password length
 * @param {number} maxAttempts - Maximum number of attempts
 * @returns {Generator<string>} - Password generator
 */
function* generatePasswords(charset, minLength, maxLength, maxAttempts, startPassword = '') {
    let attempts = 0;

    for (let length = minLength; length <= maxLength; length++) {
        const passwordIndices = Array(length).fill(0);
        const charsetLength = charset.length;
        let hasMorePasswords = true;
        const passwordChars = new Array(length);

        while (hasMorePasswords) {
            if (attempts >= maxAttempts) break;

            for (let i = 0; i < length; i++) {
                passwordChars[i] = charset[passwordIndices[i]];
            }
            const password = passwordChars.join('');

            yield password;
            attempts++;

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

        if (attempts >= maxAttempts) break;
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
        if (this.cache.size >= this.maxSize) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }
        this.cache.set(key, value);
    }
    get(key) {
        return this.cache.get(key);
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
