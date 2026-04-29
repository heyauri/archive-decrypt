/**
 * Generate common passwords
 */

/**
 * Generate sequential numbers (123, 1234, 123456, etc.)
 * @param {number} minLength - Minimum length
 * @param {number} maxLength - Maximum length
 * @returns {Set<string>} Sequential number passwords
 */
function generateSequentialNumbers(minLength = 3, maxLength = 8) {
    const passwords = new Set();
    for (let len = minLength; len <= maxLength; len++) {
        let password = '';
        for (let i = 0; i < len; i++) {
            password += (i + 1).toString();
        }
        passwords.add(password.slice(0, len));
    }
    return passwords;
}

/**
 * Generate repeated digits (111, 2222, 333333, etc.)
 * @param {number} minLength - Minimum length
 * @param {number} maxLength - Maximum length
 * @returns {Set<string>} Repeated digit passwords
 */
function generateRepeatedDigits(minLength = 3, maxLength = 8) {
    const passwords = new Set();
    for (let len = minLength; len <= maxLength; len++) {
        for (let d = 0; d <= 9; d++) {
            passwords.add(d.toString().repeat(len));
        }
    }
    return passwords;
}

/**
 * Generate birthday format passwords (MMDDYYYY, DDMMYYYY, YYYYMMDD)
 * @param {number} startYear - Start year
 * @param {number} endYear - End year (defaults to current year)
 * @returns {Set<string>} Birthday passwords
 */
function generateBirthdays(startYear = 1970, endYear = new Date().getFullYear()) {
    const passwords = new Set();
    for (let year = startYear; year <= endYear; year++) {
        const yearStr = year.toString();
        const shortYear = yearStr.slice(-2);

        for (let month = 1; month <= 12; month++) {
            const monthStr = month.toString().padStart(2, '0');

            const daysInMonth = new Date(year, month, 0).getDate();
            for (let day = 1; day <= daysInMonth; day++) {
                const dayStr = day.toString().padStart(2, '0');

                // MMDDYYYY
                passwords.add(monthStr + dayStr + yearStr);
                // DDMMYYYY
                passwords.add(dayStr + monthStr + yearStr);
                // YYYYMMDD
                passwords.add(yearStr + monthStr + dayStr);
                // MMDDYY
                passwords.add(monthStr + dayStr + shortYear);
                // DDMMYY
                passwords.add(dayStr + monthStr + shortYear);
                // YYMMDD
                passwords.add(shortYear + monthStr + dayStr);
            }
        }
    }
    return passwords;
}

/**
 * Generate common number patterns
 * @returns {Set<string>} Common number pattern passwords
 */
function generateNumberPatterns() {
    const passwords = new Set();

    // Reverse sequential
    for (let len = 3; len <= 6; len++) {
        let password = '';
        for (let i = len; i >= 1; i--) {
            password += i.toString();
        }
        passwords.add(password.slice(0, len));
    }

    // Alternating numbers
    passwords.add('121212');
    passwords.add('123123');
    passwords.add('121314');
    passwords.add('010101');
    passwords.add('010203');

    // Keyboard patterns
    passwords.add('123456');
    passwords.add('123456789');
    passwords.add('0987654321');
    passwords.add('654321');

    // Common pin codes
    passwords.add('1212');
    return passwords;
}

/**
 * Generate common word passwords
 * @returns {Set<string>} Common word passwords
 */
function generateCommonWords() {
    const passwords = new Set([
        'password', 'Password', 'PASSWORD', 'admin', 'Admin',
        '123456', '123456789', 'qwerty', 'abc123', '111111',
        'password123', 'Password123', '12345678', '1234567890',
        'welcome', 'Welcome', 'welcome123', 'monkey', 'dragon',
        'master', 'master123', '123321', '000000', 'password1',
        'qwerty123', 'abc12345', '123abc', 'iloveyou', 'ILOVEYOU',
        'sunshine', 'qwertyuiop', 'letmein', 'trustno1', 'lovely',
        'princess', 'qwerty1', 'football', '1234qwer', '1q2w3e4r',
        '1qaz2wsx', '12345', '1234', '1234567', '123'
    ]);
    for (let year = 1900; year <= new Date().getFullYear(); year++) {
        passwords.add(year.toString());
    }
    return passwords;
}

/**
 * Generate all common passwords
 * @param {Object} options - Options
 * @param {boolean} options.sequential - Include sequential numbers
 * @param {boolean} options.repeated - Include repeated digits
 * @param {boolean} options.birthdays - Include birthdays
 * @param {boolean} options.patterns - Include number patterns
 * @param {boolean} options.commonWords - Include common words
 * @returns {Set<string>} All common passwords
 */
function generateCommonPasswords(options = {}) {
    const {
        sequential = true,
        repeated = true,
        birthdays = true,
        patterns = true,
        commonWords = true
    } = options;

    const passwords = new Set();

    if (commonWords) {
        for (const pwd of generateCommonWords()) {
            passwords.add(pwd);
        }
    }

    if (sequential) {
        for (const pwd of generateSequentialNumbers()) {
            passwords.add(pwd);
        }
    }

    if (repeated) {
        for (const pwd of generateRepeatedDigits()) {
            passwords.add(pwd);
        }
    }

    if (patterns) {
        for (const pwd of generateNumberPatterns()) {
            passwords.add(pwd);
        }
    }

    if (birthdays) {
        for (const pwd of generateBirthdays()) {
            passwords.add(pwd);
        }
    }

    return passwords;
}

module.exports = {
    generateCommonPasswords,
    generateSequentialNumbers,
    generateRepeatedDigits,
    generateBirthdays,
    generateNumberPatterns,
    generateCommonWords
};
