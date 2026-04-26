# ArchiveDecrypt

A Node.js package for brute force and dictionary attacks on encrypted archive files.

## Features

- **Dictionary Attack**: Try passwords from a wordlist
- **Brute Force Attack**: Generate and try all possible password combinations
- **Hybrid Attack**: Combine dictionary and brute force attacks
- **Programmatic API**: Use in your Node.js applications
- **Command Line Interface**: Use from your terminal
- **Support for Multiple Formats**: Works with both ZIP and RAR files
- **Target File Selection**: Specify a specific file to verify password (faster)
- **Character Set Presets**: Use predefined character sets like `lowercase`, `numbers`, etc.
- **Progress Display**: Shows speed, ETA, and progress
- **Statistics**: Shows elapsed time, speed, and total attempts

## Installation

```bash
npm install archive-decrypt
```

## Usage

### Command Line Interface

#### Dictionary Attack
```bash
# Basic usage
archive-decrypt dictionary encrypted.zip passwords.txt

# With options
archive-decrypt dictionary encrypted.zip passwords.txt \
  --target-file "path/to/file.jpg" \
  --max-attempts 10000 \
  --delay 10 \
  --quiet
```

#### Brute Force Attack
```bash
# Basic usage with default character set
archive-decrypt brute-force encrypted.zip

# With options
archive-decrypt brute-force encrypted.zip \
  --charset numbers \
  --min-length 4 \
  --max-length 6 \
  --target-file "path/to/file.jpg" \
  --max-attempts 10000

# Use custom character set
archive-decrypt brute-force encrypted.zip --charset "abc123!@#"
```

#### Hybrid Attack
```bash
# Basic usage
archive-decrypt hybrid encrypted.zip passwords.txt

# With options
archive-decrypt hybrid encrypted.zip passwords.txt \
  --charset lowercase \
  --min-length 3 \
  --max-length 5 \
  --target-file "path/to/file.jpg"
```

### Character Set Presets
The following character set presets are available:
- `lowercase`: `abcdefghijklmnopqrstuvwxyz`
- `uppercase`: `ABCDEFGHIJKLMNOPQRSTUVWXYZ`
- `numbers`: `0123456789`
- `symbols`: `!@#$%^&*()_+-=[]{}|;:'",./<>?`
- `all`: `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:'",./<>?`
- `alphanumeric`: same as `all`

### Programmatic API

#### Dictionary Attack
```javascript
const ArchiveDecrypt = require('archive-decrypt');

const archiveDecrypt = new ArchiveDecrypt('encrypted.archive'); // Can be .zip or .rar

const dictionary = ['password', '1234', 'qwerty'];

(async () => {
  const result = await archiveDecrypt.dictionaryAttack({
    dictionary: dictionary,
    targetFileName: 'path/to/file.jpg', // Optional: Verify password by extracting this specific file
    onAttempt: (password, attempts, info) => {
      if (attempts % 1000 === 0) {
        console.log(`Attempt ${attempts} (${info.speed}/s) - ETA: ${info.eta}`);
      }
    },
    onSuccess: (password, attempts, info) => {
      console.log(`Success! Password found: ${password}`);
      console.log(`Attempts: ${attempts}`);
      console.log(`Elapsed: ${info.elapsed.toFixed(1)}s`);
      console.log(`Speed: ${info.speed}/s`);
    },
    onFailure: (info) => {
      console.log('Password not found in dictionary');
      console.log(`Attempts: ${info.attempts}`);
      console.log(`Elapsed: ${info.elapsed.toFixed(1)}s`);
    }
  });
})();
```

#### Brute Force Attack
```javascript
const ArchiveDecrypt = require('archive-decrypt');

const archiveDecrypt = new ArchiveDecrypt('encrypted.archive'); // Can be .zip or .rar

(async () => {
  const result = await archiveDecrypt.bruteForceAttack({
    charset: 'numbers', // or custom charset like '0123456789'
    minLength: 4,
    maxLength: 6,
    targetFileName: 'path/to/file.jpg', // Optional: Verify password by extracting this specific file
    onAttempt: (password, attempts, info) => {
      if (attempts % 1000 === 0) {
        console.log(`Attempt ${attempts} (${info.speed}/s) - ETA: ${info.eta}`);
      }
    },
    onSuccess: (password, attempts, info) => {
      console.log(`Success! Password found: ${password}`);
    },
    onFailure: (info) => {
      console.log('Password not found');
    }
  });
})();
```

#### Hybrid Attack
```javascript
const ArchiveDecrypt = require('archive-decrypt');

const archiveDecrypt = new ArchiveDecrypt('encrypted.archive'); // Can be .zip or .rar

const dictionary = ['password', '1234', 'qwerty'];

(async () => {
  const result = await archiveDecrypt.hybridAttack({
    dictionary: dictionary,
    charset: 'lowercase',
    minLength: 3,
    maxLength: 5,
    targetFileName: 'path/to/file.jpg', // Optional: Verify password by extracting this specific file
    onAttempt: (password, attempts, info) => {
      if (attempts % 1000 === 0) {
        console.log(`Attempt ${attempts} (${info.speed}/s) - ETA: ${info.eta}`);
      }
    },
    onSuccess: (password, attempts, info) => {
      console.log(`Success! Password found: ${password}`);
    },
    onFailure: (info) => {
      console.log('Password not found');
    }
  });
})();
```

## Options

### Common Options
All attack methods support these options:

- `targetFileName`: Optional. Verify password by extracting this specific file. If the file doesn't exist in the archive, the attack will terminate immediately. If not specified, the smallest file will be automatically selected for faster verification.
- `maxAttempts`: Maximum number of attempts (default: Infinity)
- `delay`: Delay between attempts in milliseconds (default: 0)
- `ignoreUnexpectedError`: Ignore unexpected errors and continue trying (default: true). This helps with zlib errors (Z_DATA_ERROR, CRC32 checksum failed, etc.) that can occur when trying wrong passwords.
- `onAttempt`: Callback function called for each attempt. Receives parameters: (password, attempts, { speed, eta, total })
- `onSuccess`: Callback function called when password is found. Receives parameters: (password, attempts, { elapsed, speed })
- `onFailure`: Callback function called when password is not found. Receives parameters: ({ elapsed, speed, attempts })

### Dictionary Attack Options
- `dictionary`: Array of passwords to try

### Brute Force Attack Options
- `charset`: Characters to use for password generation, or a preset (lowercase, uppercase, numbers, symbols, all, alphanumeric) (default: all letters and numbers)
- `minLength`: Minimum password length (default: 1)
- `maxLength`: Maximum password length (default: 6)

## Performance Considerations

- **Dictionary Attack**: Fastest option, especially with a good wordlist
- **Brute Force Attack**: Can be very slow for long passwords or large character sets
- **Hybrid Attack**: Balances speed and coverage
- **Target File**: Using `targetFileName` can significantly improve performance by only verifying a specific file (preferably small). If not specified, the smallest file in the archive will be automatically selected.
- **File Size Matters**: Larger files take longer to decrypt and verify. Always prefer using the smallest file possible for password verification.
- **RAR vs ZIP**: ZIP files are generally faster to verify than RAR files

## Security Note

This tool is intended for educational purposes only. Always obtain proper authorization before attempting to decrypt any encrypted files.

## Limitations

- For RAR files, requires node-unrar-js for password verification
- For ZIP files, uses adm-zip for password verification
- Large character sets and long passwords can result in very slow brute force attacks
- Target file name must match exactly, including path and case sensitivity
