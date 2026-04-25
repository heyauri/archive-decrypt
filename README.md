# ArchiveDecrypt

A Node.js package for brute force and dictionary attacks on encrypted archive files.

## Features

- **Dictionary Attack**: Try passwords from a wordlist
- **Brute Force Attack**: Generate and try all possible password combinations
- **Hybrid Attack**: Combine dictionary and brute force attacks
- **Programmatic API**: Use in your Node.js applications
- **Support for Multiple Formats**: Works with both ZIP and RAR files
- **Target File Selection**: Specify a specific file to verify password (faster)
- **RAR Optimization**: Uses node-unrar-js for proper RAR password handling

## Installation

```bash
npm install archive-decrypt
```

## Usage

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
    onAttempt: (password, attempts) => {
      if (attempts % 100 === 0) {
        console.log(`Attempt ${attempts}: ${password}`);
      }
    },
    onSuccess: (password, attempts) => {
      console.log(`Success! Password found: ${password} (${attempts} attempts)`);
    },
    onFailure: () => {
      console.log('Password not found in dictionary');
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
    charset: '0123456789',
    minLength: 1,
    maxLength: 4,
    targetFileName: 'path/to/file.jpg', // Optional: Verify password by extracting this specific file
    onAttempt: (password, attempts) => {
      if (attempts % 100 === 0) {
        console.log(`Attempt ${attempts}: ${password}`);
      }
    },
    onSuccess: (password, attempts) => {
      console.log(`Success! Password found: ${password} (${attempts} attempts)`);
    },
    onFailure: () => {
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
    charset: '0123456789',
    minLength: 1,
    maxLength: 4,
    targetFileName: 'path/to/file.jpg', // Optional: Verify password by extracting this specific file
    onAttempt: (password, attempts) => {
      if (attempts % 100 === 0) {
        console.log(`Attempt ${attempts}: ${password}`);
      }
    },
    onSuccess: (password, attempts) => {
      console.log(`Success! Password found: ${password} (${attempts} attempts)`);
    },
    onFailure: () => {
      console.log('Password not found');
    }
  });
})();
```

## Options

### Common Options

All attack methods support these options:

- `targetFileName`: Optional. Verify password by extracting this specific file. If the file doesn't exist in the archive, the attack will terminate immediately.
- `maxAttempts`: Maximum number of attempts (default: Infinity)
- `delay`: Delay between attempts in milliseconds (default: 0)
- `onAttempt`: Callback function called for each attempt
- `onSuccess`: Callback function called when password is found
- `onFailure`: Callback function called when password is not found

### Dictionary Attack Options

- `dictionary`: Array of passwords to try

### Brute Force Attack Options

- `charset`: Characters to use for password generation (default: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
- `minLength`: Minimum password length (default: 1)
- `maxLength`: Maximum password length (default: 6)

## Performance Considerations

- **Dictionary Attack**: Fastest option, especially with a good wordlist
- **Brute Force Attack**: Can be very slow for long passwords or large character sets
- **Hybrid Attack**: Balances speed and coverage
- **Target File**: Using `targetFileName` can significantly improve performance by only verifying a specific file (preferably small)

## Security Note

This tool is intended for educational purposes only. Always obtain proper authorization before attempting to decrypt any encrypted files.

## Limitations

- For RAR files, requires node-unrar-js for password verification
- For ZIP files, uses yauzl for password verification
- Large character sets and long passwords can result in very slow brute force attacks
- Target file name must match exactly, including path and case sensitivity
