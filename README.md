# ArchiveDecrypt

A Node.js package for brute force and dictionary attacks on encrypted archive files.

## Features

- **Dictionary Attack**: Try passwords from a wordlist
- **Brute Force Attack**: Generate and try all possible password combinations
- **Hybrid Attack**: Combine dictionary and brute force attacks
- **Command Line Interface**: Easy to use from the terminal
- **Programmatic API**: Use in your Node.js applications
- **Support for Multiple Formats**: Works with both ZIP and RAR files
- **Password Support**: Uses node-unrar-js for proper RAR password handling

## Installation

```bash
npm install archive-decrypt
```

## Usage

### Command Line

#### Dictionary Attack

```bash
archive-decrypt <archive> --dictionary <wordlist.txt>
```

#### Brute Force Attack

```bash
archive-decrypt <archive> --brute-force --charset "0123456789" --min-length 1 --max-length 4
```

#### Hybrid Attack

```bash
archive-decrypt <archive> --hybrid --dictionary <wordlist.txt> --charset "0123456789" --min-length 1 --max-length 4
```

#### Help

```bash
archive-decrypt --help
```

```
Usage: archive-decrypt [options] <archive>

A Node.js package for brute force and dictionary attacks on encrypted archive files

Options:
  -V, --version          output the version number
  --dictionary <file>    Use dictionary attack with specified wordlist
  --brute-force          Use brute force attack
  --charset <chars>      Charset for brute force (default: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
  --min-length <n>       Minimum password length (default: 1)
  --max-length <n>       Maximum password length (default: 6)
  --hybrid               Use hybrid attack (dictionary + brute force)
  -h, --help             display help for command
```

### Programmatic API

#### Dictionary Attack

```javascript
const ArchiveDecrypt = require('archive-decrypt');

const archiveDecrypt = new ArchiveDecrypt('encrypted.archive'); // Can be .zip or .rar

const dictionary = ['password', '1234', 'qwerty'];

(async () => {
  const result = await archiveDecrypt.dictionaryAttack(dictionary, {
    onAttempt: (password, attempts) => {
      console.log(`Attempt ${attempts}: ${password}`);
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
    onAttempt: (password, attempts) => {
      console.log(`Attempt ${attempts}: ${password}`);
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
  const result = await archiveDecrypt.hybridAttack(dictionary, {
    charset: '0123456789',
    minLength: 1,
    maxLength: 4,
    onAttempt: (password, attempts) => {
      console.log(`Attempt ${attempts}: ${password}`);
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

### Dictionary Attack Options

- `dictionary`: Array of passwords to try
- `maxAttempts`: Maximum number of attempts (default: Infinity)
- `delay`: Delay between attempts in milliseconds (default: 0)
- `onAttempt`: Callback function called for each attempt
- `onSuccess`: Callback function called when password is found
- `onFailure`: Callback function called when password is not found

### Brute Force Attack Options

- `charset`: Characters to use for password generation (default: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
- `minLength`: Minimum password length (default: 1)
- `maxLength`: Maximum password length (default: 6)
- `maxAttempts`: Maximum number of attempts (default: Infinity)
- `delay`: Delay between attempts in milliseconds (default: 0)
- `onAttempt`: Callback function called for each attempt
- `onSuccess`: Callback function called when password is found
- `onFailure`: Callback function called when password is not found

## Performance Considerations

- **Dictionary Attack**: Fastest option, especially with a good wordlist
- **Brute Force Attack**: Can be very slow for long passwords or large character sets
- **Hybrid Attack**: Balances speed and coverage

## Security Note

This tool is intended for educational purposes only. Always obtain proper authorization before attempting to decrypt any encrypted files.

## Limitations

- **adm-zip** library does not support creating encrypted zip files. To test this tool, you need to create encrypted zip files using other tools (e.g., WinZip, 7-Zip).
- The password verification process uses `readFile` method, which attempts to read the first file in the zip archive. This is more efficient than extracting the entire archive.
