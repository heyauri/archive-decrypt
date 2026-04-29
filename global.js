#!/usr/bin/env node
const path = require('path');
const fs = require('fs');
const ArchiveDecryptWrapper = require('./index');
const utils = require('./src/utils');
const { program } = require('commander');

const DEFAULT_CHARSET = 'alphanumeric';

// Create common callback functions
function createCallbacks(options) {
    return {
        onAttempt: (password, attempts, info) => {
            if (options.quiet) return;

            if (attempts % 1000 === 0) {
                const speedStr = info.speed ? `(${info.speed}/s)` : '';
                const etaStr = info.eta !== null ? `ETA: ${utils.formatTime(info.eta)}` : '';
                const progressStr = info.total ? `[${attempts}/${info.total}]` : `[${attempts}]`;
                process.stdout.write(`\rAttempt ${progressStr} ${speedStr} ${etaStr}`);
            }
        },
        onSuccess: (password, attempts, info) => {
            console.log(`\n\n✅ Success! Password found: "${password}"`);
            console.log(`   Attempts: ${attempts}`);
            console.log(`   Elapsed: ${info.elapsed.toFixed(1)}s`);
            console.log(`   Speed: ${info.speed}/s`);
            process.exit(0);
        },
        onFailure: (info) => {
            console.log(`\n\n❌ Password not found`);
            console.log(`   Attempts: ${info.attempts}`);
            console.log(`   Elapsed: ${info.elapsed.toFixed(1)}s`);
            console.log(`   Speed: ${info.speed}/s`);
            process.exit(1);
        }
    };
}

// Validate that files exist
function validateFiles(files) {
    for (const { path: filePath, desc } of files) {
        if (!fs.existsSync(filePath)) {
            console.error(`Error: ${desc} not found: ${filePath}`);
            process.exit(1);
        }
    }
}

// Read dictionary file
function readDictionary(dictionaryPath) {
    return fs.readFileSync(dictionaryPath, 'utf8')
        .split('\n')
        .map(line => line.replace(/(\r|\n)/g, ''))
        .filter(Boolean);
}

// Add common options
function addCommonOptions(cmd) {
    return cmd
        .option('--target-file <file>', 'Target file to verify password')
        .option('--max-attempts <number>', 'Maximum number of attempts', parseInt)
        .option('--delay <ms>', 'Delay between attempts in milliseconds', parseInt, 0)
        .option('--quiet', 'Quiet mode, only show final result', false)
        .option('--save-progress', 'Enable progress saving for resume', false)
        .option('--load-progress', 'Load and resume from saved progress', false)
        .option('--progress-interval <ms>', 'Progress save interval in milliseconds', parseInt, 60000);
}

// Create base options object
function createBaseOptions(options) {
    return {
        targetFileName: options.targetFile,
        maxAttempts: options.maxAttempts,
        delay: options.delay,
        saveProgress: options.saveProgress,
        loadProgress: options.loadProgress,
        progressInterval: options.progressInterval,
        ...createCallbacks(options)
    };
}

program
    .name('archive-decrypt')
    .description('Decrypt ZIP and RAR archives using brute force or dictionary attacks')
    .version('1.0.0');

addCommonOptions(program
    .command('dictionary')
    .description('Use a dictionary attack')
    .argument('<archive>', 'Path to the encrypted archive')
    .argument('<dictionary>', 'Path to the dictionary file')
)
    .action(async (archive, dictionary, options) => {
        try {
            validateFiles([
                { path: archive, desc: 'Archive file' },
                { path: dictionary, desc: 'Dictionary file' }
            ]);

            const dict = readDictionary(dictionary);
            const archiveDecrypt = new ArchiveDecryptWrapper(archive);

            console.log(`Starting dictionary attack with ${dict.length} passwords...`);

            await archiveDecrypt.dictionaryAttack({
                dictionary: dict,
                ...createBaseOptions(options)
            });
        } catch (error) {
            console.error(`Error: ${error.message}`);
            process.exit(1);
        }
    });

addCommonOptions(program
    .command('brute-force')
    .description('Use a brute force attack')
    .argument('<archive>', 'Path to the encrypted archive')
    .option('--charset <chars>', 'Character set for password generation or preset (lowercase, uppercase, numbers, symbols, all, alphanumeric)')
    .option('--min-length <number>', 'Minimum password length', parseInt, 1)
    .option('--max-length <number>', 'Maximum password length', parseInt, 10)
)
    .action(async (archive, options) => {
        try {
            validateFiles([{ path: archive, desc: 'Archive file' }]);

            const archiveDecrypt = new ArchiveDecryptWrapper(archive);

            console.log(`Starting brute force attack...`);
            if (options.charset) {
                console.log(`Character set: ${options.charset}`);
            } else {
                options.charset = DEFAULT_CHARSET;
                console.log(`Character set: ${DEFAULT_CHARSET}`);
            }
            console.log(`Password length: ${options.minLength}-${options.maxLength}`);

            await archiveDecrypt.bruteForceAttack({
                charset: options.charset,
                minLength: options.minLength,
                maxLength: options.maxLength,
                ...createBaseOptions(options)
            });
        } catch (error) {
            console.error(`Error: ${error.message}`);
            process.exit(1);
        }
    });

addCommonOptions(program
    .command('hybrid')
    .description('Use a hybrid attack (dictionary + brute force)')
    .argument('<archive>', 'Path to the encrypted archive')
    .argument('<dictionary>', 'Path to the dictionary file')
    .option('--charset <chars>', 'Character set for password generation or preset (lowercase, uppercase, numbers, symbols, all, alphanumeric)')
    .option('--min-length <number>', 'Minimum password length', parseInt, 1)
    .option('--max-length <number>', 'Maximum password length', parseInt, 10)
)
    .action(async (archive, dictionary, options) => {
        try {
            validateFiles([
                { path: archive, desc: 'Archive file' },
                { path: dictionary, desc: 'Dictionary file' }
            ]);

            const dict = readDictionary(dictionary);
            const archiveDecrypt = new ArchiveDecryptWrapper(archive);

            console.log(`Starting hybrid attack...`);
            console.log(`Dictionary: ${dict.length} passwords`);
            if (options.charset) {
                console.log(`Character set: ${options.charset}`);
            } else {
                options.charset = DEFAULT_CHARSET;
                console.log(`Character set: ${DEFAULT_CHARSET}`);
            }
            console.log(`Password length: ${options.minLength}-${options.maxLength}`);

            await archiveDecrypt.hybridAttack({
                dictionary: dict,
                charset: options.charset,
                minLength: options.minLength,
                maxLength: options.maxLength,
                ...createBaseOptions(options)
            });
        } catch (error) {
            console.error(`Error: ${error.message}`);
            process.exit(1);
        }
    });

program.parse();
