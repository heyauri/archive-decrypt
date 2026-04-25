#!/usr/bin/env node
const fs = require('fs');
const { Command } = require('commander');
const ArchiveDecrypt = require('./index');

const program = new Command();

program
    .name('archive-decrypt')
    .description('A Node.js package for brute force and dictionary attacks on encrypted archive files')
    .version('1.0.0');

program
    .argument('<archive>', 'Path to the encrypted archive file')
    .option('--dictionary <file>', 'Use dictionary attack with specified wordlist')
    .option('--brute-force', 'Use brute force attack')
    .option('--charset <chars>', 'Charset for brute force', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    .option('--min-length <n>', 'Minimum password length', parseInt, 1)
    .option('--max-length <n>', 'Maximum password length', parseInt, 6)
    .option('--hybrid', 'Use hybrid attack (dictionary + brute force)');

program.parse();

const options = program.opts();
const archivePath = program.args[0];

if (!fs.existsSync(archivePath)) {
    console.error('Error: Archive file not found');
    process.exit(1);
}

try {
    const archiveDecrypt = new ArchiveDecrypt(archivePath);

    // Execute attack
    (async () => {
        console.log(`Starting attack on ${archivePath}...`);

        let result = null;

        if (options.hybrid && options.dictionary) {
            // Hybrid attack
            const dictionary = fs.readFileSync(options.dictionary, 'utf8').split('\n').filter(word => word.trim() !== '');
            result = await archiveDecrypt.hybridAttack(dictionary, {
                charset: options.charset,
                minLength: options.minLength,
                maxLength: options.maxLength,
                onAttempt: (password, attempts) => {
                    process.stdout.write(`\rAttempt ${attempts}: ${password}`);
                },
                onSuccess: (password, attempts) => {
                    console.log(`\nSuccess! Password found: ${password} (${attempts} attempts)`);
                },
                onFailure: () => {
                    console.log('\nFailure: Password not found');
                }
            });
        } else if (options.dictionary) {
            // Dictionary attack
            const dictionary = fs.readFileSync(options.dictionary, 'utf8').split('\n').filter(word => word.trim() !== '');
            result = await archiveDecrypt.dictionaryAttack(dictionary, {
                onAttempt: (password, attempts) => {
                    process.stdout.write(`\rAttempt ${attempts}: ${password}`);
                },
                onSuccess: (password, attempts) => {
                    console.log(`\nSuccess! Password found: ${password} (${attempts} attempts)`);
                },
                onFailure: () => {
                    console.log('\nFailure: Password not found in dictionary');
                }
            });
        } else if (options.bruteForce) {
            // Brute force attack
            result = await archiveDecrypt.bruteForceAttack({
                charset: options.charset,
                minLength: options.minLength,
                maxLength: options.maxLength,
                onAttempt: (password, attempts) => {
                    process.stdout.write(`\rAttempt ${attempts}: ${password}`);
                },
                onSuccess: (password, attempts) => {
                    console.log(`\nSuccess! Password found: ${password} (${attempts} attempts)`);
                },
                onFailure: () => {
                    console.log('\nFailure: Password not found');
                }
            });
        } else {
            console.log('Error: Please specify either --dictionary, --brute-force, or --hybrid');
            process.exit(1);
        }
    })();
} catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
}