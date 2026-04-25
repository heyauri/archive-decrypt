#!/usr/bin/env node
const path = require('path');
const fs = require('fs');
const ArchiveDecrypt = require('./index');
const { program } = require('commander');

program
  .name('archive-decrypt')
  .description('Decrypt ZIP and RAR archives using brute force or dictionary attacks')
  .version('1.0.0');

program
  .command('dictionary')
  .description('Use a dictionary attack')
  .argument('<archive>', 'Path to the encrypted archive')
  .argument('<dictionary>', 'Path to the dictionary file')
  .option('--target-file <file>', 'Target file to verify password')
  .option('--max-attempts <number>', 'Maximum number of attempts', parseInt)
  .option('--delay <ms>', 'Delay between attempts in milliseconds', parseInt, 0)
  .option('--quiet', 'Quiet mode, only show final result', false)
  .option('--progress', 'Show progress bar', true)
  .action(async (archive, dictionary, options) => {
    try {
      if (!fs.existsSync(archive)) {
        console.error(`Error: Archive file not found: ${archive}`);
        process.exit(1);
      }
      if (!fs.existsSync(dictionary)) {
        console.error(`Error: Dictionary file not found: ${dictionary}`);
        process.exit(1);
      }

      const archiveDecrypt = new ArchiveDecrypt(archive);
      const dict = fs.readFileSync(dictionary, 'utf8').trim().split('\n').map(line => line.trim()).filter(Boolean);

      console.log(`Starting dictionary attack with ${dict.length} passwords...`);

      const opts = {
        dictionary: dict,
        maxAttempts: options.maxAttempts,
        delay: options.delay,
        targetFileName: options.targetFile,
        onAttempt: (password, attempts, info) => {
          if (options.quiet) return;

          if (attempts % 1000 === 0) {
            const speedStr = info.speed ? `(${info.speed}/s)` : '';
            const etaStr = info.eta !== null ? `ETA: ${archiveDecrypt.formatTime(info.eta)}` : '';
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

      await archiveDecrypt.dictionaryAttack(opts);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  });

program
  .command('brute-force')
  .description('Use a brute force attack')
  .argument('<archive>', 'Path to the encrypted archive')
  .option('--charset <chars>', 'Character set for password generation or preset (lowercase, uppercase, numbers, symbols, all, alphanumeric)')
  .option('--min-length <number>', 'Minimum password length', parseInt, 1)
  .option('--max-length <number>', 'Maximum password length', parseInt, 6)
  .option('--target-file <file>', 'Target file to verify password')
  .option('--max-attempts <number>', 'Maximum number of attempts', parseInt)
  .option('--delay <ms>', 'Delay between attempts in milliseconds', parseInt, 0)
  .option('--quiet', 'Quiet mode, only show final result', false)
  .action(async (archive, options) => {
    try {
      if (!fs.existsSync(archive)) {
        console.error(`Error: Archive file not found: ${archive}`);
        process.exit(1);
      }

      const archiveDecrypt = new ArchiveDecrypt(archive);

      console.log(`Starting brute force attack...`);
      if (options.charset) {
        console.log(`Character set: ${options.charset}`);
      }
      console.log(`Password length: ${options.minLength}-${options.maxLength}`);

      const opts = {
        charset: options.charset,
        minLength: options.minLength,
        maxLength: options.maxLength,
        maxAttempts: options.maxAttempts,
        delay: options.delay,
        targetFileName: options.targetFile,
        onAttempt: (password, attempts, info) => {
          if (options.quiet) return;

          if (attempts % 1000 === 0) {
            const speedStr = info.speed ? `(${info.speed}/s)` : '';
            const etaStr = info.eta !== null ? `ETA: ${archiveDecrypt.formatTime(info.eta)}` : '';
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

      await archiveDecrypt.bruteForceAttack(opts);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  });

program
  .command('hybrid')
  .description('Use a hybrid attack (dictionary + brute force)')
  .argument('<archive>', 'Path to the encrypted archive')
  .argument('<dictionary>', 'Path to the dictionary file')
  .option('--charset <chars>', 'Character set for password generation or preset (lowercase, uppercase, numbers, symbols, all, alphanumeric)')
  .option('--min-length <number>', 'Minimum password length', parseInt, 1)
  .option('--max-length <number>', 'Maximum password length', parseInt, 6)
  .option('--target-file <file>', 'Target file to verify password')
  .option('--max-attempts <number>', 'Maximum number of attempts', parseInt)
  .option('--delay <ms>', 'Delay between attempts in milliseconds', parseInt, 0)
  .option('--quiet', 'Quiet mode, only show final result', false)
  .action(async (archive, dictionary, options) => {
    try {
      if (!fs.existsSync(archive)) {
        console.error(`Error: Archive file not found: ${archive}`);
        process.exit(1);
      }
      if (!fs.existsSync(dictionary)) {
        console.error(`Error: Dictionary file not found: ${dictionary}`);
        process.exit(1);
      }

      const archiveDecrypt = new ArchiveDecrypt(archive);
      const dict = fs.readFileSync(dictionary, 'utf8').trim().split('\n').map(line => line.trim()).filter(Boolean);

      console.log(`Starting hybrid attack...`);
      console.log(`Dictionary: ${dict.length} passwords`);
      if (options.charset) {
        console.log(`Character set: ${options.charset}`);
      }
      console.log(`Password length: ${options.minLength}-${options.maxLength}`);

      const opts = {
        dictionary: dict,
        charset: options.charset,
        minLength: options.minLength,
        maxLength: options.maxLength,
        maxAttempts: options.maxAttempts,
        delay: options.delay,
        targetFileName: options.targetFile,
        onAttempt: (password, attempts, info) => {
          if (options.quiet) return;

          if (attempts % 1000 === 0) {
            const speedStr = info.speed ? `(${info.speed}/s)` : '';
            const etaStr = info.eta !== null ? `ETA: ${archiveDecrypt.formatTime(info.eta)}` : '';
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

      await archiveDecrypt.hybridAttack(opts);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  });

program.parse();
