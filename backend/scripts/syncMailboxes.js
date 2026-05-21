import fs from 'fs';
import path from 'path';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

// Get absolute path of this file
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables
dotenv.config({ path: path.join(__dirname, '../.env') });

// Import Webmail model (using ES Module standard)
import Webmail from '../models/Webmail.js';

const run = async () => {
    try {
        console.log('Connecting to database...');
        if (!process.env.MONGO_URI) {
            throw new Error('MONGO_URI is not defined in environment variables');
        }
        await mongoose.connect(process.env.MONGO_URI);
        console.log('Database connected successfully.');

        // Fetch all active webmail accounts
        const webmails = await Webmail.find({ isActive: true });
        console.log(`Found ${webmails.length} active webmail accounts.`);

        // 1. Extract unique domains and lines
        const domains = new Set();
        const virtualLines = [];
        const dovecotLines = [];

        webmails.forEach(wm => {
            const email = wm.email.toLowerCase().trim();
            const forwardTo = wm.forwardTo.toLowerCase().trim();
            const domain = email.split('@')[1];
            if (domain) {
                domains.add(domain);
            }

            // Postfix alias format: email forwardTo
            virtualLines.push(`${email} ${forwardTo}`);

            // Dovecot passwd-file format: email:{CRYPT}hash::::::
            dovecotLines.push(`${email}:{CRYPT}${wm.passwordHash}::::::`);
        });

        const domainLines = Array.from(domains);

        // 2. Define target file paths (with fallback for local testing)
        // Check if we are running as root on a system with postfix installed
        const isProd = process.env.NODE_ENV === 'production' && fs.existsSync('/etc/postfix');
        
        const postfixDir = isProd ? '/etc/postfix' : path.join(__dirname, '../mail-configs/postfix');
        const dovecotDir = isProd ? '/etc/dovecot' : path.join(__dirname, '../mail-configs/dovecot');

        // Create directory paths if they don't exist
        if (!fs.existsSync(postfixDir)) {
            fs.mkdirSync(postfixDir, { recursive: true });
        }
        if (!fs.existsSync(dovecotDir)) {
            fs.mkdirSync(dovecotDir, { recursive: true });
        }

        const virtualDomainsPath = path.join(postfixDir, 'virtual_domains');
        const virtualPath = path.join(postfixDir, 'virtual');
        const dovecotUsersPath = path.join(dovecotDir, 'users');

        // 3. Write config files
        console.log(`Writing Postfix virtual domains to: ${virtualDomainsPath}`);
        fs.writeFileSync(virtualDomainsPath, domainLines.join('\n') + '\n', 'utf8');

        console.log(`Writing Postfix virtual aliases to: ${virtualPath}`);
        fs.writeFileSync(virtualPath, virtualLines.join('\n') + '\n', 'utf8');

        console.log(`Writing Dovecot user database to: ${dovecotUsersPath}`);
        // Secure permission mode for Dovecot users db (read/write by owner, read by group)
        fs.writeFileSync(dovecotUsersPath, dovecotLines.join('\n') + '\n', { encoding: 'utf8', mode: 0o640 });

        // 4. Reload mail services (only in production VPS environment with root permission)
        if (isProd) {
            console.log('Regenerating Postfix lookup tables...');
            const { execSync } = await import('child_process');
            try {
                // Ensure correct group ownership for Dovecot
                execSync(`chown root:dovecot ${dovecotUsersPath}`);
                console.log('Dovecot users file ownership updated.');
                
                execSync(`postmap ${virtualPath}`);
                console.log('postmap executed successfully.');
                execSync('systemctl reload postfix');
                console.log('Postfix reloaded successfully.');
                execSync('systemctl reload dovecot');
                console.log('Dovecot reloaded successfully.');
            } catch (cmdErr) {
                console.error('Failed to run system service reload commands:', cmdErr.message);
            }
        } else {
            console.log('Local environment or lack of postfix system folders detected. Skipping system command execution.');
        }

        console.log('Sync completed successfully.');
    } catch (err) {
        console.error('Error during synchronization:', err);
    } finally {
        await mongoose.disconnect();
        console.log('Database disconnected.');
    }
};

run();
