import asyncHandler from 'express-async-handler';
import bcrypt from 'bcryptjs';
import Webmail from '../models/Webmail.js';

// @desc    Get all webmail accounts
// @route   GET /api/webmail
// @access  Private/Admin
export const getWebmails = asyncHandler(async (req, res) => {
    const webmails = await Webmail.find({}).sort({ createdAt: -1 });
    res.json(webmails);
});

// Sync utility helper
const runSyncScript = async () => {
    const { execSync } = await import('child_process');
    const path = await import('path');
    const fs = await import('fs');
    try {
        const cwd = process.cwd();
        let scriptPath = path.join(cwd, 'scripts/syncMailboxes.js');
        if (!fs.existsSync(scriptPath)) {
            scriptPath = path.join(cwd, 'backend/scripts/syncMailboxes.js');
        }
        if (!fs.existsSync(scriptPath)) {
            throw new Error(`Sync script not found`);
        }
        console.log(`[MAIL SYNC] Triggering sync mailboxes: node "${scriptPath}"`);
        const output = execSync(`node "${scriptPath}"`, { encoding: 'utf8', timeout: 15000 });
        return { success: true, output };
    } catch (err) {
        console.error('[MAIL SYNC] Error during sync:', err.message);
        return { success: false, error: err.message, stderr: err.stderr || '' };
    }
};

// @desc    Create a webmail account
// @route   POST /api/webmail
// @access  Private/Admin
export const createWebmail = asyncHandler(async (req, res) => {
    const { email, forwardTo, password } = req.body;

    if (!email || !forwardTo || !password) {
        res.status(400);
        throw new Error('Please fill all fields');
    }

    const emailExists = await Webmail.findOne({ email: email.toLowerCase() });

    if (emailExists) {
        res.status(400);
        throw new Error('Webmail email already exists');
    }

    // Encrypt password using bcryptjs
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const webmail = await Webmail.create({
        email: email.toLowerCase(),
        forwardTo: forwardTo.toLowerCase(),
        passwordHash,
        isActive: true
    });

    // Auto-sync configuration on server
    await runSyncScript();

    res.status(201).json(webmail);
});

// @desc    Update webmail details (forwardTo and/or password)
// @route   PUT /api/webmail/:id
// @access  Private/Admin
export const updateWebmail = asyncHandler(async (req, res) => {
    const webmail = await Webmail.findById(req.params.id);

    if (!webmail) {
        res.status(404);
        throw new Error('Webmail account not found');
    }

    const { forwardTo, password, isActive } = req.body;

    if (forwardTo) {
        webmail.forwardTo = forwardTo.toLowerCase();
    }

    if (password) {
        const salt = await bcrypt.genSalt(10);
        webmail.passwordHash = await bcrypt.hash(password, salt);
    }

    if (typeof isActive !== 'undefined') {
        webmail.isActive = isActive;
    }

    const updatedWebmail = await webmail.save();
    
    // Auto-sync configuration on server
    await runSyncScript();

    res.json(updatedWebmail);
});

// @desc    Delete webmail account
// @route   DELETE /api/webmail/:id
// @access  Private/Admin
export const deleteWebmail = asyncHandler(async (req, res) => {
    const webmail = await Webmail.findById(req.params.id);

    if (!webmail) {
        res.status(404);
        throw new Error('Webmail account not found');
    }

    await webmail.deleteOne();
    
    // Auto-sync configuration on server
    await runSyncScript();

    res.json({ message: 'Webmail account deleted successfully' });
});

// @desc    Manually trigger mail service sync
// @route   POST /api/webmail/sync
// @access  Private/Admin
export const triggerSync = asyncHandler(async (req, res) => {
    const result = await runSyncScript();
    if (result.success) {
        res.json({ message: 'Mailbox configuration successfully synchronized!', output: result.output });
    } else {
        res.status(500);
        throw new Error(`Synchronization failed: ${result.error}. ${result.stderr}`);
    }
});

// @desc    Get mail server diagnostics
// @route   GET /api/webmail/diagnostics
// @access  Private/Admin
export const getDiagnostics = asyncHandler(async (req, res) => {
    const { execSync } = await import('child_process');
    const fs = await import('fs');
    const results = {};

    const runCommand = (cmd) => {
        try {
            return execSync(cmd, { encoding: 'utf8', timeout: 5000 });
        } catch (err) {
            return `Error executing "${cmd}": ${err.message}\n${err.stderr || ''}`;
        }
    };

    results.mailq = runCommand('mailq');
    
    // Check which mail log file exists, fallback to journalctl
    let mailLog = '';
    if (fs.existsSync('/var/log/mail.log')) {
        mailLog = runCommand('tail -n 100 /var/log/mail.log');
    } else if (fs.existsSync('/var/log/maillog')) {
        mailLog = runCommand('tail -n 100 /var/log/maillog');
    } else {
        mailLog = '--- Systemd Journal Logs (Postfix/Dovecot) ---\n';
        mailLog += runCommand('journalctl -u postfix -u dovecot -n 100 --no-pager');
    }
    results.mailLog = mailLog;

    results.postfixStatus = runCommand('systemctl status postfix');
    results.dovecotStatus = runCommand('systemctl status dovecot');

    // Read configured postfix aliases (virtual)
    let postfixVirtual = '';
    if (fs.existsSync('/etc/postfix/virtual')) {
        postfixVirtual = fs.readFileSync('/etc/postfix/virtual', 'utf8');
    } else if (fs.existsSync('mail-configs/postfix/virtual')) {
        postfixVirtual = fs.readFileSync('mail-configs/postfix/virtual', 'utf8');
    }
    results.postfixVirtual = postfixVirtual;

    // Read configured dovecot users (mask CRYPT hashes for security)
    let dovecotUsers = '';
    let rawUsers = '';
    if (fs.existsSync('/etc/dovecot/users')) {
        rawUsers = fs.readFileSync('/etc/dovecot/users', 'utf8');
    } else if (fs.existsSync('mail-configs/dovecot/users')) {
        rawUsers = fs.readFileSync('mail-configs/dovecot/users', 'utf8');
    }
    if (rawUsers) {
        dovecotUsers = rawUsers.split('\n').map(line => {
            if (!line.trim()) return '';
            const parts = line.split(':');
            if (parts.length >= 2) {
                parts[1] = '{CRYPT}***MASKED_HASH***';
            }
            return parts.join(':');
        }).filter(Boolean).join('\n');
    }
    results.dovecotUsers = dovecotUsers;
    
    res.json(results);
});


