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
    res.json({ message: 'Webmail account deleted successfully' });
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
    
    // Check which mail log file exists
    let mailLog = '';
    if (fs.existsSync('/var/log/mail.log')) {
        mailLog = runCommand('tail -n 100 /var/log/mail.log');
    } else if (fs.existsSync('/var/log/maillog')) {
        mailLog = runCommand('tail -n 100 /var/log/maillog');
    } else {
        mailLog = 'Neither /var/log/mail.log nor /var/log/maillog was found.';
    }
    results.mailLog = mailLog;

    results.postfixStatus = runCommand('systemctl status postfix');
    results.dovecotStatus = runCommand('systemctl status dovecot');
    
    res.json(results);
});

