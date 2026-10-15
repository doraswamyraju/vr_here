import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import asyncHandler from 'express-async-handler';
import UserDocument from '../models/UserDocument.js';
import User from '../models/User.js';
import { uploadBufferToDrive, getCustomerDriveFolder } from '../services/googleDriveService.js';
import { triggerNotification } from '../services/notificationService.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// @desc    Get user's profile document vault records
// @route   GET /api/documents
// @access  Private
export const getUserDocuments = asyncHandler(async (req, res) => {
    const targetUserId = req.query.userId || req.user._id;
    const documents = await UserDocument.find({ user: targetUserId }).sort({ createdAt: -1 });

    res.json({
        success: true,
        count: documents.length,
        data: documents
    });
});

// @desc    Upload document to customer profile vault in Google Drive
// @route   POST /api/documents/upload
// @access  Private
export const uploadUserDocument = asyncHandler(async (req, res) => {
    if (!req.file) {
        res.status(400);
        throw new Error('Please select a document file to upload');
    }

    const { docType = 'Other', notes = '' } = req.body;
    const userId = req.user._id;
    const user = await User.findById(userId);

    if (!user) {
        res.status(404);
        throw new Error('User account not found');
    }

    // 1. Get/Create Customer Google Drive folder hierarchy
    const driveHierarchy = await getCustomerDriveFolder({ clientName: user.name });
    const profileFolderId = driveHierarchy ? driveHierarchy.profileDocsFolderId : null;

    // 2. Stream upload buffer directly to Google Drive (no VPS disk storage)
    const fileName = `${docType.replace(/\s+/g, '_')}_${Date.now()}_${req.file.originalname}`;
    const driveResult = await uploadBufferToDrive({
        fileBuffer: req.file.buffer,
        mimeType: req.file.mimetype,
        fileName,
        parentFolderId: profileFolderId
    });

    // 3. Upsert UserDocument record (replace old file of same docType if exists)
    let documentRecord = await UserDocument.findOne({ user: userId, docType });

    if (documentRecord) {
        documentRecord.fileName = req.file.originalname;
        documentRecord.gdriveFileId = driveResult.fileId;
        documentRecord.gdriveWebViewLink = driveResult.webViewLink;
        documentRecord.verificationStatus = 'Verified';
        documentRecord.notes = notes;
        await documentRecord.save();
    } else {
        documentRecord = await UserDocument.create({
            user: userId,
            docType,
            fileName: req.file.originalname,
            gdriveFileId: driveResult.fileId,
            gdriveWebViewLink: driveResult.webViewLink,
            verificationStatus: 'Verified',
            notes
        });
    }

    // 4. Trigger in-app notification
    triggerNotification({
        userId,
        title: 'Document Saved to Google Drive',
        message: `Your ${docType} (${req.file.originalname}) has been securely uploaded and saved to your VR HERE Google Drive vault.`,
        type: 'System'
    }).catch(err => console.error('Error triggering document upload notification:', err.message));

    res.status(201).json({
        success: true,
        message: `${docType} uploaded successfully to Google Drive`,
        data: documentRecord
    });
});

// @desc    Delete a user profile document
// @route   DELETE /api/documents/:id
// @access  Private
export const deleteUserDocument = asyncHandler(async (req, res) => {
    const documentRecord = await UserDocument.findById(req.params.id);

    if (!documentRecord) {
        res.status(404);
        throw new Error('Document record not found');
    }

    // Ensure authorization (User owns doc or Admin)
    if (documentRecord.user.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
        res.status(401);
        throw new Error('Not authorized to delete this document');
    }

    await documentRecord.deleteOne();

    res.json({
        success: true,
        message: 'Document record deleted successfully'
    });
});

// @desc    Verify or Update document status (Admin)
// @route   PUT /api/documents/:id/verify
// @access  Private (Admin/Employee)
export const verifyUserDocument = asyncHandler(async (req, res) => {
    const { status = 'Verified', notes = '' } = req.body;
    const documentRecord = await UserDocument.findById(req.params.id);

    if (!documentRecord) {
        res.status(404);
        throw new Error('Document record not found');
    }

    documentRecord.verificationStatus = status;
    if (notes) documentRecord.notes = notes;
    await documentRecord.save();

    res.json({
        success: true,
        message: `Document status updated to ${status}`,
        data: documentRecord
    });
});

// @desc    Download document file with forced Content-Disposition attachment header
// @route   GET /api/documents/download
// @access  Public / Authenticated
export const downloadDocumentFile = asyncHandler(async (req, res) => {
    const { url, name } = req.query;
    if (!url) {
        return res.status(400).json({ message: 'Document URL is required' });
    }

    const filename = name || 'document';

    // 1. Local /uploads/ files
    if (url.startsWith('/uploads/')) {
        const cleanPath = url.replace('/uploads/', '').split('?')[0];
        const uploadsDir = path.resolve(__dirname, '../uploads');
        const filePath = path.join(uploadsDir, cleanPath);
        if (fs.existsSync(filePath)) {
            return res.download(filePath, filename);
        }
        return res.status(404).json({ message: 'File not found on server' });
    }

    // 2. Google Drive files: redirect to export=download
    if (url.includes('drive.google.com/file/d/')) {
        const match = url.match(/\/file\/d\/([a-zA-Z0-9_-]+)/);
        if (match && match[1]) {
            return res.redirect(`https://drive.google.com/uc?export=download&id=${match[1]}`);
        }
    }

    // 3. Fallback: redirect to original URL
    res.redirect(url);
});
