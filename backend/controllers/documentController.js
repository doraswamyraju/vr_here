import asyncHandler from 'express-async-handler';
import UserDocument from '../models/UserDocument.js';
import User from '../models/User.js';
import { uploadBufferToDrive, getCustomerDriveFolder } from '../services/googleDriveService.js';
import { triggerNotification } from '../services/notificationService.js';

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
