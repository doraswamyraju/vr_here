import { google } from 'googleapis';
import path from 'path';
import fs from 'fs';
import { Readable } from 'stream';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SERVICE_ACCOUNT_PATH = path.join(__dirname, '..', 'service-account.json');

// Google Drive API scopes
const SCOPES = ['https://www.googleapis.com/auth/drive'];

let driveClient = null;

/**
 * Initializes and returns the Google Drive API client using service-account.json
 */
const getDriveClient = () => {
    if (driveClient) return driveClient;

    try {
        let keyFileExists = fs.existsSync(SERVICE_ACCOUNT_PATH);
        let auth;

        if (keyFileExists) {
            auth = new google.auth.GoogleAuth({
                keyFile: SERVICE_ACCOUNT_PATH,
                scopes: SCOPES,
            });
        } else if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
            const credentials = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
            auth = new google.auth.GoogleAuth({
                credentials,
                scopes: SCOPES,
            });
        } else {
            console.warn('[GoogleDrive] Service account JSON not found. Falling back to default auth.');
            auth = new google.auth.GoogleAuth({ scopes: SCOPES });
        }

        driveClient = google.drive({ version: 'v3', auth });
        console.log('[GoogleDrive] Client initialized successfully.'.green);
        return driveClient;
    } catch (error) {
        console.error('[GoogleDrive] Auth Initialization Error:', error.message);
        return null;
    }
};

/**
 * Finds or creates a folder in Google Drive.
 */
export const findOrCreateFolder = async (folderName, parentFolderId = null) => {
    const drive = getDriveClient();
    if (!drive) return null;

    const effectiveParentId = parentFolderId || process.env.GOOGLE_DRIVE_ROOT_FOLDER_ID;

    try {
        let query = `name = '${folderName.replace(/'/g, "\\'")}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false`;
        if (effectiveParentId) {
            query += ` and '${effectiveParentId}' in parents`;
        }

        const res = await drive.files.list({
            q: query,
            fields: 'files(id, name)',
            spaces: 'drive',
            supportsAllDrives: true,
            includeItemsFromAllDrives: true,
        });

        if (res.data.files && res.data.files.length > 0) {
            return res.data.files[0].id;
        }

        // Folder does not exist, create it
        const folderMetadata = {
            name: folderName,
            mimeType: 'application/vnd.google-apps.folder',
            parents: effectiveParentId ? [effectiveParentId] : [],
        };

        const folder = await drive.files.create({
            requestBody: folderMetadata,
            fields: 'id, name',
            supportsAllDrives: true,
        });

        console.log(`[GoogleDrive] Created Folder: "${folderName}" (ID: ${folder.data.id})`.cyan);
        return folder.data.id;
    } catch (error) {
        console.error(`[GoogleDrive] Error finding/creating folder "${folderName}":`, error.message);
        return null;
    }
};

/**
 * Uploads a buffer directly into Google Drive (no VPS local disk storage).
 */
export const uploadBufferToDrive = async ({ fileBuffer, mimeType, fileName, parentFolderId = null }) => {
    const drive = getDriveClient();
    if (!drive) throw new Error('Google Drive client is not available');

    const effectiveParentId = parentFolderId || process.env.GOOGLE_DRIVE_ROOT_FOLDER_ID;

    try {
        const stream = Readable.from(fileBuffer);
        const fileMetadata = {
            name: fileName,
            parents: effectiveParentId ? [effectiveParentId] : [],
        };

        const media = {
            mimeType,
            body: stream,
        };

        const res = await drive.files.create({
            requestBody: fileMetadata,
            media,
            fields: 'id, name, webViewLink, webContentLink',
            supportsAllDrives: true,
        });

        // Set file permissions to be viewable via link
        try {
            await drive.permissions.create({
                fileId: res.data.id,
                requestBody: {
                    role: 'reader',
                    type: 'anyone',
                },
                supportsAllDrives: true,
            });
        } catch (permErr) {
            console.warn('[GoogleDrive] Warning creating public permission:', permErr.message);
        }

        console.log(`[GoogleDrive] File uploaded: "${fileName}" (ID: ${res.data.id})`.green);
        return {
            fileId: res.data.id,
            webViewLink: res.data.webViewLink || `https://drive.google.com/file/d/${res.data.id}/view`,
            webContentLink: res.data.webContentLink,
        };
    } catch (error) {
        console.error(`[GoogleDrive] Upload failed for "${fileName}":`, error.message);
        throw error;
    }
};

/**
 * Copies an existing file in Google Drive into a target folder.
 */
export const copyDriveFile = async (fileId, targetFolderId, newFileName = null) => {
    const drive = getDriveClient();
    if (!drive || !fileId || !targetFolderId) return null;

    try {
        const res = await drive.files.copy({
            fileId,
            requestBody: {
                name: newFileName || undefined,
                parents: [targetFolderId],
            },
            fields: 'id, name, webViewLink',
            supportsAllDrives: true,
        });

        console.log(`[GoogleDrive] Copied File ID: ${fileId} -> Target Folder ID: ${targetFolderId}`.green);
        return {
            fileId: res.data.id,
            webViewLink: res.data.webViewLink || `https://drive.google.com/file/d/${res.data.id}/view`,
        };
    } catch (error) {
        console.error(`[GoogleDrive] Copy File Error (ID: ${fileId}):`, error.message);
        return null;
    }
};

/**
 * Prepares and returns the customer's Google Drive folder hierarchy:
 * Root ("VR HERE Documents") -> "Customers" -> "[Client Name]" -> "Profile Documents" or "Orders/[Order ID]"
 */
export const getCustomerDriveFolder = async ({ clientName, orderId = null, orderDate = null }) => {
    try {
        const rootFolderId = process.env.GOOGLE_DRIVE_ROOT_FOLDER_ID || 
                             await findOrCreateFolder('VR HERE Documents');
        const customersFolderId = await findOrCreateFolder('Customers', rootFolderId);
        
        const sanitizeClient = clientName || 'General Customers';
        const clientFolderId = await findOrCreateFolder(sanitizeClient, customersFolderId);

        let profileDocsFolderId = null;
        let orderFolderId = null;

        profileDocsFolderId = await findOrCreateFolder('Profile Documents (Basic Docs)', clientFolderId);

        if (orderId) {
            const ordersFolderId = await findOrCreateFolder('Orders', clientFolderId);
            const dateStr = orderDate ? new Date(orderDate).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' }) : '';
            const orderFolderName = `${orderId} ${dateStr ? `(${dateStr})` : ''}`.trim();
            orderFolderId = await findOrCreateFolder(orderFolderName, ordersFolderId);
        }

        return {
            rootFolderId,
            customersFolderId,
            clientFolderId,
            profileDocsFolderId,
            orderFolderId,
            folderUrl: `https://drive.google.com/drive/folders/${clientFolderId}`,
        };
    } catch (error) {
        console.error('[GoogleDrive] Error building folder hierarchy:', error.message);
        return null;
    }
};
