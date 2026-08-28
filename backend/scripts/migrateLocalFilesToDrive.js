import mongoose from 'mongoose';
import path from 'path';
import fs from 'fs';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load env vars
dotenv.config({ path: path.join(__dirname, '..', '.env') });

import Order from '../models/Order.js';
import UserDocument from '../models/UserDocument.js';
import { getCustomerDriveFolder, uploadBufferToDrive } from '../services/googleDriveService.js';

const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/vrhere');
        console.log(`[Migration] MongoDB Connected: ${conn.connection.host}`);
    } catch (err) {
        console.error(`[Migration] Database Connection Error: ${err.message}`);
        process.exit(1);
    }
};

const resolveLocalFilePath = (fileUrl) => {
    if (!fileUrl || typeof fileUrl !== 'string') return null;
    if (!fileUrl.startsWith('/uploads/')) return null;

    const fileName = fileUrl.replace('/uploads/', '');
    const uploadsDir = path.join(__dirname, '..', 'uploads');
    const fullPath = path.join(uploadsDir, fileName);

    if (fs.existsSync(fullPath)) {
        return { fullPath, fileName };
    }
    return null;
};

const mimeTypes = {
    '.pdf': 'application/pdf',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xls': 'application/vnd.ms-excel',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
};

const getMimeType = (fileName) => {
    const ext = path.extname(fileName).toLowerCase();
    return mimeTypes[ext] || 'application/octet-stream';
};

const runMigration = async () => {
    await connectDB();
    console.log('[Migration] Starting VPS Local Disk -> Google Drive Migration...'.cyan);

    const orders = await Order.find({});
    let totalMigratedFiles = 0;
    let totalUpdatedOrders = 0;

    for (const order of orders) {
        let orderModified = false;

        const driveFolders = await getCustomerDriveFolder({
            clientName: order.clientName || 'General Client',
            orderId: order._id,
            orderDate: order.createdAt
        });

        const orderFolderId = driveFolders ? driveFolders.orderFolderId : null;

        // 1. Client Documents
        if (order.clientDocuments && order.clientDocuments.length > 0) {
            for (const doc of order.clientDocuments) {
                const localInfo = resolveLocalFilePath(doc.url);
                if (localInfo) {
                    try {
                        const fileBuffer = fs.readFileSync(localInfo.fullPath);
                        const driveResult = await uploadBufferToDrive({
                            fileBuffer,
                            mimeType: getMimeType(localInfo.fileName),
                            fileName: doc.name || localInfo.fileName,
                            parentFolderId: orderFolderId
                        });

                        doc.url = driveResult.webViewLink;
                        orderModified = true;
                        totalMigratedFiles++;
                        console.log(`[Migration] Migrated Client Doc: ${doc.name} -> Drive URL: ${doc.url}`);
                    } catch (err) {
                        console.error(`[Migration] Failed to migrate ${doc.name}: ${err.message}`);
                    }
                }
            }
        }

        // 2. Admin Documents
        if (order.adminDocuments && order.adminDocuments.length > 0) {
            for (const doc of order.adminDocuments) {
                const localInfo = resolveLocalFilePath(doc.url);
                if (localInfo) {
                    try {
                        const fileBuffer = fs.readFileSync(localInfo.fullPath);
                        const driveResult = await uploadBufferToDrive({
                            fileBuffer,
                            mimeType: getMimeType(localInfo.fileName),
                            fileName: doc.name || localInfo.fileName,
                            parentFolderId: orderFolderId
                        });

                        doc.url = driveResult.webViewLink;
                        orderModified = true;
                        totalMigratedFiles++;
                        console.log(`[Migration] Migrated Admin Doc: ${doc.name} -> Drive URL: ${doc.url}`);
                    } catch (err) {
                        console.error(`[Migration] Failed to migrate Admin Doc ${doc.name}: ${err.message}`);
                    }
                }
            }
        }

        // 3. Final Certificate
        if (order.finalCertificateUrl) {
            const localInfo = resolveLocalFilePath(order.finalCertificateUrl);
            if (localInfo) {
                try {
                    const fileBuffer = fs.readFileSync(localInfo.fullPath);
                    const driveResult = await uploadBufferToDrive({
                        fileBuffer,
                        mimeType: getMimeType(localInfo.fileName),
                        fileName: `${order.serviceName}_Final_Certificate_${localInfo.fileName}`,
                        parentFolderId: orderFolderId
                    });

                    order.finalCertificateUrl = driveResult.webViewLink;
                    orderModified = true;
                    totalMigratedFiles++;
                    console.log(`[Migration] Migrated Final Certificate -> Drive URL: ${order.finalCertificateUrl}`);
                } catch (err) {
                    console.error(`[Migration] Failed to migrate Final Certificate: ${err.message}`);
                }
            }
        }

        // 4. Customer Requirements
        if (order.customerRequirements && order.customerRequirements.length > 0) {
            for (const req of order.customerRequirements) {
                // Check uploadedDocumentUrl
                if (req.uploadedDocumentUrl) {
                    const localInfo = resolveLocalFilePath(req.uploadedDocumentUrl);
                    if (localInfo) {
                        try {
                            const fileBuffer = fs.readFileSync(localInfo.fullPath);
                            const driveResult = await uploadBufferToDrive({
                                fileBuffer,
                                mimeType: getMimeType(localInfo.fileName),
                                fileName: req.uploadedDocumentName || req.title || localInfo.fileName,
                                parentFolderId: orderFolderId
                            });

                            req.uploadedDocumentUrl = driveResult.webViewLink;
                            req.documentUrl = driveResult.webViewLink;
                            orderModified = true;
                            totalMigratedFiles++;
                            console.log(`[Migration] Migrated Requirement: ${req.title} -> Drive URL: ${req.uploadedDocumentUrl}`);
                        } catch (err) {
                            console.error(`[Migration] Failed requirement ${req.title}: ${err.message}`);
                        }
                    }
                }

                // Check req.documents array
                if (req.documents && req.documents.length > 0) {
                    for (const subDoc of req.documents) {
                        const localInfo = resolveLocalFilePath(subDoc.url);
                        if (localInfo) {
                            try {
                                const fileBuffer = fs.readFileSync(localInfo.fullPath);
                                const driveResult = await uploadBufferToDrive({
                                    fileBuffer,
                                    mimeType: getMimeType(localInfo.fileName),
                                    fileName: subDoc.name || localInfo.fileName,
                                    parentFolderId: orderFolderId
                                });

                                subDoc.url = driveResult.webViewLink;
                                orderModified = true;
                                totalMigratedFiles++;
                            } catch (err) {
                                console.error(`[Migration] Failed subDoc ${subDoc.name}: ${err.message}`);
                            }
                        }
                    }
                }
            }
        }

        if (orderModified) {
            await order.save();
            totalUpdatedOrders++;
        }
    }

    console.log(`\n==================================================`.green);
    console.log(`[Migration Complete] Total Files Migrated to Drive: ${totalMigratedFiles}`.green);
    console.log(`[Migration Complete] Total Orders Updated: ${totalUpdatedOrders}`.green);
    console.log(`==================================================\n`.green);

    process.exit(0);
};

runMigration();
