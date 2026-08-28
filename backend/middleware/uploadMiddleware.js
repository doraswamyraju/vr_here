import path from 'path';
import fs from 'fs';
import multer from 'multer';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Memory storage streaming directly to Google Drive (no VPS disk storage)
const storage = multer.memoryStorage();

function checkFileType(file, cb) {
    const filetypes = /jpg|jpeg|png|pdf|doc|docx|xls|xlsx|csv|txt|zip/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const allowedMimeRegex = /image|pdf|word|excel|spreadsheet|csv|text\/plain|zip|octet-stream/;
    const mimetype = allowedMimeRegex.test(file.mimetype) || filetypes.test(file.mimetype);

    if (extname && mimetype) {
        return cb(null, true);
    } else {
        cb(new Error('Invalid file type! Allowed types: Images, PDFs, Word, Excel, CSV, TXT, ZIP.'));
    }
}

const upload = multer({
    storage,
    fileFilter: function (req, file, cb) {
        checkFileType(file, cb);
    },
});

export default upload;
