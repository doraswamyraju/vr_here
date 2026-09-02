import path from 'path';
import multer from 'multer';

// Memory storage streaming directly to Google Drive (no VPS disk storage)
const storage = multer.memoryStorage();

function checkFileType(file, cb) {
    const allowedExtensions = /^(jpg|jpeg|png|webp|svg|gif|bmp|pdf|doc|docx|xls|xlsx|csv|txt|zip|rar|7z|rtf|odt|ods)$/i;
    const fileExt = path.extname(file.originalname).replace(/^\./, '').toLowerCase();

    // Accept if valid extension or document/image mimetype
    if (allowedExtensions.test(fileExt) || /image|pdf|word|excel|spreadsheet|csv|plain|zip|document|octet-stream/i.test(file.mimetype)) {
        return cb(null, true);
    } else {
        cb(new Error('Invalid file type! Allowed types: Images, PDFs, Word, Excel, CSV, TXT, ZIP.'));
    }
}

const upload = multer({
    storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB limit
    fileFilter: function (req, file, cb) {
        checkFileType(file, cb);
    },
});

export default upload;
