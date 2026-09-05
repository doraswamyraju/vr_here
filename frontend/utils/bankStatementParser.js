import * as XLSX from 'xlsx';
import * as pdfjsLib from 'pdfjs-dist';
import pdfWorker from 'pdfjs-dist/build/pdf.worker.min.js?url';

// Configure PDFjs worker via local bundled Vite URL
if (typeof window !== 'undefined') {
    try {
        pdfjsLib.GlobalWorkerOptions.workerSrc = pdfWorker;
    } catch (e) {
        console.warn('Could not set pdfjs workerSrc:', e);
    }
}

/**
 * Parse standard Indian bank statement dates (DD/MM/YYYY, DD-MM-YYYY, DD-MMM-YYYY)
 */
export const parseIndianDate = (dateStr) => {
    if (!dateStr) return new Date().toISOString().split('T')[0];
    const clean = dateStr.trim();
    
    // DD/MM/YYYY or DD-MM-YYYY or DD.MM.YYYY
    const dmy = clean.match(/^(\d{1,2})[\.\/\-](\d{1,2})[\.\/\-](\d{2,4})$/);
    if (dmy) {
        let day = parseInt(dmy[1], 10);
        let month = parseInt(dmy[2], 10);
        let year = parseInt(dmy[3], 10);
        if (year < 100) year += 2000;
        return `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
    }
    
    // DD-MMM-YYYY or DD MMM YYYY (e.g. 02-Mar-2025, 02 Mar 2025)
    const monthNames = { 
        jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, 
        jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 
    };
    const dMy = clean.match(/^(\d{1,2})[\.\/\-\s]([A-Za-z]{3})[\.\/\-\s](\d{2,4})$/i);
    if (dMy) {
        let day = parseInt(dMy[1], 10);
        let mName = dMy[2].toLowerCase();
        let month = monthNames[mName] || 1;
        let year = parseInt(dMy[3], 10);
        if (year < 100) year += 2000;
        return `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
    }
    
    return new Date().toISOString().split('T')[0];
};

/**
 * Auto-detect bank name from extracted text content
 */
export const detectBankFromText = (text) => {
    const upper = (text || '').toUpperCase();
    if (upper.includes('UNION BANK OF INDIA') || upper.includes('UNION BANK') || upper.includes('UBIN') || upper.includes('UNIONBANKOFINDIA')) return 'Union Bank of India';
    if (upper.includes('STATE BANK OF INDIA') || /\bSBI\b/.test(upper) || upper.includes('ONLINESBI')) return 'State Bank of India (SBI)';
    if (upper.includes('HDFC BANK') || /\bHDFC\b/.test(upper)) return 'HDFC Bank';
    if (upper.includes('ICICI BANK') || /\bICICI\b/.test(upper)) return 'ICICI Bank';
    if (upper.includes('AXIS BANK') || /\bAXIS\b/.test(upper)) return 'Axis Bank';
    if (upper.includes('KOTAK MAHINDRA') || upper.includes('KOTAK BANK') || /\bKOTAK\b/.test(upper)) return 'Kotak Mahindra Bank';
    if (upper.includes('PUNJAB NATIONAL') || /\bPNB\b/.test(upper)) return 'Punjab National Bank (PNB)';
    if (upper.includes('CANARA BANK')) return 'Canara Bank';
    if (upper.includes('BANK OF BARODA') || /\bBOB\b/.test(upper)) return 'Bank of Baroda';
    if (upper.includes('FEDERAL BANK')) return 'Federal Bank';
    if (upper.includes('INDUSIND')) return 'IndusInd Bank';
    if (upper.includes('YES BANK')) return 'Yes Bank';
    if (upper.includes('IDFC FIRST') || /\bIDFC\b/.test(upper)) return 'IDFC FIRST Bank';
    if (upper.includes('INDIAN BANK')) return 'Indian Bank';
    if (upper.includes('BANK OF INDIA')) return 'Bank of India';
    return 'Bank Account';
};

/**
 * Auto-detect account number from text
 */
export const detectAccountNumberFromText = (text) => {
    const patterns = [
        /(?:A\/c(?:\s*No|\s*Number)?|Account(?:\s*No|\s*Number|\s*#)?)\s*[:.-]?\s*([0-9Xx]{8,18})/i,
        /(?:Account\s*ID|Customer\s*ID)\s*[:.-]?\s*([0-9Xx]{8,18})/i,
        /\b(?:A\/c|Acc|Acct)\s*[:.-]?\s*([0-9Xx]{8,18})/i
    ];
    for (const p of patterns) {
        const match = text.match(p);
        if (match && match[1]) {
            return match[1].trim();
        }
    }
    return '';
};

/**
 * Parse an Excel / CSV file into transaction lines
 */
export const parseExcelStatement = async (file) => {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const data = new Uint8Array(e.target.result);
                const workbook = XLSX.read(data, { type: 'array', cellDates: true });
                const sheetName = workbook.SheetNames[0];
                const worksheet = workbook.Sheets[sheetName];
                const jsonRows = XLSX.utils.sheet_to_json(worksheet, { header: 1, defval: '' });

                const rawText = jsonRows.map(r => r.join(' ')).join('\n');
                const bankName = detectBankFromText(rawText);
                const accountNumber = detectAccountNumberFromText(rawText);

                const transactions = [];

                for (let r = 0; r < jsonRows.length; r++) {
                    const row = jsonRows[r];
                    if (!row || row.length < 3) continue;

                    const rowStr = row.map(c => String(c).toLowerCase()).join(' ');
                    // Skip header rows
                    if (rowStr.includes('date') && (rowStr.includes('narration') || rowStr.includes('description') || rowStr.includes('particulars'))) {
                        continue;
                    }

                    // Try finding date in first 2 columns
                    let rowDate = new Date().toISOString().split('T')[0];
                    if (row[0] && !isNaN(Date.parse(row[0]))) {
                        rowDate = new Date(row[0]).toISOString().split('T')[0];
                    } else if (row[1] && !isNaN(Date.parse(row[1]))) {
                        rowDate = new Date(row[1]).toISOString().split('T')[0];
                    }

                    // Find narration
                    const description = String(row[1] || row[2] || '').trim();
                    if (!description || description.length < 3) continue;

                    let debitAmt = 0;
                    let creditAmt = 0;
                    let refNo = '';

                    row.forEach(cell => {
                        const val = String(cell).replace(/,/g, '').trim();
                        const num = parseFloat(val);
                        if (!isNaN(num) && num > 0) {
                            if (debitAmt === 0) debitAmt = num;
                            else if (creditAmt === 0) creditAmt = num;
                        }
                        if (val.length >= 8 && /^[a-zA-Z0-9]+$/.test(val) && isNaN(parseFloat(val))) {
                            refNo = val;
                        }
                    });

                    const isCredit = creditAmt > 0 || (debitAmt > 0 && (rowStr.includes('cr') || rowStr.includes('deposit')));
                    const amount = isCredit ? (creditAmt || debitAmt) : debitAmt;

                    if (amount > 0) {
                        transactions.push({
                            date: rowDate,
                            description: description.slice(0, 120),
                            referenceNo: refNo || `TXN${Math.floor(100000 + Math.random() * 900000)}`,
                            type: isCredit ? 'CREDIT' : 'DEBIT',
                            amount: Math.abs(amount),
                            balance: 0,
                            reconciliationStatus: 'UNRECONCILED'
                        });
                    }
                }

                resolve({
                    bankName: bankName !== 'Bank Account' ? bankName : 'Bank Statement',
                    accountNumber: accountNumber || 'A/c Auto-Detected',
                    transactions,
                    fileType: 'EXCEL'
                });
            } catch (err) {
                reject(err);
            }
        };
        reader.onerror = reject;
        reader.readAsArrayBuffer(file);
    });
};

/**
 * Parse a multi-page PDF bank statement with spatial coordinate line reconstruction
 */
export const parsePdfStatement = async (file, password = '') => {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = async (e) => {
            try {
                const arrayBuffer = e.target.result;
                const loadingTask = pdfjsLib.getDocument({
                    data: arrayBuffer,
                    password: password || undefined
                });

                let pdfDoc;
                try {
                    pdfDoc = await loadingTask.promise;
                } catch (pdfErr) {
                    if (pdfErr.name === 'PasswordException' || String(pdfErr.message).includes('password') || pdfErr.code === 1 || pdfErr.code === 2) {
                        return reject({
                            isPasswordRequired: true,
                            message: 'PDF is password protected. Please enter the password to unlock.'
                        });
                    }
                    throw pdfErr;
                }

                let fullDocumentText = '';
                const allSpatialRows = [];

                // Iterate through EVERY page of the PDF document
                for (let pageNum = 1; pageNum <= pdfDoc.numPages; pageNum++) {
                    const page = await pdfDoc.getPage(pageNum);
                    const textContent = await page.getTextContent();
                    
                    const pageItems = [];
                    for (const it of textContent.items) {
                        if (!it.str || !it.str.trim()) continue;
                        pageItems.push({
                            str: it.str.trim(),
                            x: it.transform[4],
                            y: it.transform[5],
                            w: it.width || 0,
                            h: it.height || 0
                        });
                    }

                    // Sort items: Y descending (top to bottom), then X ascending (left to right)
                    pageItems.sort((a, b) => (b.y - a.y) || (a.x - b.x));

                    // Cluster items into horizontal rows (tolerance 4.0 pt)
                    let currentCluster = [];
                    let clusterY = null;

                    for (const it of pageItems) {
                        if (clusterY === null || Math.abs(it.y - clusterY) > 4.5) {
                            if (currentCluster.length > 0) {
                                currentCluster.sort((a, b) => a.x - b.x);
                                const rowText = currentCluster.map(c => c.str).join(' ');
                                allSpatialRows.push({
                                    text: rowText,
                                    items: currentCluster,
                                    pageNum
                                });
                                fullDocumentText += ' ' + rowText;
                            }
                            currentCluster = [it];
                            clusterY = it.y;
                        } else {
                            currentCluster.push(it);
                        }
                    }
                    if (currentCluster.length > 0) {
                        currentCluster.sort((a, b) => a.x - b.x);
                        const rowText = currentCluster.map(c => c.str).join(' ');
                        allSpatialRows.push({
                            text: rowText,
                            items: currentCluster,
                            pageNum
                        });
                        fullDocumentText += ' ' + rowText;
                    }
                }

                // Detect Bank & Account details across whole document
                const bankName = detectBankFromText(fullDocumentText);
                const accountNumber = detectAccountNumberFromText(fullDocumentText);

                // Date matcher: DD/MM/YYYY, DD-MM-YYYY, DD-MMM-YYYY, DD/MM/YY
                const dateRegex = /\b(\d{1,2}[\.\/\-]\d{1,2}[\.\/\-]\d{2,4}|\d{1,2}[\-\s](?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[\-\s]\d{2,4})\b/i;
                
                // Amount matcher with optional (Dr)/(Cr) suffix
                // e.g. "130.00 (Dr)", "31810.01 (Cr)", "130.00", "1,250.00"
                const amountTokenRegex = /\b(\d{1,3}(?:,\d{3})*(?:\.\d{2})?|\d+\.\d{2})\s*(?:\((?:Dr|Cr|DR|CR)\)|(?:Dr|Cr|DR|CR)\b)?/gi;

                const transactions = [];

                for (let i = 0; i < allSpatialRows.length; i++) {
                    const row = allSpatialRows[i];
                    const lineText = row.text;

                    // Skip common headers and footers
                    const lower = lineText.toLowerCase();
                    if (lower.includes('details of statement') || 
                        lower.includes('closing balance') || 
                        lower.includes('opening balance') ||
                        (lower.includes('date') && lower.includes('remarks') && lower.includes('amount')) ||
                        (lower.includes('date') && lower.includes('narration') && lower.includes('balance'))) {
                        continue;
                    }

                    const dateMatch = lineText.match(dateRegex);
                    if (dateMatch) {
                        const rawDateStr = dateMatch[0];
                        const formattedDate = parseIndianDate(rawDateStr);

                        // Find all amount candidates
                        const amounts = [];
                        let match;
                        const amtRegexLocal = /(\d{1,3}(?:,\d{3})*\.\d{2}|\d+\.\d{2})\s*(?:\(((?:Dr|Cr|DR|CR))\)|((?:Dr|Cr|DR|CR)\b))?/gi;
                        
                        while ((match = amtRegexLocal.exec(lineText)) !== null) {
                            const rawVal = match[1].replace(/,/g, '');
                            const num = parseFloat(rawVal);
                            const drcrTag = (match[2] || match[3] || '').toUpperCase();
                            if (!isNaN(num) && num > 0) {
                                amounts.push({
                                    raw: match[0],
                                    value: num,
                                    tag: drcrTag
                                });
                            }
                        }

                        if (amounts.length >= 1) {
                            // First amount is the transaction amount, second is running balance if present
                            const txnAmountObj = amounts[0];
                            const balanceAmountObj = amounts.length > 1 ? amounts[1] : null;

                            // Determine Credit or Debit
                            let isCredit = false;
                            if (txnAmountObj.tag === 'CR') {
                                isCredit = true;
                            } else if (txnAmountObj.tag === 'DR') {
                                isCredit = false;
                            } else if (balanceAmountObj && balanceAmountObj.tag === 'CR' && txnAmountObj.tag === 'CR') {
                                isCredit = true;
                            } else {
                                // Check line text indicators
                                isCredit = /\b(CR|CREDIT|DEPOSIT|INWARD|RECEIVED)\b/i.test(lineText) && !/\b(DR|DEBIT)\b/i.test(lineText);
                            }

                            // Extract Transaction ID / Reference No
                            let referenceNo = '';
                            // Check for UPI/AR/ or 6-18 digit transaction ID in row
                            const refMatch = lineText.match(/\b(?:UPI\/[A-Z0-9]+\/|REF\/|UTR\/)?([0-9]{8,18})\b/i);
                            if (refMatch && refMatch[1]) {
                                referenceNo = refMatch[1];
                            } else {
                                const idMatch = lineText.match(/\b([0-9]{6,12})\b/);
                                if (idMatch && idMatch[1] && idMatch[1] !== rawDateStr.replace(/[^0-9]/g, '')) {
                                    referenceNo = idMatch[1];
                                }
                            }

                            // Build clean description / narration
                            let desc = lineText;
                            // Remove S.No, Date, amounts
                            desc = desc.replace(rawDateStr, ' ');
                            amounts.forEach(a => {
                                desc = desc.replace(a.raw, ' ');
                            });
                            // Remove leading S.No if present (e.g. "169 ")
                            desc = desc.replace(/^\s*\d{1,4}\s+/, '');
                            desc = desc.replace(/\s+/g, ' ').trim();

                            // If next row is a continuation line (no date, no amount), append it
                            if (i + 1 < allSpatialRows.length) {
                                const nextRow = allSpatialRows[i + 1];
                                const nextDateMatch = nextRow.text.match(dateRegex);
                                const nextAmtMatch = nextRow.text.match(amtRegexLocal);
                                if (!nextDateMatch && !nextAmtMatch && nextRow.text.length > 3 && !nextRow.text.toLowerCase().includes('closing')) {
                                    desc += ' ' + nextRow.text.trim();
                                }
                            }

                            transactions.push({
                                date: formattedDate,
                                description: desc.slice(0, 150) || 'Bank Transaction',
                                referenceNo: referenceNo || `TXN${Math.floor(100000 + Math.random() * 900000)}`,
                                type: isCredit ? 'CREDIT' : 'DEBIT',
                                amount: txnAmountObj.value,
                                balance: balanceAmountObj ? balanceAmountObj.value : 0,
                                reconciliationStatus: 'UNRECONCILED'
                            });
                        }
                    }
                }

                resolve({
                    bankName: bankName !== 'Bank Account' ? bankName : 'Bank Statement',
                    accountNumber: accountNumber || 'A/c Auto-Detected',
                    transactions,
                    fileType: 'PDF',
                    isDecrypted: Boolean(password)
                });
            } catch (err) {
                reject(err);
            }
        };
        reader.onerror = reject;
        reader.readAsArrayBuffer(file);
    });
};
