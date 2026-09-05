import asyncHandler from 'express-async-handler';
import mongoose from 'mongoose';
import Transaction from '../models/Transaction.js';
import CompanyDetails from '../models/CompanyDetails.js';
import Party from '../models/Party.js';
import BankStatement from '../models/BankStatement.js';
import Payroll from '../models/Payroll.js';

// Helper: Convert number to Indian words
export const numberToWords = (num) => {
    if (!num || isNaN(num)) return 'Zero Rupees Only';
    const a = ['', 'One ', 'Two ', 'Three ', 'Four ', 'Five ', 'Six ', 'Seven ', 'Eight ', 'Nine ', 'Ten ', 'Eleven ', 'Twelve ', 'Thirteen ', 'Fourteen ', 'Fifteen ', 'Sixteen ', 'Seventeen ', 'Eighteen ', 'Nineteen '];
    const b = ['', '', 'Twenty', 'Thirty', 'Forty', 'Fifty', 'Sixty', 'Seventy', 'Eighty', 'Ninety'];

    const numStr = Math.floor(Math.abs(num)).toString();
    if (numStr.length > 9) return 'Rupees ' + num.toLocaleString('en-IN');

    const n = ('000000000' + numStr).substr(-9).match(/^(\d{2})(\d{2})(\d{2})(\d{1})(\d{2})$/);
    if (!n) return '';
    let str = '';
    str += (n[1] != 0) ? (a[Number(n[1])] || b[n[1][0]] + ' ' + a[n[1][1]]) + 'Crore ' : '';
    str += (n[2] != 0) ? (a[Number(n[2])] || b[n[2][0]] + ' ' + a[n[2][1]]) + 'Lakh ' : '';
    str += (n[3] != 0) ? (a[Number(n[3])] || b[n[3][0]] + ' ' + a[n[3][1]]) + 'Thousand ' : '';
    str += (n[4] != 0) ? (a[Number(n[4])] || b[n[4][0]] + ' ' + a[n[4][1]]) + 'Hundred ' : '';
    str += (n[5] != 0) ? ((str != '') ? 'and ' : '') + (a[Number(n[5])] || b[n[5][0]] + ' ' + a[n[5][1]]) : '';
    
    // Paise
    const paise = Math.round((Math.abs(num) - Math.floor(Math.abs(num))) * 100);
    let paiseStr = '';
    if (paise > 0) {
        paiseStr = ' and ' + (a[paise] || b[Math.floor(paise / 10)] + ' ' + a[paise % 10]) + 'Paise';
    }

    return 'Rupees ' + str.trim() + paiseStr + ' Only';
};

// ==================== TRANSACTIONS CRUD ====================

// @desc    Create a new transaction
// @route   POST /api/accounting/transactions
export const createTransaction = asyncHandler(async (req, res) => {
    const {
        transactionType,
        copyType,
        docNumber,
        docDate,
        dueDate,
        paymentMode,
        partyName,
        partyGstin,
        partyPan,
        partyAddress,
        partyState,
        partyPhone,
        partyEmail,
        placeOfSupply,
        isInterstate,
        shipToSameAsBilling,
        shipToName,
        shipToAddress,
        shipToGstin,
        shipToPan,
        shipToState,
        shipToMobile,
        shipToEmail,
        items,
        itcEligibility,
        paymentStatus,
        paidAmount,
        notes,
        attachmentUrl,
        termsAndConditions,
        clientId
    } = req.body;

    if (!transactionType || !docNumber || !docDate || !partyName || !placeOfSupply || !items || items.length === 0) {
        res.status(400);
        throw new Error('Please fill in all required fields and provide at least one item');
    }

    let targetUserId = req.user._id;
    if (clientId && (req.user.role === 'admin' || req.user.role === 'employee')) {
        targetUserId = clientId;
    }

    // Process line items with discount, taxable value, and tax breakdown
    let totalTaxableValue = 0;
    let totalCgst = 0;
    let totalSgst = 0;
    let totalIgst = 0;

    const processedItems = items.map(item => {
        const qty = Number(item.qty) || 1;
        const rate = Number(item.rate) || 0;
        const discPercent = Number(item.discPercent) || 0;
        const rawTotal = qty * rate;
        const discountAmount = Math.round((rawTotal * (discPercent / 100)) * 100) / 100;
        const taxableValue = Math.max(0, Math.round((rawTotal - discountAmount) * 100) / 100);

        let cgst = 0;
        let sgst = 0;
        let igst = 0;
        const gstRate = Number(item.gstRate) || 0;

        if (gstRate > 0) {
            if (isInterstate) {
                igst = Math.round((taxableValue * (gstRate / 100)) * 100) / 100;
            } else {
                cgst = Math.round((taxableValue * ((gstRate / 2) / 100)) * 100) / 100;
                sgst = cgst;
            }
        }

        const total = Math.round((taxableValue + cgst + sgst + igst) * 100) / 100;
        totalTaxableValue += taxableValue;
        totalCgst += cgst;
        totalSgst += sgst;
        totalIgst += igst;

        return {
            description: item.description,
            hsnSac: item.hsnSac || '',
            qty,
            unit: item.unit || 'PCS',
            rate,
            discPercent,
            taxableValue,
            gstRate,
            cgst,
            sgst,
            igst,
            total
        };
    });

    const rawGrandTotal = totalTaxableValue + totalCgst + totalSgst + totalIgst;
    const roundedTotal = Math.round(rawGrandTotal);
    const roundOff = Math.round((roundedTotal - rawGrandTotal) * 100) / 100;

    const summary = {
        totalTaxableValue: Math.round(totalTaxableValue * 100) / 100,
        totalCgst: Math.round(totalCgst * 100) / 100,
        totalSgst: Math.round(totalSgst * 100) / 100,
        totalIgst: Math.round(totalIgst * 100) / 100,
        roundOff,
        totalAmount: roundedTotal,
        amountInWords: numberToWords(roundedTotal)
    };

    const transaction = await Transaction.create({
        clientUser: targetUserId,
        transactionType,
        copyType: copyType || 'Original for Recipient',
        docNumber,
        docDate: new Date(docDate),
        dueDate: dueDate ? new Date(dueDate) : undefined,
        paymentMode: paymentMode || 'Bank Transfer',
        partyName,
        partyGstin: partyGstin || '',
        partyPan: partyPan || '',
        partyAddress: partyAddress || '',
        partyState: partyState || '',
        partyPhone: partyPhone || '',
        partyEmail: partyEmail || '',
        placeOfSupply,
        isInterstate: !!isInterstate,
        shipToSameAsBilling: shipToSameAsBilling !== false,
        shipToName: shipToName || '',
        shipToAddress: shipToAddress || '',
        shipToGstin: shipToGstin || '',
        shipToPan: shipToPan || '',
        shipToState: shipToState || '',
        shipToMobile: shipToMobile || '',
        shipToEmail: shipToEmail || '',
        items: processedItems,
        summary,
        itcEligibility: itcEligibility || 'N/A',
        paymentStatus: paymentStatus || 'Unpaid',
        paidAmount: Number(paidAmount) || 0,
        notes: notes || '',
        attachmentUrl: attachmentUrl || '',
        termsAndConditions: Array.isArray(termsAndConditions) && termsAndConditions.length > 0 ? termsAndConditions : undefined,
        createdBy: req.user._id
    });

    res.status(201).json(transaction);
});

// @desc    Get all transactions for the logged in client or filtered client
// @route   GET /api/accounting/transactions
export const getTransactions = asyncHandler(async (req, res) => {
    const { type, status, startDate, endDate, clientId, search } = req.query;

    let targetUserId = req.user._id;
    if (clientId && (req.user.role === 'admin' || req.user.role === 'employee')) {
        targetUserId = clientId;
    }

    const query = { clientUser: targetUserId };

    if (type && type !== 'All') query.transactionType = type;
    if (status && status !== 'All') query.status = status;
    if (startDate || endDate) {
        query.docDate = {};
        if (startDate) query.docDate.$gte = new Date(startDate);
        if (endDate) query.docDate.$lte = new Date(endDate);
    }
    if (search) {
        query.$or = [
            { docNumber: { $regex: search, $options: 'i' } },
            { partyName: { $regex: search, $options: 'i' } },
            { partyGstin: { $regex: search, $options: 'i' } }
        ];
    }

    const transactions = await Transaction.find(query).sort({ docDate: -1, createdAt: -1 });
    res.json(transactions);
});

// @desc    Update a transaction
// @route   PUT /api/accounting/transactions/:id
export const updateTransaction = asyncHandler(async (req, res) => {
    const transaction = await Transaction.findById(req.params.id);

    if (!transaction) {
        res.status(404);
        throw new Error('Transaction not found');
    }

    if (transaction.clientUser.toString() !== req.user._id.toString() && req.user.role !== 'admin' && req.user.role !== 'employee') {
        res.status(401);
        throw new Error('Not authorized to edit this transaction');
    }

    const updates = req.body;
    
    // Recalculate totals if items changed
    if (updates.items) {
        const isInterstate = updates.isInterstate !== undefined ? updates.isInterstate : transaction.isInterstate;
        let totalTaxableValue = 0;
        let totalCgst = 0;
        let totalSgst = 0;
        let totalIgst = 0;

        updates.items = updates.items.map(item => {
            const qty = Number(item.qty) || 1;
            const rate = Number(item.rate) || 0;
            const discPercent = Number(item.discPercent) || 0;
            const rawTotal = qty * rate;
            const discountAmount = Math.round((rawTotal * (discPercent / 100)) * 100) / 100;
            const taxableValue = Math.max(0, Math.round((rawTotal - discountAmount) * 100) / 100);

            let cgst = 0;
            let sgst = 0;
            let igst = 0;
            const gstRate = Number(item.gstRate) || 0;

            if (gstRate > 0) {
                if (isInterstate) {
                    igst = Math.round((taxableValue * (gstRate / 100)) * 100) / 100;
                } else {
                    cgst = Math.round((taxableValue * ((gstRate / 2) / 100)) * 100) / 100;
                    sgst = cgst;
                }
            }

            const total = Math.round((taxableValue + cgst + sgst + igst) * 100) / 100;
            totalTaxableValue += taxableValue;
            totalCgst += cgst;
            totalSgst += sgst;
            totalIgst += igst;

            return {
                description: item.description,
                hsnSac: item.hsnSac || '',
                qty,
                unit: item.unit || 'PCS',
                rate,
                discPercent,
                taxableValue,
                gstRate,
                cgst,
                sgst,
                igst,
                total
            };
        });

        const rawGrandTotal = totalTaxableValue + totalCgst + totalSgst + totalIgst;
        const roundedTotal = Math.round(rawGrandTotal);
        const roundOff = Math.round((roundedTotal - rawGrandTotal) * 100) / 100;

        updates.summary = {
            totalTaxableValue: Math.round(totalTaxableValue * 100) / 100,
            totalCgst: Math.round(totalCgst * 100) / 100,
            totalSgst: Math.round(totalSgst * 100) / 100,
            totalIgst: Math.round(totalIgst * 100) / 100,
            roundOff,
            totalAmount: roundedTotal,
            amountInWords: numberToWords(roundedTotal)
        };
    }

    Object.assign(transaction, updates);
    const updatedTransaction = await transaction.save();
    res.json(updatedTransaction);
});

// @desc    Delete a transaction
// @route   DELETE /api/accounting/transactions/:id
export const deleteTransaction = asyncHandler(async (req, res) => {
    const transaction = await Transaction.findById(req.params.id);

    if (!transaction) {
        res.status(404);
        throw new Error('Transaction not found');
    }

    if (transaction.clientUser.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
        res.status(401);
        throw new Error('Not authorized to delete this transaction');
    }

    await transaction.deleteOne();
    res.json({ message: 'Transaction removed successfully' });
});

// ==================== COMPANY SETTINGS ====================

// @desc    Get client company configuration
// @route   GET /api/accounting/company
export const getCompanyDetails = asyncHandler(async (req, res) => {
    const { clientId } = req.query;
    let targetUserId = req.user._id;
    if (clientId && (req.user.role === 'admin' || req.user.role === 'employee')) {
        targetUserId = clientId;
    }

    const company = await CompanyDetails.findOne({ user: targetUserId });
    if (!company) {
        return res.status(200).json(null);
    }
    res.json(company);
});

// @desc    Create or update company configuration
// @route   POST /api/accounting/company
export const upsertCompanyDetails = asyncHandler(async (req, res) => {
    const { 
        companyName, tradeName, gstin, address, state, bankDetails,
        phone, email, businessType, businessCategory, pincode,
        logo, signature, upiId, qrCode, clientId
    } = req.body;

    let targetUserId = req.user._id;
    if (clientId && (req.user.role === 'admin' || req.user.role === 'employee')) {
        targetUserId = clientId;
    }

    let company = await CompanyDetails.findOne({ user: targetUserId });

    if (company) {
        company.companyName = companyName || company.companyName;
        company.tradeName = tradeName !== undefined ? tradeName : company.tradeName;
        company.gstin = gstin || company.gstin;
        company.address = address || company.address;
        company.state = state || company.state;
        company.phone = phone !== undefined ? phone : company.phone;
        company.email = email !== undefined ? email : company.email;
        company.businessType = businessType !== undefined ? businessType : company.businessType;
        company.businessCategory = businessCategory !== undefined ? businessCategory : company.businessCategory;
        company.pincode = pincode !== undefined ? pincode : company.pincode;
        company.logo = logo !== undefined ? logo : company.logo;
        company.signature = signature !== undefined ? signature : company.signature;
        company.upiId = upiId !== undefined ? upiId : company.upiId;
        company.qrCode = qrCode !== undefined ? qrCode : company.qrCode;
        if (bankDetails) {
            company.bankDetails = { ...company.bankDetails, ...bankDetails };
        }
        await company.save();
    } else {
        company = await CompanyDetails.create({
            user: targetUserId,
            companyName,
            tradeName,
            gstin,
            address,
            state,
            phone,
            email,
            businessType,
            businessCategory,
            pincode,
            logo,
            signature,
            upiId,
            qrCode,
            bankDetails
        });
    }

    res.json(company);
});

// ==================== PARTIES (CUSTOMERS & VENDORS) ====================

// @desc    Get all parties for user
// @route   GET /api/accounting/parties
export const getParties = asyncHandler(async (req, res) => {
    const { clientId, type } = req.query;
    let targetUserId = req.user._id;
    if (clientId && (req.user.role === 'admin' || req.user.role === 'employee')) {
        targetUserId = clientId;
    }

    const query = { clientUser: targetUserId };
    if (type && type !== 'All') query.partyType = { $in: [type, 'Both'] };

    const parties = await Party.find(query).sort({ name: 1 });
    res.json(parties);
});

// @desc    Create a new party
// @route   POST /api/accounting/parties
export const createParty = asyncHandler(async (req, res) => {
    const { clientId, name, tradeName, partyType, gstin, pan, email, phone, billingAddress, shippingAddress, state, pincode, openingBalance, creditPeriodDays } = req.body;
    let targetUserId = req.user._id;
    if (clientId && (req.user.role === 'admin' || req.user.role === 'employee')) {
        targetUserId = clientId;
    }

    if (!name) {
        res.status(400);
        throw new Error('Party name is required');
    }

    const party = await Party.create({
        clientUser: targetUserId,
        name,
        tradeName: tradeName || '',
        partyType: partyType || 'Customer',
        gstin: gstin || '',
        pan: pan || '',
        email: email || '',
        phone: phone || '',
        billingAddress: billingAddress || '',
        shippingAddress: shippingAddress || '',
        state: state || 'Andhra Pradesh',
        pincode: pincode || '',
        openingBalance: Number(openingBalance) || 0,
        creditPeriodDays: Number(creditPeriodDays) || 30
    });

    res.status(201).json(party);
});

// @desc    Update a party
// @route   PUT /api/accounting/parties/:id
export const updateParty = asyncHandler(async (req, res) => {
    const party = await Party.findById(req.params.id);
    if (!party) {
        res.status(404);
        throw new Error('Party not found');
    }
    Object.assign(party, req.body);
    const updated = await party.save();
    res.json(updated);
});

// @desc    Delete a party
// @route   DELETE /api/accounting/parties/:id
export const deleteParty = asyncHandler(async (req, res) => {
    const party = await Party.findById(req.params.id);
    if (!party) {
        res.status(404);
        throw new Error('Party not found');
    }
    await party.deleteOne();
    res.json({ message: 'Party removed' });
});

// ==================== BANK STATEMENTS & MANUAL TAGGING ====================

// @desc    Get all bank statements
// @route   GET /api/accounting/bank-statements
export const getBankStatements = asyncHandler(async (req, res) => {
    const { clientId } = req.query;
    let targetUserId = req.user._id;
    if (clientId && (req.user.role === 'admin' || req.user.role === 'employee')) {
        targetUserId = clientId;
    }

    const statements = await BankStatement.find({ clientUser: targetUserId }).sort({ createdAt: -1 });
    res.json(statements);
});

// @desc    Upload / Save bank statement with parsed transaction lines (smart merge by account)
// @route   POST /api/accounting/bank-statements
export const createBankStatement = asyncHandler(async (req, res) => {
    const { clientId, bankName, accountNumber, statementTitle, fileName, fileUrl, isPasswordProtected, pdfPassword, transactions, replaceAll = false } = req.body;
    let targetUserId = req.user._id;
    if (clientId && (req.user.role === 'admin' || req.user.role === 'employee')) {
        targetUserId = clientId;
    }

    if (!bankName || !accountNumber || !transactions || transactions.length === 0) {
        res.status(400);
        throw new Error('Bank name, account number, and transaction rows are required');
    }

    const formattedTxs = transactions.map(t => ({
        date: new Date(t.date),
        description: t.description,
        referenceNo: t.referenceNo || '',
        type: t.type === 'CREDIT' ? 'CREDIT' : 'DEBIT',
        amount: Number(t.amount) || 0,
        balance: Number(t.balance) || 0,
        reconciliationStatus: t.reconciliationStatus || 'UNRECONCILED',
        taggedVoucher: t.taggedVoucher || null,
        taggedCategory: t.taggedCategory || '',
        notes: t.notes || ''
    }));

    // Check if account already exists for this client to prevent duplicate bank tabs
    let existingStatement = await BankStatement.findOne({ clientUser: targetUserId, accountNumber });

    if (existingStatement) {
        if (replaceAll) {
            existingStatement.transactions = formattedTxs;
        } else {
            // Append only new transactions that don't already exist (deduplicate by refNo or date+amount+desc)
            const existingKeys = new Set(existingStatement.transactions.map(tx => 
                tx.referenceNo ? tx.referenceNo : `${new Date(tx.date).toISOString().split('T')[0]}_${tx.amount}_${tx.description.slice(0, 30)}`
            ));

            const newUniqueTxs = formattedTxs.filter(tx => {
                const key = tx.referenceNo ? tx.referenceNo : `${new Date(tx.date).toISOString().split('T')[0]}_${tx.amount}_${tx.description.slice(0, 30)}`;
                return !existingKeys.has(key);
            });

            existingStatement.transactions.push(...newUniqueTxs);
        }

        existingStatement.bankName = bankName;
        existingStatement.statementTitle = statementTitle || existingStatement.statementTitle;
        existingStatement.fileName = fileName || existingStatement.fileName;
        if (pdfPassword) {
            existingStatement.pdfPassword = pdfPassword;
            existingStatement.isPasswordProtected = true;
        }

        await existingStatement.save();
        return res.json(existingStatement);
    }

    // Otherwise create fresh statement record
    const statement = await BankStatement.create({
        clientUser: targetUserId,
        bankName,
        accountNumber,
        statementTitle: statementTitle || `${bankName} Statement`,
        fileName: fileName || '',
        fileUrl: fileUrl || '',
        isPasswordProtected: Boolean(isPasswordProtected || pdfPassword),
        pdfPassword: pdfPassword || '',
        transactions: formattedTxs
    });

    res.status(201).json(statement);
});

// @desc    Delete a bank statement & all its transactions
// @route   DELETE /api/accounting/bank-statements/:id
export const deleteBankStatement = asyncHandler(async (req, res) => {
    const statement = await BankStatement.findById(req.params.id);
    if (!statement) {
        res.status(404);
        throw new Error('Bank statement not found');
    }

    if (statement.clientUser.toString() !== req.user._id.toString() && req.user.role !== 'admin' && req.user.role !== 'employee') {
        res.status(401);
        throw new Error('Not authorized to delete this statement');
    }

    await statement.deleteOne();
    res.json({ message: 'Bank statement and all transactions removed successfully' });
});

// @desc    Delete all bank statements for user
// @route   DELETE /api/accounting/bank-statements
export const deleteAllBankStatements = asyncHandler(async (req, res) => {
    const { clientId } = req.query;
    let targetUserId = req.user._id;
    if (clientId && (req.user.role === 'admin' || req.user.role === 'employee')) {
        targetUserId = clientId;
    }

    await BankStatement.deleteMany({ clientUser: targetUserId });
    res.json({ message: 'All bank statements and transaction ledgers removed' });
});

// @desc    Clear all transactions in a specific bank statement
// @route   POST /api/accounting/bank-statements/:id/clear
export const clearBankStatementTransactions = asyncHandler(async (req, res) => {
    const statement = await BankStatement.findById(req.params.id);
    if (!statement) {
        res.status(404);
        throw new Error('Bank statement not found');
    }

    statement.transactions = [];
    await statement.save();
    res.json({ message: 'All transactions cleared from statement', statement });
});

// @desc    Manually tag a bank transaction line to an Invoice/Bill or Category
// @route   POST /api/accounting/bank-statements/:id/tag
export const tagBankTransaction = asyncHandler(async (req, res) => {
    const { statementId, lineId, taggedVoucherId, taggedCategory, notes, status } = req.body;
    
    const statement = await BankStatement.findById(req.params.id || statementId);
    if (!statement) {
        res.status(404);
        throw new Error('Bank statement not found');
    }

    const line = statement.transactions.id(lineId);
    if (!line) {
        res.status(404);
        throw new Error('Transaction line not found in statement');
    }

    line.reconciliationStatus = status || 'TAGGED';
    line.taggedCategory = taggedCategory || '';
    line.notes = notes || '';

    // Safely assign taggedVoucher only if valid 24-char ObjectId
    if (taggedVoucherId && mongoose.Types.ObjectId.isValid(taggedVoucherId)) {
        line.taggedVoucher = new mongoose.Types.ObjectId(taggedVoucherId);
        
        // If tagged to a voucher, mark the voucher payment status
        const voucher = await Transaction.findById(taggedVoucherId);
        if (voucher) {
            const totalAmount = Number(voucher.summary?.totalAmount || voucher.totalAmount || 0);
            const newPaidAmount = Math.min(totalAmount, (Number(voucher.paidAmount) || 0) + Number(line.amount || 0));
            const newPaymentStatus = (totalAmount > 0 && newPaidAmount >= totalAmount) ? 'Paid' : 'Partially Paid';
            
            await Transaction.findByIdAndUpdate(taggedVoucherId, {
                paidAmount: newPaidAmount,
                paymentStatus: newPaymentStatus
            });
        }
    } else {
        line.taggedVoucher = undefined;
    }

    await statement.save();
    res.json({ message: 'Transaction line updated successfully', statement });
});

// ==================== PAYROLL & FORM 16 ====================

// @desc    Get payroll registers
// @route   GET /api/accounting/payroll
export const getPayrollRecords = asyncHandler(async (req, res) => {
    const { clientId, month, financialYear } = req.query;
    let targetUserId = req.user._id;
    if (clientId && (req.user.role === 'admin' || req.user.role === 'employee')) {
        targetUserId = clientId;
    }

    const query = { clientUser: targetUserId };
    if (month) query.month = month;
    if (financialYear) query.financialYear = financialYear;

    const records = await Payroll.find(query).sort({ createdAt: -1 });
    res.json(records);
});

// @desc    Add payroll entry
// @route   POST /api/accounting/payroll
export const createPayrollRecord = asyncHandler(async (req, res) => {
    const { clientId, financialYear, month, employeeName, employeePan, designation, taxRegime, basic, hra, allowances, grossSalary, pfEmployee, esiEmployee, professionalTax, tdsDeducted, status } = req.body;
    let targetUserId = req.user._id;
    if (clientId && (req.user.role === 'admin' || req.user.role === 'employee')) {
        targetUserId = clientId;
    }

    const gross = Number(grossSalary) || (Number(basic) + Number(hra) + Number(allowances));
    const totalDeductions = (Number(pfEmployee) || 0) + (Number(esiEmployee) || 0) + (Number(professionalTax) || 0) + (Number(tdsDeducted) || 0);
    const netPayable = gross - totalDeductions;

    const record = await Payroll.create({
        clientUser: targetUserId,
        financialYear: financialYear || '2025-2026',
        month,
        employeeName,
        employeePan,
        designation: designation || '',
        taxRegime: taxRegime || 'NEW',
        basic: Number(basic) || 0,
        hra: Number(hra) || 0,
        allowances: Number(allowances) || 0,
        grossSalary: gross,
        pfEmployee: Number(pfEmployee) || 0,
        esiEmployee: Number(esiEmployee) || 0,
        professionalTax: Number(professionalTax) || 0,
        tdsDeducted: Number(tdsDeducted) || 0,
        totalDeductions,
        netPayable,
        status: status || 'Processed'
    });

    res.status(201).json(record);
});

// ==================== STATUTORY & TALLY EXPORTS ====================

// @desc    Export Tally XML Vouchers
// @route   GET /api/accounting/export/tally
export const exportTallyVouchers = asyncHandler(async (req, res) => {
    const { startDate, endDate, clientId } = req.query;
    let targetUserId = req.user._id;
    if (clientId && (req.user.role === 'admin' || req.user.role === 'employee')) {
        targetUserId = clientId;
    }
    const query = { clientUser: targetUserId };
    if (startDate || endDate) {
        query.docDate = {};
        if (startDate) query.docDate.$gte = new Date(startDate);
        if (endDate) query.docDate.$lte = new Date(endDate);
    }

    const transactions = await Transaction.find(query).sort({ docDate: 1 });

    let xml = `<?xml version="1.0"?>\n<ENVELOPE>\n  <HEADER>\n    <TALLYREQUEST>Import Data</TALLYREQUEST>\n  </HEADER>\n  <BODY>\n    <IMPORTDATA>\n      <REQUESTDESC>\n        <REPORTNAME>Vouchers</REPORTNAME>\n      </REQUESTDESC>\n      <REQUESTDATA>\n`;

    transactions.forEach(t => {
        const dateStr = new Date(t.docDate).toISOString().slice(0, 10).replace(/-/g, '');
        const type = t.transactionType === 'Sales' ? 'Sales' : t.transactionType === 'Purchase' ? 'Purchase' : 'Journal';
        
        xml += `        <TALLYMESSAGE xmlns:UDF="TallyUDF">\n`;
        xml += `          <VOUCHER VCHTYPE="${type}" ACTION="Create">\n`;
        xml += `            <DATE>${dateStr}</DATE>\n`;
        xml += `            <VOUCHERNUMBER>${t.docNumber}</VOUCHERNUMBER>\n`;
        xml += `            <PARTYLEDGERNAME>${t.partyName}</PARTYLEDGERNAME>\n`;
        xml += `            <EFFECTIVEDATE>${dateStr}</EFFECTIVEDATE>\n`;
        
        if (t.transactionType === 'Sales') {
            xml += `            <ALLLEDGERENTRIES.LIST>\n`;
            xml += `              <LEDGERNAME>${t.partyName}</LEDGERNAME>\n`;
            xml += `              <ISDEEMEDPOSITIVE>Yes</ISDEEMEDPOSITIVE>\n`;
            xml += `              <AMOUNT>-${t.summary.totalAmount}</AMOUNT>\n`;
            xml += `            </ALLLEDGERENTRIES.LIST>\n`;
            xml += `            <ALLLEDGERENTRIES.LIST>\n`;
            xml += `              <LEDGERNAME>Sales Account</LEDGERNAME>\n`;
            xml += `              <ISDEEMEDPOSITIVE>No</ISDEEMEDPOSITIVE>\n`;
            xml += `              <AMOUNT>${t.summary.totalTaxableValue}</AMOUNT>\n`;
            xml += `            </ALLLEDGERENTRIES.LIST>\n`;
            if (t.summary.totalCgst > 0) {
                xml += `            <ALLLEDGERENTRIES.LIST>\n`;
                xml += `              <LEDGERNAME>Output CGST</LEDGERNAME>\n`;
                xml += `              <ISDEEMEDPOSITIVE>No</ISDEEMEDPOSITIVE>\n`;
                xml += `              <AMOUNT>${t.summary.totalCgst}</AMOUNT>\n`;
                xml += `            </ALLLEDGERENTRIES.LIST>\n`;
            }
            if (t.summary.totalSgst > 0) {
                xml += `            <ALLLEDGERENTRIES.LIST>\n`;
                xml += `              <LEDGERNAME>Output SGST</LEDGERNAME>\n`;
                xml += `              <ISDEEMEDPOSITIVE>No</ISDEEMEDPOSITIVE>\n`;
                xml += `              <AMOUNT>${t.summary.totalSgst}</AMOUNT>\n`;
                xml += `            </ALLLEDGERENTRIES.LIST>\n`;
            }
            if (t.summary.totalIgst > 0) {
                xml += `            <ALLLEDGERENTRIES.LIST>\n`;
                xml += `              <LEDGERNAME>Output IGST</LEDGERNAME>\n`;
                xml += `              <ISDEEMEDPOSITIVE>No</ISDEEMEDPOSITIVE>\n`;
                xml += `              <AMOUNT>${t.summary.totalIgst}</AMOUNT>\n`;
                xml += `            </ALLLEDGERENTRIES.LIST>\n`;
            }
        } else {
            xml += `            <ALLLEDGERENTRIES.LIST>\n`;
            xml += `              <LEDGERNAME>${t.partyName}</LEDGERNAME>\n`;
            xml += `              <ISDEEMEDPOSITIVE>No</ISDEEMEDPOSITIVE>\n`;
            xml += `              <AMOUNT>${t.summary.totalAmount}</AMOUNT>\n`;
            xml += `            </ALLLEDGERENTRIES.LIST>\n`;
            xml += `            <ALLLEDGERENTRIES.LIST>\n`;
            xml += `              <LEDGERNAME>Purchase Account</LEDGERNAME>\n`;
            xml += `              <ISDEEMEDPOSITIVE>Yes</ISDEEMEDPOSITIVE>\n`;
            xml += `              <AMOUNT>-${t.summary.totalTaxableValue}</AMOUNT>\n`;
            xml += `            </ALLLEDGERENTRIES.LIST>\n`;
            if (t.summary.totalCgst > 0) {
                xml += `            <ALLLEDGERENTRIES.LIST>\n`;
                xml += `              <LEDGERNAME>Input CGST</LEDGERNAME>\n`;
                xml += `              <ISDEEMEDPOSITIVE>Yes</ISDEEMEDPOSITIVE>\n`;
                xml += `              <AMOUNT>-${t.summary.totalCgst}</AMOUNT>\n`;
                xml += `            </ALLLEDGERENTRIES.LIST>\n`;
            }
            if (t.summary.totalSgst > 0) {
                xml += `            <ALLLEDGERENTRIES.LIST>\n`;
                xml += `              <LEDGERNAME>Input SGST</LEDGERNAME>\n`;
                xml += `              <ISDEEMEDPOSITIVE>Yes</ISDEEMEDPOSITIVE>\n`;
                xml += `              <AMOUNT>-${t.summary.totalSgst}</AMOUNT>\n`;
                xml += `            </ALLLEDGERENTRIES.LIST>\n`;
            }
            if (t.summary.totalIgst > 0) {
                xml += `            <ALLLEDGERENTRIES.LIST>\n`;
                xml += `              <LEDGERNAME>Input IGST</LEDGERNAME>\n`;
                xml += `              <ISDEEMEDPOSITIVE>Yes</ISDEEMEDPOSITIVE>\n`;
                xml += `              <AMOUNT>-${t.summary.totalIgst}</AMOUNT>\n`;
                xml += `            </ALLLEDGERENTRIES.LIST>\n`;
            }
        }

        xml += `          </VOUCHER>\n`;
        xml += `        </TALLYMESSAGE>\n`;
    });

    xml += `      </REQUESTDATA>\n    </IMPORTDATA>\n  </BODY>\n</ENVELOPE>`;
    
    res.setHeader('Content-Type', 'application/xml');
    res.setHeader('Content-Disposition', `attachment; filename=TallyVouchers_${targetUserId}.xml`);
    res.send(xml);
});

// @desc    Export GSTR-1 Offline Tool JSON Payload
// @route   GET /api/accounting/export/gstr1
export const exportGstr1Data = asyncHandler(async (req, res) => {
    const { startDate, endDate, clientId } = req.query;
    let targetUserId = req.user._id;
    if (clientId && (req.user.role === 'admin' || req.user.role === 'employee')) {
        targetUserId = clientId;
    }
    const query = { clientUser: targetUserId, transactionType: 'Sales' };
    if (startDate || endDate) {
        query.docDate = {};
        if (startDate) query.docDate.$gte = new Date(startDate);
        if (endDate) query.docDate.$lte = new Date(endDate);
    }

    const sales = await Transaction.find(query);
    const company = await CompanyDetails.findOne({ user: targetUserId });
    const gstinSender = company?.gstin || '';

    const b2b = [];
    const b2cs = [];
    const hsnSummary = {};

    sales.forEach(sale => {
        const invDateFormatted = new Date(sale.docDate).toLocaleDateString('en-GB').replace(/\//g, '-');
        
        sale.items.forEach(item => {
            const hsn = item.hsnSac || '9999';
            if (!hsnSummary[hsn]) {
                hsnSummary[hsn] = {
                    hsn_sc: hsn,
                    desc: item.description,
                    uqc: item.unit || 'OTH',
                    qty: 0,
                    val: 0,
                    txval: 0,
                    iamt: 0,
                    camt: 0,
                    samt: 0,
                    csamt: 0
                };
            }
            hsnSummary[hsn].qty += item.qty;
            hsnSummary[hsn].val += item.total;
            hsnSummary[hsn].txval += item.taxableValue;
            hsnSummary[hsn].iamt += item.igst;
            hsnSummary[hsn].camt += item.cgst;
            hsnSummary[hsn].samt += item.sgst;
        });

        if (sale.partyGstin && sale.partyGstin.trim().length === 15) {
            let partyGstr = b2b.find(p => p.ctin === sale.partyGstin);
            if (!partyGstr) {
                partyGstr = { ctin: sale.partyGstin, inv: [] };
                b2b.push(partyGstr);
            }

            partyGstr.inv.push({
                inum: sale.docNumber,
                idt: invDateFormatted,
                val: sale.summary.totalAmount,
                pos: sale.placeOfSupply.slice(0, 2),
                rchrg: 'N',
                inv_typ: 'R',
                itms: sale.items.map((item, idx) => ({
                    num: idx + 1,
                    itm_det: {
                        ty: 'G',
                        hsn_sc: item.hsnSac || '9999',
                        txval: item.taxableValue,
                        rt: item.gstRate,
                        iamt: item.igst,
                        camt: item.cgst,
                        samt: item.sgst,
                        csamt: 0
                    }
                }))
            });
        } else {
            sale.items.forEach(item => {
                const posCode = sale.placeOfSupply.slice(0, 2);
                let csItem = b2cs.find(c => c.pos === posCode && c.rt === item.gstRate);
                if (!csItem) {
                    csItem = {
                        pos: posCode,
                        rt: item.gstRate,
                        txval: 0,
                        iamt: 0,
                        camt: 0,
                        samt: 0,
                        csamt: 0,
                        sply_ty: posCode === gstinSender.slice(0, 2) ? 'INTRA' : 'INTER'
                    };
                    b2cs.push(csItem);
                }
                csItem.txval += item.taxableValue;
                csItem.iamt += item.igst;
                csItem.camt += item.cgst;
                csItem.samt += item.sgst;
            });
        }
    });

    const gstr1Payload = {
        gstin: gstinSender,
        fp: new Date().toLocaleDateString('en-GB', { month: '2-digit', year: '2-digit' }).replace('/', ''),
        gt: 0.0,
        cur_gt: 0.0,
        b2b,
        b2cs,
        hsn: {
            data: Object.values(hsnSummary)
        }
    };

    res.json(gstr1Payload);
});

// @desc    Export GSTR-3B Computation Summary
// @route   GET /api/accounting/export/gstr3b
export const exportGstr3bData = asyncHandler(async (req, res) => {
    const { startDate, endDate, clientId } = req.query;
    let targetUserId = req.user._id;
    if (clientId && (req.user.role === 'admin' || req.user.role === 'employee')) {
        targetUserId = clientId;
    }
    const query = { clientUser: targetUserId };
    if (startDate || endDate) {
        query.docDate = {};
        if (startDate) query.docDate.$gte = new Date(startDate);
        if (endDate) query.docDate.$lte = new Date(endDate);
    }

    const [sales, purchases] = await Promise.all([
        Transaction.find({ ...query, transactionType: 'Sales' }),
        Transaction.find({ ...query, transactionType: 'Purchase' })
    ]);

    // Outward supplies (Table 3.1)
    let outwardTaxable = 0, outwardCgst = 0, outwardSgst = 0, outwardIgst = 0;
    sales.forEach(s => {
        outwardTaxable += s.summary.totalTaxableValue;
        outwardCgst += s.summary.totalCgst;
        outwardSgst += s.summary.totalSgst;
        outwardIgst += s.summary.totalIgst;
    });

    // Inward eligible ITC (Table 4)
    let itcTaxable = 0, itcCgst = 0, itcSgst = 0, itcIgst = 0;
    purchases.forEach(p => {
        if (p.itcEligibility !== 'Ineligible') {
            itcTaxable += p.summary.totalTaxableValue;
            itcCgst += p.summary.totalCgst;
            itcSgst += p.summary.totalSgst;
            itcIgst += p.summary.totalIgst;
        }
    });

    const gstr3bSummary = {
        table3_1: {
            outwardTaxableSupplies: {
                taxableValue: Math.round(outwardTaxable * 100) / 100,
                igst: Math.round(outwardIgst * 100) / 100,
                cgst: Math.round(outwardCgst * 100) / 100,
                sgst: Math.round(outwardSgst * 100) / 100,
                cess: 0
            }
        },
        table4: {
            eligibleItc: {
                taxableValue: Math.round(itcTaxable * 100) / 100,
                igst: Math.round(itcIgst * 100) / 100,
                cgst: Math.round(itcCgst * 100) / 100,
                sgst: Math.round(itcSgst * 100) / 100,
                cess: 0
            }
        },
        netPayable: {
            igst: Math.max(0, Math.round((outwardIgst - itcIgst) * 100) / 100),
            cgst: Math.max(0, Math.round((outwardCgst - itcCgst) * 100) / 100),
            sgst: Math.max(0, Math.round((outwardSgst - itcSgst) * 100) / 100)
        }
    };

    res.json(gstr3bSummary);
});
