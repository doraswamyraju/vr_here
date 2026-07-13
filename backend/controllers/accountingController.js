import asyncHandler from 'express-async-handler';
import Transaction from '../models/Transaction.js';
import CompanyDetails from '../models/CompanyDetails.js';

// @desc    Create a new transaction
// @route   POST /api/accounting/transactions
// @access  Private
export const createTransaction = asyncHandler(async (req, res) => {
    const {
        transactionType,
        docNumber,
        docDate,
        partyName,
        partyGstin,
        placeOfSupply,
        items,
        itcEligibility,
        notes,
        attachmentUrl
    } = req.body;

    if (!transactionType || !docNumber || !docDate || !partyName || !placeOfSupply || !items || items.length === 0) {
        res.status(400);
        throw new Error('Please fill in all required fields and add at least one item');
    }

    // Calculate totals and GST
    let totalTaxableValue = 0;
    let totalCgst = 0;
    let totalSgst = 0;
    let totalIgst = 0;

    const processedItems = items.map(item => {
        const taxableValue = item.qty * item.rate;
        let cgst = 0;
        let sgst = 0;
        let igst = 0;

        // Simplified logic: If POS matches our state, apply CGST+SGST, else IGST.
        // POS usually begins with state code or is compared.
        // We'll compare client's POS to the supplied placeOfSupply.
        // For simplicity, if we detect it's interstate (e.g. via partyGstin comparison or POS name comparison), apply IGST.
        // Let's assume the client state is fetched or we just check if POS is inter-state based on request input.
        const isInterstate = req.body.isInterstate || false;

        if (item.gstRate && item.gstRate > 0) {
            if (isInterstate) {
                igst = Math.round((taxableValue * (item.gstRate / 100)) * 100) / 100;
            } else {
                cgst = Math.round((taxableValue * ((item.gstRate / 2) / 100)) * 100) / 100;
                sgst = cgst;
            }
        }

        const amount = taxableValue + cgst + sgst + igst;
        totalTaxableValue += taxableValue;
        totalCgst += cgst;
        totalSgst += sgst;
        totalIgst += igst;

        return {
            ...item,
            taxableValue,
            cgst,
            sgst,
            igst,
            amount
        };
    });

    const summary = {
        totalTaxableValue,
        totalCgst,
        totalSgst,
        totalIgst,
        totalAmount: totalTaxableValue + totalCgst + totalSgst + totalIgst
    };

    const transaction = await Transaction.create({
        clientUser: req.user._id,
        transactionType,
        docNumber,
        docDate,
        partyName,
        partyGstin,
        placeOfSupply,
        items: processedItems,
        summary,
        itcEligibility: itcEligibility || 'N/A',
        notes,
        attachmentUrl,
        createdBy: req.user._id
    });

    res.status(201).json(transaction);
});

// @desc    Get all transactions for the logged in client
// @route   GET /api/accounting/transactions
// @access  Private
export const getTransactions = asyncHandler(async (req, res) => {
    const { type, status, startDate, endDate, clientId } = req.query;

    let targetUserId = req.user._id;
    if (clientId && (req.user.role === 'admin' || req.user.role === 'employee')) {
        targetUserId = clientId;
    }

    const query = { clientUser: targetUserId };

    if (type) query.transactionType = type;
    if (status) query.status = status;
    if (startDate || endDate) {
        query.docDate = {};
        if (startDate) query.docDate.$gte = new Date(startDate);
        if (endDate) query.docDate.$lte = new Date(endDate);
    }

    const transactions = await Transaction.find(query).sort({ docDate: -1 });
    res.json(transactions);
});

// @desc    Update a transaction
// @route   PUT /api/accounting/transactions/:id
// @access  Private
export const updateTransaction = asyncHandler(async (req, res) => {
    const transaction = await Transaction.findById(req.params.id);

    if (!transaction) {
        res.status(404);
        throw new Error('Transaction not found');
    }

    // Check ownership (client or assigned employee/admin)
    if (transaction.clientUser.toString() !== req.user._id.toString() && req.user.role !== 'admin' && req.user.role !== 'employee') {
        res.status(401);
        throw new Error('Not authorized to edit this transaction');
    }

    // Update fields allowed
    const updates = req.body;
    
    // If updating items, re-calculate totals
    if (updates.items) {
        let totalTaxableValue = 0;
        let totalCgst = 0;
        let totalSgst = 0;
        let totalIgst = 0;
        const isInterstate = req.body.isInterstate || false;

        updates.items = updates.items.map(item => {
            const taxableValue = item.qty * item.rate;
            let cgst = 0;
            let sgst = 0;
            let igst = 0;

            if (item.gstRate && item.gstRate > 0) {
                if (isInterstate) {
                    igst = Math.round((taxableValue * (item.gstRate / 100)) * 100) / 100;
                } else {
                    cgst = Math.round((taxableValue * ((item.gstRate / 2) / 100)) * 100) / 100;
                    sgst = cgst;
                }
            }

            const amount = taxableValue + cgst + sgst + igst;
            totalTaxableValue += taxableValue;
            totalCgst += cgst;
            totalSgst += sgst;
            totalIgst += igst;

            return {
                ...item,
                taxableValue,
                cgst,
                sgst,
                igst,
                amount
            };
        });

        updates.summary = {
            totalTaxableValue,
            totalCgst,
            totalSgst,
            totalIgst,
            totalAmount: totalTaxableValue + totalCgst + totalSgst + totalIgst
        };
    }

    Object.assign(transaction, updates);
    const updatedTransaction = await transaction.save();
    res.json(updatedTransaction);
});

// @desc    Delete a transaction
// @route   DELETE /api/accounting/transactions/:id
// @access  Private
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
    res.json({ message: 'Transaction removed' });
});

// @desc    Get client company configuration
// @route   GET /api/accounting/company
// @access  Private
export const getCompanyDetails = asyncHandler(async (req, res) => {
    const company = await CompanyDetails.findOne({ user: req.user._id });
    if (!company) {
        res.status(404);
        throw new Error('Company details not configured yet');
    }
    res.json(company);
});

// @desc    Create or update company configuration
// @route   POST /api/accounting/company
// @access  Private
export const upsertCompanyDetails = asyncHandler(async (req, res) => {
    const { 
        companyName, tradeName, gstin, address, state, bankDetails,
        phone, email, businessType, businessCategory, pincode,
        logo, signature, upiId, qrCode
    } = req.body;

    let company = await CompanyDetails.findOne({ user: req.user._id });

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
            user: req.user._id,
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

// @desc    Export Tally XML Vouchers
// @route   GET /api/accounting/export/tally
// @access  Private
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

    const transactions = await Transaction.find(query);

    // Simple Tally XML Generator
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
        
        // Items & Ledgers detail mappings
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
            // Purchase/Expense
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
    res.setHeader('Content-Disposition', `attachment; filename=TallyVouchers_${req.user._id}.xml`);
    res.send(xml);
});

// @desc    Export GSTR-1 Offline Tool JSON Payload
// @route   GET /api/accounting/export/gstr1
// @access  Private
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

    // GSTR-1 structure
    const b2b = [];
    const b2cs = [];
    const hsnSummary = {};

    sales.forEach(sale => {
        const invDateFormatted = new Date(sale.docDate).toLocaleDateString('en-GB').replace(/\//g, '-'); // DD-MM-YYYY
        
        // HSN Summary aggregation
        sale.items.forEach(item => {
            const hsn = item.hsnSac || '9999';
            if (!hsnSummary[hsn]) {
                hsnSummary[hsn] = {
                    hsn_sc: hsn,
                    desc: item.description,
                    uqc: 'OTH',
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
            hsnSummary[hsn].val += item.amount;
            hsnSummary[hsn].txval += item.taxableValue;
            hsnSummary[hsn].iamt += item.igst;
            hsnSummary[hsn].camt += item.cgst;
            hsnSummary[hsn].samt += item.sgst;
        });

        if (sale.partyGstin && sale.partyGstin.trim().length === 15) {
            // B2B Invoice
            let partyGstr = b2b.find(p => p.ctin === sale.partyGstin);
            if (!partyGstr) {
                partyGstr = { ctin: sale.partyGstin, inv: [] };
                b2b.push(partyGstr);
            }

            partyGstr.inv.push({
                inum: sale.docNumber,
                idt: invDateFormatted,
                val: sale.summary.totalAmount,
                pos: sale.placeOfSupply.slice(0, 2), // first 2 chars of POS is state code
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
            // B2CS (Consolidated unregistered sales)
            // Group by POS and Tax rate
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
        fp: new Date().toLocaleDateString('en-GB', { month: '2-digit', year: '2-digit' }).replace('/', ''), // MMYYYY
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
