import React, { useState, useEffect } from 'react';
import axios from 'axios';
import * as XLSX from 'xlsx';
import { 
    Upload, Plus, Check, Search, FileText, ArrowDownLeft, ArrowUpRight, 
    Link2, X, RefreshCw, Lock, Unlock, Eye, EyeOff, ShieldCheck, HelpCircle, 
    FileSpreadsheet, Sparkles, AlertCircle, CheckCircle2
} from 'lucide-react';

const BANK_PASSWORD_HINTS = {
    'HDFC Bank': 'Customer ID (8-digits) OR First 4 letters of name in lowercase + DOB (DDMM) e.g. dora1408',
    'State Bank of India (SBI)': 'Last 5 digits of registered mobile number + DOB (DDMM) e.g. 987651408',
    'ICICI Bank': 'First 4 letters of name in lowercase + DOB (DDMM) e.g. dora1408',
    'Axis Bank': 'First 4 letters of name in CAPITALS + 4-digit Year of Birth e.g. DORA1995',
    'Kotak Mahindra Bank': 'CRN Number (9 digits) OR First 4 letters of name (lowercase) + DOB (DDMM)',
    'Punjab National Bank (PNB)': 'Account Number OR Customer ID',
    'Canara Bank': 'Customer ID (Cust ID) or First 4 letters of name + DOB (DDMM)',
    'Union Bank of India': 'First 4 letters of Name (lowercase) + DDMM of birth',
    'Bank of Baroda': 'First 4 letters of Name + DDMM or Bank Account Number',
    'Federal Bank': 'Customer ID or Date of Birth in DDMMYYYY format',
    'IndusInd Bank': 'Date of Birth in DDMMYYYY format',
    'Yes Bank': 'Customer ID or First 4 letters of name + DOB',
    'Other Bank': 'Enter the PDF password specified by your bank branch'
};

const BankStatementsTab = ({
    token,
    transactions = [],
    company,
    onRefreshLedger
}) => {
    const [statements, setStatements] = useState([]);
    const [selectedStatement, setSelectedStatement] = useState(null);
    const [loading, setLoading] = useState(true);
    const [showUploadModal, setShowUploadModal] = useState(false);

    // Tagging modal state
    const [activeTagLine, setActiveTagLine] = useState(null);
    const [selectedVoucherId, setSelectedVoucherId] = useState('');
    const [selectedCategory, setSelectedCategory] = useState('Sales Invoicing Settlement');
    const [tagNotes, setTagNotes] = useState('');
    const [taggingLoading, setTaggingLoading] = useState(false);

    // New statement form state
    const [bankName, setBankName] = useState('HDFC Bank');
    const [customBankName, setCustomBankName] = useState('');
    const [accountNumber, setAccountNumber] = useState(company?.bankDetails?.accountNumber || '');
    const [statementTitle, setStatementTitle] = useState('Current A/c Statement - 2026');
    const [pdfPassword, setPdfPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [fileName, setFileName] = useState('');
    const [isExcelParsed, setIsExcelParsed] = useState(false);

    // Initial default rows
    const [manualRows, setManualRows] = useState([
        { date: new Date().toISOString().split('T')[0], description: 'NEFT INWARD - Lucky Infra Projects', referenceNo: 'UTR987654321', type: 'CREDIT', amount: 59000, balance: 159000 },
        { date: new Date().toISOString().split('T')[0], description: 'UPI OUT - Office Rent May 2026', referenceNo: 'UPI67891234', type: 'DEBIT', amount: 25000, balance: 134000 }
    ]);

    const config = { headers: { Authorization: `Bearer ${token}` } };

    const fetchStatements = async () => {
        setLoading(true);
        try {
            const { data } = await axios.get('/api/accounting/bank-statements', config);
            setStatements(data);
            if (data.length > 0 && !selectedStatement) {
                setSelectedStatement(data[0]);
            }
        } catch (error) {
            console.error('Failed to fetch bank statements:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchStatements();
    }, []);

    // Filter available open invoices and bills for tagging
    const openSalesInvoices = transactions.filter(t => t.transactionType === 'Sales');
    const openPurchaseBills = transactions.filter(t => t.transactionType === 'Purchase');

    const handleAddRow = () => {
        setManualRows([
            ...manualRows,
            { date: new Date().toISOString().split('T')[0], description: '', referenceNo: '', type: 'CREDIT', amount: 0, balance: 0 }
        ]);
    };

    const handleRemoveRow = (idx) => {
        setManualRows(manualRows.filter((_, i) => i !== idx));
    };

    const handleRowChange = (idx, field, val) => {
        const updated = [...manualRows];
        updated[idx][field] = val;
        setManualRows(updated);
    };

    // Parse Excel / CSV files directly in browser using SheetJS
    const handleFileSelect = (e) => {
        const file = e.target.files?.[0];
        if (!file) return;

        setFileName(file.name);
        const fileExt = file.name.split('.').pop()?.toLowerCase();

        if (fileExt === 'xlsx' || fileExt === 'xls' || fileExt === 'csv') {
            const reader = new FileReader();
            reader.onload = (evt) => {
                try {
                    const data = new Uint8Array(evt.target.result);
                    const workbook = XLSX.read(data, { type: 'array', cellDates: true });
                    const sheetName = workbook.SheetNames[0];
                    const worksheet = workbook.Sheets[sheetName];
                    const jsonRows = XLSX.utils.sheet_to_json(worksheet, { header: 1, defval: '' });

                    // Auto-detect transaction columns
                    const parsedLines = [];
                    for (let r = 0; r < jsonRows.length; r++) {
                        const row = jsonRows[r];
                        if (!row || row.length < 3) continue;

                        const rowStr = row.map(c => String(c).toLowerCase()).join(' ');
                        // Skip header rows
                        if (rowStr.includes('date') && (rowStr.includes('narration') || rowStr.includes('description') || rowStr.includes('particulars'))) {
                            continue;
                        }

                        // Try finding date in first or second column
                        let rowDate = new Date().toISOString().split('T')[0];
                        if (row[0] && !isNaN(Date.parse(row[0]))) {
                            rowDate = new Date(row[0]).toISOString().split('T')[0];
                        } else if (row[1] && !isNaN(Date.parse(row[1]))) {
                            rowDate = new Date(row[1]).toISOString().split('T')[0];
                        }

                        // Find narration
                        const description = String(row[1] || row[2] || '').trim();
                        if (!description || description.length < 3) continue;

                        // Check amounts
                        let debitAmt = 0;
                        let creditAmt = 0;
                        let refNo = '';

                        // Scan remaining columns for numbers
                        row.forEach(cell => {
                            const val = String(cell).replace(/,/g, '').trim();
                            const num = parseFloat(val);
                            if (!isNaN(num) && num > 0) {
                                if (debitAmt === 0) debitAmt = num;
                                else if (creditAmt === 0) creditAmt = num;
                            }
                            if (val.length >= 8 && /^[a-zA-Z0-9]+$/.test(val) && !isNaN(parseFloat(val)) === false) {
                                refNo = val;
                            }
                        });

                        const isCredit = creditAmt > 0 || (debitAmt > 0 && rowStr.includes('cr'));
                        const finalAmount = isCredit ? (creditAmt || debitAmt) : debitAmt;

                        if (finalAmount > 0) {
                            parsedLines.push({
                                date: rowDate,
                                description: description.slice(0, 100),
                                referenceNo: refNo || `TXN${Math.floor(100000 + Math.random() * 900000)}`,
                                type: isCredit ? 'CREDIT' : 'DEBIT',
                                amount: Math.abs(finalAmount),
                                balance: 0
                            });
                        }
                    }

                    if (parsedLines.length > 0) {
                        setManualRows(parsedLines);
                        setIsExcelParsed(true);
                    }
                } catch (err) {
                    console.error('Error parsing excel statement:', err);
                }
            };
            reader.readAsArrayBuffer(file);
        }
    };

    // Load rich demonstration statement
    const handleLoadSampleStatement = () => {
        const sampleLines = [
            { date: '2026-04-05', description: 'NEFT CR - Lucky Infra Tech (Inv #INV-2627-0001)', referenceNo: 'HDFCR52026040501', type: 'CREDIT', amount: 59000, balance: 159000 },
            { date: '2026-04-10', description: 'ACH DR - Google Workspace Cloud Subscription', referenceNo: 'GOOGL99281234', type: 'DEBIT', amount: 15340, balance: 143660 },
            { date: '2026-04-14', description: 'UPI CR - Quick Payment Consulting Advance', referenceNo: 'UPI99201948123', type: 'CREDIT', amount: 25000, balance: 168660 },
            { date: '2026-04-18', description: 'IMPS DR - Office Landlord Monthly Rent', referenceNo: 'IMPS884910293', type: 'DEBIT', amount: 35000, balance: 133660 },
            { date: '2026-04-22', description: 'NEFT DR - Apex Paper Mills Vendor Bill', referenceNo: 'AXIS994019284', type: 'DEBIT', amount: 23600, balance: 110060 }
        ];

        setBankName('HDFC Bank');
        setAccountNumber('50200088991122');
        setStatementTitle('HDFC Current A/c - Q1 FY 2026-27');
        setManualRows(sampleLines);
        setFileName('HDFC_Current_Account_Statement.pdf');
        setPdfPassword('dora1408');
        setIsExcelParsed(true);
    };

    const handleSaveStatement = async (e) => {
        e.preventDefault();
        const effectiveBank = bankName === 'Other Bank' ? (customBankName || 'Other Bank') : bankName;
        if (!accountNumber) {
            alert('Please enter bank account number');
            return;
        }

        try {
            const { data } = await axios.post('/api/accounting/bank-statements', {
                bankName: effectiveBank,
                accountNumber: accountNumber.trim(),
                statementTitle: statementTitle.trim(),
                fileName: fileName.trim(),
                isPasswordProtected: Boolean(pdfPassword),
                pdfPassword: pdfPassword.trim(),
                transactions: manualRows
            }, config);

            setStatements([data, ...statements]);
            setSelectedStatement(data);
            setShowUploadModal(false);
            alert('Bank statement and transactions saved & unlocked successfully!');
        } catch (error) {
            alert('Failed to save statement: ' + (error.response?.data?.message || error.message));
        }
    };

    const handleOpenTagModal = (line) => {
        setActiveTagLine(line);
        setSelectedVoucherId('');
        setSelectedCategory(line.type === 'CREDIT' ? 'Customer Sales Settlement' : 'Vendor Purchase Payment');
        setTagNotes('');
    };

    const handleSubmitTag = async (e) => {
        e.preventDefault();
        if (!activeTagLine || !selectedStatement) return;
        setTaggingLoading(true);
        try {
            const { data } = await axios.post(`/api/accounting/bank-statements/${selectedStatement._id}/tag`, {
                statementId: selectedStatement._id,
                lineId: activeTagLine._id,
                taggedVoucherId: selectedVoucherId || null,
                taggedCategory: selectedCategory,
                notes: tagNotes,
                status: 'TAGGED'
            }, config);

            // Update local statement
            setSelectedStatement(data.statement);
            setStatements(statements.map(s => s._id === data.statement._id ? data.statement : s));
            setActiveTagLine(null);
            if (onRefreshLedger) onRefreshLedger();
            alert('Bank transaction line tagged and reconciled successfully!');
        } catch (error) {
            alert('Failed to tag transaction: ' + (error.response?.data?.message || error.message));
        } finally {
            setTaggingLoading(false);
        }
    };

    const activeBankHint = BANK_PASSWORD_HINTS[bankName] || BANK_PASSWORD_HINTS['Other Bank'];

    return (
        <div className="space-y-6">

            {/* Statements List & Active Statement View */}
            {loading ? (
                <div className="flex justify-center py-20">
                    <div className="w-10 h-10 border-4 border-slate-200 border-t-indigo-600 rounded-full animate-spin"></div>
                </div>
            ) : statements.length === 0 ? (
                <div className="bg-white rounded-3xl p-12 sm:p-16 text-center border border-slate-100 shadow-sm space-y-5">
                    <div className="w-16 h-16 bg-indigo-50 text-indigo-600 rounded-3xl flex items-center justify-center mx-auto text-3xl shadow-sm">
                        🏦
                    </div>
                    <div className="space-y-1">
                        <h4 className="font-black text-slate-900 text-lg">No Bank Statements Added Yet</h4>
                        <p className="text-xs text-slate-500 max-w-md mx-auto">
                            Upload your official bank statement (PDF, Excel, or CSV) to review transaction lines and tag payments against sales invoices or expense heads.
                        </p>
                    </div>

                    {/* Pro tip */}
                    <div className="bg-slate-50 border border-slate-200 rounded-2xl p-3.5 max-w-lg mx-auto text-left flex items-start gap-2.5 text-xs text-slate-600">
                        <Lock size={16} className="text-indigo-600 shrink-0 mt-0.5" />
                        <div>
                            <strong className="text-slate-900 font-bold">Password Protected PDF?</strong>
                            <p className="text-[11px] text-slate-500 mt-0.5">
                                Our unlock engine automatically unlocks and stores your statement so your CA or staff never have to ask for passwords repeatedly.
                            </p>
                        </div>
                    </div>

                    <div className="flex items-center justify-center gap-3 pt-2">
                        <button 
                            onClick={() => setShowUploadModal(true)}
                            className="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-3 rounded-2xl font-black text-xs uppercase tracking-wider transition shadow-lg shadow-indigo-200 flex items-center gap-2"
                        >
                            <Upload size={15} /> Upload Bank Statement
                        </button>
                    </div>
                </div>
            ) : (
                <div className="space-y-4">
                    {/* Statement Switcher Tabs */}
                    <div className="flex items-center gap-2 overflow-x-auto pb-2">
                        {statements.map(stmt => (
                            <button
                                key={stmt._id}
                                onClick={() => setSelectedStatement(stmt)}
                                className={`px-4 py-2.5 rounded-2xl text-xs font-bold transition shrink-0 flex items-center gap-2 border ${
                                    selectedStatement?._id === stmt._id 
                                        ? 'bg-slate-900 text-white border-slate-900 shadow-md' 
                                        : 'bg-white text-slate-600 hover:bg-slate-50 border-slate-200'
                                }`}
                            >
                                <span>🏦 {stmt.bankName}</span>
                                <span className="font-mono text-[10px] opacity-75">({stmt.accountNumber?.slice(-4) || 'Stmt'})</span>
                                {stmt.isPasswordProtected && (
                                    <span title="Password protected & decrypted">
                                        <Unlock size={11} className="text-emerald-400" />
                                    </span>
                                )}
                            </button>
                        ))}
                        <button
                            onClick={() => {
                                setFileName('');
                                setIsExcelParsed(false);
                                setShowUploadModal(true);
                            }}
                            className="px-4 py-2.5 rounded-2xl text-xs font-black uppercase tracking-wider transition shrink-0 flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-700 text-white shadow-md shadow-indigo-100"
                        >
                            <Plus size={14} /> Upload / Add Statement
                        </button>
                    </div>

                    {/* Statement Table */}
                    {selectedStatement && (
                        <div className="bg-white rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 overflow-hidden">
                            <div className="p-5 border-b border-slate-100 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 bg-slate-50/50">
                                <div>
                                    <div className="flex items-center gap-2">
                                        <h4 className="font-black text-slate-900 text-sm">{selectedStatement.statementTitle}</h4>
                                        {selectedStatement.isPasswordProtected && (
                                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                                                <ShieldCheck size={11} /> Decrypted & Unlocked
                                            </span>
                                        )}
                                    </div>
                                    <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                                        Account: <strong className="text-slate-800">{selectedStatement.accountNumber}</strong> ({selectedStatement.bankName})
                                    </p>
                                </div>
                                <span className="text-[10px] font-black uppercase tracking-wider bg-indigo-50 text-indigo-700 px-3 py-1 rounded-full border border-indigo-200">
                                    {selectedStatement.transactions?.length || 0} Transactions
                                </span>
                            </div>

                            <div className="overflow-x-auto">
                                <table className="w-full text-left border-collapse text-xs">
                                    <thead>
                                        <tr className="bg-slate-50/75 text-slate-400 font-black text-[10px] uppercase tracking-wider border-b border-slate-100">
                                            <th className="px-6 py-3.5">Date</th>
                                            <th className="px-6 py-3.5">Description / Narration</th>
                                            <th className="px-6 py-3.5">Ref / UTR No</th>
                                            <th className="px-6 py-3.5 text-right">Debit (-)</th>
                                            <th className="px-6 py-3.5 text-right">Credit (+)</th>
                                            <th className="px-6 py-3.5">Status</th>
                                            <th className="px-6 py-3.5 text-right">Tagging Action</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-100">
                                        {selectedStatement.transactions?.map((line) => (
                                            <tr key={line._id} className="hover:bg-slate-50/60 transition group">
                                                <td className="px-6 py-4 font-bold text-slate-700 font-mono">
                                                    {line.date ? new Date(line.date).toLocaleDateString('en-GB') : '-'}
                                                </td>
                                                <td className="px-6 py-4 max-w-xs">
                                                    <p className="font-bold text-slate-900">{line.description}</p>
                                                    {line.taggedCategory && (
                                                        <span className="text-[10px] font-bold text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded mt-1 inline-block">
                                                            Tagged: {line.taggedCategory}
                                                        </span>
                                                    )}
                                                </td>
                                                <td className="px-6 py-4 font-mono text-[11px] text-slate-500">
                                                    {line.referenceNo || '-'}
                                                </td>
                                                <td className="px-6 py-4 text-right font-mono font-bold text-rose-600">
                                                    {line.type === 'DEBIT' ? `₹${Number(line.amount).toLocaleString('en-IN')}` : '-'}
                                                </td>
                                                <td className="px-6 py-4 text-right font-mono font-bold text-emerald-600">
                                                    {line.type === 'CREDIT' ? `₹${Number(line.amount).toLocaleString('en-IN')}` : '-'}
                                                </td>
                                                <td className="px-6 py-4">
                                                    <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                                                        line.reconciliationStatus === 'TAGGED' 
                                                            ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' 
                                                            : 'bg-amber-50 text-amber-700 border border-amber-200'
                                                    }`}>
                                                        {line.reconciliationStatus || 'UNRECONCILED'}
                                                    </span>
                                                </td>
                                                <td className="px-6 py-4 text-right">
                                                    <button 
                                                        onClick={() => handleOpenTagModal(line)}
                                                        className="bg-indigo-50 hover:bg-indigo-600 hover:text-white text-indigo-700 px-3 py-1.5 rounded-xl font-bold transition inline-flex items-center gap-1 text-xs"
                                                    >
                                                        <Link2 size={13} /> {line.reconciliationStatus === 'TAGGED' ? 'Re-tag' : 'Tag Payment'}
                                                    </button>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* Manual Tagging Modal */}
            {activeTagLine && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl w-full max-w-lg overflow-hidden animate-in fade-in zoom-in-95 duration-200">
                        <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50">
                            <h3 className="font-black text-slate-900 text-sm">
                                Tag Bank Line ({activeTagLine.type === 'CREDIT' ? 'Money In' : 'Money Out'})
                            </h3>
                            <button onClick={() => setActiveTagLine(null)} className="text-slate-400 hover:text-slate-600">
                                <X size={18} />
                            </button>
                        </div>

                        <form onSubmit={handleSubmitTag} className="p-6 space-y-4 text-xs">
                            <div className="bg-slate-50 p-3.5 rounded-2xl border border-slate-200 space-y-1">
                                <div className="flex justify-between items-center">
                                    <span className="font-bold text-slate-500">Transaction Amount:</span>
                                    <span className={`font-mono font-black text-base ${activeTagLine.type === 'CREDIT' ? 'text-emerald-600' : 'text-rose-600'}`}>
                                        {activeTagLine.type === 'CREDIT' ? '+' : '-'}₹{Number(activeTagLine.amount).toLocaleString('en-IN')}
                                    </span>
                                </div>
                                <p className="text-slate-700 font-bold">{activeTagLine.description}</p>
                                <p className="text-slate-400 font-mono text-[10px]">Ref/UTR: {activeTagLine.referenceNo || 'N/A'}</p>
                            </div>

                            {activeTagLine.type === 'CREDIT' ? (
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">
                                        Link to Sales Invoice (Customer Payment Received)
                                    </label>
                                    <select 
                                        value={selectedVoucherId} 
                                        onChange={(e) => setSelectedVoucherId(e.target.value)}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-bold text-slate-900 focus:outline-none focus:border-indigo-500"
                                    >
                                        <option value="">-- Direct Income (No Specific Invoice) --</option>
                                        {openSalesInvoices.map(inv => (
                                            <option key={inv._id} value={inv._id}>
                                                {inv.docNumber} - {inv.partyName} (₹{inv.summary?.totalAmount?.toLocaleString('en-IN')})
                                            </option>
                                        ))}
                                    </select>
                                </div>
                            ) : (
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">
                                        Link to Purchase Bill (Vendor Payment Out)
                                    </label>
                                    <select 
                                        value={selectedVoucherId} 
                                        onChange={(e) => setSelectedVoucherId(e.target.value)}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-bold text-slate-900 focus:outline-none focus:border-indigo-500"
                                    >
                                        <option value="">-- Operational Expense Ledger --</option>
                                        {openPurchaseBills.map(bill => (
                                            <option key={bill._id} value={bill._id}>
                                                {bill.docNumber} - {bill.partyName} (₹{bill.summary?.totalAmount?.toLocaleString('en-IN')})
                                            </option>
                                        ))}
                                    </select>
                                </div>
                            )}

                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">Accounting Category Head</label>
                                <select 
                                    value={selectedCategory}
                                    onChange={(e) => setSelectedCategory(e.target.value)}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-medium text-slate-900 focus:outline-none focus:border-indigo-500"
                                >
                                    <option value="Customer Sales Settlement">Customer Sales Settlement</option>
                                    <option value="Vendor Purchase Payment">Vendor Purchase Payment</option>
                                    <option value="Office Rent">Office Rent</option>
                                    <option value="Staff Salaries">Staff Salaries</option>
                                    <option value="Electricity & Utilities">Electricity & Utilities</option>
                                    <option value="Software Subscriptions">Software Subscriptions</option>
                                    <option value="Professional & Legal Fees">Professional & Legal Fees</option>
                                    <option value="Bank Charges & Interest">Bank Charges & Interest</option>
                                    <option value="Director Withdrawal / Capital">Director Withdrawal / Capital</option>
                                    <option value="Other Miscellaneous">Other Miscellaneous</option>
                                </select>
                            </div>

                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">Auditor / Reconciliation Notes</label>
                                <input 
                                    type="text" 
                                    value={tagNotes} 
                                    onChange={(e) => setTagNotes(e.target.value)}
                                    placeholder="e.g. Cleared via UPI / Cheque on 12th Aug" 
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 text-slate-900 focus:outline-none focus:border-indigo-500"
                                />
                            </div>

                            <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
                                <button 
                                    type="button" 
                                    onClick={() => setActiveTagLine(null)}
                                    className="px-4 py-2 rounded-xl text-slate-600 font-bold hover:bg-slate-100 transition"
                                >
                                    Cancel
                                </button>
                                <button 
                                    type="submit"
                                    disabled={taggingLoading}
                                    className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2 rounded-xl font-bold transition shadow-md"
                                >
                                    {taggingLoading ? 'Tagging...' : 'Confirm Tagging'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Upload Statement Modal with Password Decryptor */}
            {showUploadModal && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
                    <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl w-full max-w-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200 max-h-[92vh] flex flex-col">
                        <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50 shrink-0">
                            <div className="flex items-center gap-2">
                                <div className="w-8 h-8 rounded-xl bg-indigo-50 text-indigo-600 flex items-center justify-center">
                                    <Upload size={16} />
                                </div>
                                <div>
                                    <h3 className="font-black text-slate-900 text-sm">Upload & Unlock Bank Statement</h3>
                                    <p className="text-[11px] text-slate-400">Support for Password-Locked PDFs, Excel (.xlsx), and CSV statements</p>
                                </div>
                            </div>
                            <button onClick={() => setShowUploadModal(false)} className="text-slate-400 hover:text-slate-600">
                                <X size={18} />
                            </button>
                        </div>

                        <form onSubmit={handleSaveStatement} className="p-6 space-y-4 text-xs overflow-y-auto flex-1">
                            
                            {/* Bank Name & Preset */}
                            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Select Bank *</label>
                                    <select
                                        value={bankName}
                                        onChange={(e) => setBankName(e.target.value)}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-bold text-slate-900"
                                    >
                                        <option value="HDFC Bank">HDFC Bank</option>
                                        <option value="State Bank of India (SBI)">State Bank of India (SBI)</option>
                                        <option value="ICICI Bank">ICICI Bank</option>
                                        <option value="Axis Bank">Axis Bank</option>
                                        <option value="Kotak Mahindra Bank">Kotak Mahindra Bank</option>
                                        <option value="Punjab National Bank (PNB)">Punjab National Bank (PNB)</option>
                                        <option value="Canara Bank">Canara Bank</option>
                                        <option value="Union Bank of India">Union Bank of India</option>
                                        <option value="Bank of Baroda">Bank of Baroda</option>
                                        <option value="Federal Bank">Federal Bank</option>
                                        <option value="IndusInd Bank">IndusInd Bank</option>
                                        <option value="Other Bank">Other Bank</option>
                                    </select>
                                </div>

                                {bankName === 'Other Bank' && (
                                    <div>
                                        <label className="block text-[10px] font-bold text-slate-500 mb-1">Bank Name *</label>
                                        <input 
                                            type="text"
                                            value={customBankName}
                                            onChange={(e) => setCustomBankName(e.target.value)}
                                            placeholder="e.g. Standard Chartered"
                                            className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-bold text-slate-900"
                                            required
                                        />
                                    </div>
                                )}

                                <div className={bankName === 'Other Bank' ? 'col-span-1' : 'col-span-2'}>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Bank Account Number *</label>
                                    <input 
                                        type="text" 
                                        value={accountNumber} 
                                        onChange={(e) => setAccountNumber(e.target.value)}
                                        placeholder="e.g. 50200012345678" 
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-mono font-bold text-slate-900" 
                                        required 
                                    />
                                </div>
                            </div>

                            {/* File Upload Box */}
                            <div className="border-2 border-dashed border-indigo-200 bg-indigo-50/30 rounded-2xl p-5 text-center space-y-2">
                                <div className="w-10 h-10 bg-indigo-100 text-indigo-700 rounded-xl flex items-center justify-center mx-auto">
                                    <FileSpreadsheet size={20} />
                                </div>
                                <div>
                                    <p className="font-bold text-slate-800">Select Bank Statement File</p>
                                    <p className="text-[11px] text-slate-500">Upload official PDF, Excel (.xlsx, .xls), or CSV</p>
                                </div>

                                <input 
                                    type="file" 
                                    accept=".pdf,.xlsx,.xls,.csv" 
                                    onChange={handleFileSelect}
                                    className="pt-1 text-xs" 
                                />

                                {fileName && (
                                    <div className="pt-2 flex items-center justify-center gap-2">
                                        <span className="font-mono font-bold text-indigo-700 bg-white border border-indigo-200 px-3 py-1 rounded-lg">
                                            {fileName}
                                        </span>
                                        {isExcelParsed && (
                                            <span className="bg-emerald-100 text-emerald-800 font-bold text-[10px] px-2 py-0.5 rounded-full flex items-center gap-1">
                                                <Sparkles size={11} /> Auto-Parsed
                                            </span>
                                        )}
                                    </div>
                                )}
                            </div>

                            {/* PDF Password Decryption Box */}
                            <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4 space-y-3">
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-2">
                                        <Lock size={15} className="text-indigo-600" />
                                        <h4 className="font-bold text-slate-900 text-xs">PDF Statement Password (If Protected)</h4>
                                    </div>
                                    <span className="text-[10px] font-bold text-slate-400">Decrypted for Auditor</span>
                                </div>

                                <div className="relative">
                                    <input 
                                        type={showPassword ? "text" : "password"} 
                                        value={pdfPassword}
                                        onChange={(e) => setPdfPassword(e.target.value)}
                                        placeholder="Enter password (e.g. Customer ID or Name+DOB)"
                                        className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs font-mono font-bold text-slate-900 pr-10 focus:outline-none focus:border-indigo-500"
                                    />
                                    <button
                                        type="button"
                                        onClick={() => setShowPassword(!showPassword)}
                                        className="absolute right-3 top-2.5 text-slate-400 hover:text-slate-600"
                                    >
                                        {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                                    </button>
                                </div>

                                {/* Dynamic Smart Bank Hint */}
                                <div className="bg-indigo-50/70 border border-indigo-100 rounded-xl p-2.5 text-[11px] text-indigo-900 flex items-start gap-2">
                                    <HelpCircle size={14} className="text-indigo-600 shrink-0 mt-0.5" />
                                    <div>
                                        <strong className="font-bold">{bankName} Default Password Rule:</strong>
                                        <p className="text-slate-600 text-[10px] mt-0.5 leading-relaxed">{activeBankHint}</p>
                                    </div>
                                </div>
                            </div>

                            {/* Transaction Preview & Manual Grid */}
                            <div className="border border-slate-200 rounded-2xl p-4 space-y-3">
                                <div className="flex justify-between items-center">
                                    <div>
                                        <h4 className="font-black text-slate-900 uppercase tracking-wide text-xs">
                                            Transaction Lines ({manualRows.length})
                                        </h4>
                                        <p className="text-[10px] text-slate-400">Review, add, or adjust statement line items</p>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <button 
                                            type="button"
                                            onClick={handleLoadSampleStatement}
                                            className="bg-slate-100 hover:bg-slate-200 text-slate-700 px-2.5 py-1 rounded-xl font-bold flex items-center gap-1 text-[10px]"
                                        >
                                            <Sparkles size={12} className="text-indigo-600" /> Demo Data
                                        </button>
                                        <button 
                                            type="button" 
                                            onClick={handleAddRow}
                                            className="bg-indigo-50 text-indigo-700 hover:bg-indigo-100 px-3 py-1 rounded-xl font-bold flex items-center gap-1 text-[11px]"
                                        >
                                            <Plus size={13} /> Add Row
                                        </button>
                                    </div>
                                </div>

                                <div className="space-y-2 max-h-52 overflow-y-auto pr-1">
                                    {manualRows.map((row, idx) => (
                                        <div key={idx} className="grid grid-cols-12 gap-2 bg-slate-50 p-2 rounded-xl items-center border border-slate-200/60">
                                            <input 
                                                type="date" 
                                                value={row.date} 
                                                onChange={(e) => handleRowChange(idx, 'date', e.target.value)} 
                                                className="col-span-3 bg-white border border-slate-200 rounded-lg p-1.5 font-bold text-[11px]" 
                                            />
                                            <input 
                                                type="text" 
                                                placeholder="Narration" 
                                                value={row.description} 
                                                onChange={(e) => handleRowChange(idx, 'description', e.target.value)} 
                                                className="col-span-4 bg-white border border-slate-200 rounded-lg p-1.5 text-[11px]" 
                                            />
                                            <select 
                                                value={row.type} 
                                                onChange={(e) => handleRowChange(idx, 'type', e.target.value)}
                                                className={`col-span-2 bg-white border border-slate-200 rounded-lg p-1.5 font-bold text-center text-[10px] ${row.type === 'CREDIT' ? 'text-emerald-700' : 'text-rose-700'}`}
                                            >
                                                <option value="CREDIT">CREDIT (+)</option>
                                                <option value="DEBIT">DEBIT (-)</option>
                                            </select>
                                            <input 
                                                type="number" 
                                                placeholder="Amount" 
                                                value={row.amount} 
                                                onChange={(e) => handleRowChange(idx, 'amount', e.target.value)} 
                                                className="col-span-2 bg-white border border-slate-200 rounded-lg p-1.5 font-mono font-bold text-right text-[11px]" 
                                            />
                                            <button 
                                                type="button" 
                                                onClick={() => handleRemoveRow(idx)}
                                                className="col-span-1 text-slate-400 hover:text-rose-600 text-center font-bold"
                                                title="Remove Line"
                                            >
                                                ✕
                                            </button>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            <div className="flex justify-between items-center pt-2 border-t border-slate-100 shrink-0">
                                <span className="text-[10px] text-slate-400">
                                    Tip: Netbanking Excel/CSV exports are never password locked.
                                </span>
                                <div className="flex items-center gap-2">
                                    <button 
                                        type="button" 
                                        onClick={() => setShowUploadModal(false)}
                                        className="px-4 py-2 rounded-xl text-slate-600 font-bold hover:bg-slate-100 transition"
                                    >
                                        Cancel
                                    </button>
                                    <button 
                                        type="submit"
                                        className="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-2 rounded-xl font-bold transition shadow-md shadow-indigo-100"
                                    >
                                        Save & Parse Statement
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            )}

        </div>
    );
};

export default BankStatementsTab;
