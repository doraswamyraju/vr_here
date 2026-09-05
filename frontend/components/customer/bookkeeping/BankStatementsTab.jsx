import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import { 
    Upload, Plus, Check, Search, FileText, ArrowDownLeft, ArrowUpRight, 
    Link2, X, RefreshCw, Lock, Unlock, Eye, EyeOff, ShieldCheck, HelpCircle, 
    FileSpreadsheet, Sparkles, AlertCircle, CheckCircle2, Calendar, Landmark
} from 'lucide-react';
import { parseExcelStatement, parsePdfStatement, detectBankFromText } from '../../../utils/bankStatementParser';

const BANK_PASSWORD_HINTS = {
    'HDFC Bank': 'Customer ID (8-digits) OR First 4 letters of name (lowercase) + DOB (DDMM) e.g. dora1408',
    'State Bank of India (SBI)': 'Last 5 digits of registered mobile number + DOB (DDMM) e.g. 987651408',
    'ICICI Bank': 'First 4 letters of name in lowercase + DOB (DDMM) e.g. dora1408',
    'Axis Bank': 'First 4 letters of name in CAPITALS + 4-digit Year of Birth e.g. DORA1995',
    'Kotak Mahindra Bank': 'CRN Number (9 digits) OR First 4 letters of name + DOB (DDMM)',
    'Punjab National Bank (PNB)': 'Account Number OR Customer ID',
    'Canara Bank': 'Customer ID or First 4 letters + DOB (DDMM)',
    'Other': 'Enter the PDF password specified by your bank'
};

const BankStatementsTab = ({
    token,
    transactions = [],
    company,
    selectedMonth = 'ALL',
    onRefreshLedger
}) => {
    const [statements, setStatements] = useState([]);
    const [selectedStatement, setSelectedStatement] = useState(null);
    const [loading, setLoading] = useState(true);
    
    // Upload & Parsing Modal
    const [showUploadModal, setShowUploadModal] = useState(false);
    const [uploadedFile, setUploadedFile] = useState(null);
    const [isParsing, setIsParsing] = useState(false);
    const [passwordRequired, setPasswordRequired] = useState(false);
    const [pdfPassword, setPdfPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [parsedData, setParsedData] = useState(null);
    const [parseError, setParseError] = useState('');
    const [detectedBank, setDetectedBank] = useState('HDFC Bank');

    // Tagging Modal State
    const [activeTagLine, setActiveTagLine] = useState(null);
    const [selectedVoucherId, setSelectedVoucherId] = useState('');
    const [selectedCategory, setSelectedCategory] = useState('Customer Sales Settlement');
    const [tagNotes, setTagNotes] = useState('');
    const [taggingLoading, setTaggingLoading] = useState(false);

    const config = { headers: { Authorization: `Bearer ${token}` } };

    // Fetch all bank statements
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

    // Handle File Drop / Select
    const handleFileChosen = async (file) => {
        if (!file) return;
        setUploadedFile(file);
        setParseError('');
        setPasswordRequired(false);
        setParsedData(null);
        setIsParsing(true);

        const fileExt = file.name.split('.').pop()?.toLowerCase();

        try {
            if (fileExt === 'xlsx' || fileExt === 'xls' || fileExt === 'csv') {
                const result = await parseExcelStatement(file);
                setParsedData(result);
                setDetectedBank(result.bankName);
            } else if (fileExt === 'pdf') {
                const result = await parsePdfStatement(file, pdfPassword);
                setParsedData(result);
                setDetectedBank(result.bankName);
            }
        } catch (err) {
            if (err.isPasswordRequired) {
                setPasswordRequired(true);
            } else {
                setParseError(err.message || 'Could not parse bank statement file.');
            }
        } finally {
            setIsParsing(false);
        }
    };

    // Retry with Password
    const handleUnlockWithPassword = async (e) => {
        e.preventDefault();
        if (!uploadedFile) return;
        setIsParsing(true);
        setParseError('');

        try {
            const result = await parsePdfStatement(uploadedFile, pdfPassword);
            setParsedData(result);
            setDetectedBank(result.bankName);
            setPasswordRequired(false);
        } catch (err) {
            if (err.isPasswordRequired) {
                setParseError('Incorrect password. Please verify and try again.');
            } else {
                setParseError(err.message || 'Failed to unlock PDF.');
            }
        } finally {
            setIsParsing(false);
        }
    };

    // Save Parsed Statement & Transactions to Database
    const handleSaveParsedStatement = async () => {
        if (!parsedData || parsedData.transactions.length === 0) {
            alert('No transactions found to save.');
            return;
        }

        try {
            const payload = {
                bankName: parsedData.bankName || detectedBank || 'Bank Account',
                accountNumber: parsedData.accountNumber || company?.bankDetails?.accountNumber || 'Primary A/c',
                statementTitle: `${parsedData.bankName || 'Bank'} Statement - ${new Date().toLocaleDateString('en-GB', { month: 'short', year: 'numeric' })}`,
                fileName: uploadedFile?.name || 'Statement.pdf',
                isPasswordProtected: Boolean(pdfPassword),
                pdfPassword: pdfPassword || '',
                transactions: parsedData.transactions
            };

            const { data } = await axios.post('/api/accounting/bank-statements', payload, config);
            setStatements([data, ...statements]);
            setSelectedStatement(data);
            setShowUploadModal(false);
            setUploadedFile(null);
            setParsedData(null);
            setPdfPassword('');
            alert(`Bank statement successfully parsed & saved! ${data.transactions.length} transactions are now ready for payment tagging.`);
        } catch (error) {
            alert('Failed to save statement: ' + (error.response?.data?.message || error.message));
        }
    };

    // Demo Data Loader for 1-Click Verification
    const handleLoadSampleStatement = () => {
        const sampleLines = [
            { date: '2026-04-05', description: 'NEFT CR - Lucky Infra Tech (Sales Invoice Settled)', referenceNo: 'HDFCR52026040501', type: 'CREDIT', amount: 59000, balance: 159000, reconciliationStatus: 'UNRECONCILED' },
            { date: '2026-04-10', description: 'ACH DR - Google Workspace Cloud Suite', referenceNo: 'GOOGL99281234', type: 'DEBIT', amount: 15340, balance: 143660, reconciliationStatus: 'UNRECONCILED' },
            { date: '2026-04-14', description: 'UPI CR - Consulting Retainer Advance', referenceNo: 'UPI99201948123', type: 'CREDIT', amount: 25000, balance: 168660, reconciliationStatus: 'UNRECONCILED' },
            { date: '2026-04-18', description: 'IMPS DR - Commercial Office Rent April 2026', referenceNo: 'IMPS884910293', type: 'DEBIT', amount: 35000, balance: 133660, reconciliationStatus: 'UNRECONCILED' },
            { date: '2026-04-22', description: 'NEFT DR - Apex Paper Mills (Vendor Purchase Bill)', referenceNo: 'AXIS994019284', type: 'DEBIT', amount: 23600, balance: 110060, reconciliationStatus: 'UNRECONCILED' }
        ];

        setParsedData({
            bankName: 'HDFC Bank',
            accountNumber: '50200088991122',
            transactions: sampleLines
        });
        setDetectedBank('HDFC Bank');
    };

    // Tag Transaction
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
            alert('Transaction line tagged & reconciled successfully!');
        } catch (error) {
            alert('Failed to tag transaction: ' + (error.response?.data?.message || error.message));
        } finally {
            setTaggingLoading(false);
        }
    };

    // Filter transactions based on selectedMonth
    const filteredTransactions = useMemo(() => {
        if (!selectedStatement?.transactions) return [];
        if (selectedMonth === 'ALL') return selectedStatement.transactions;

        return selectedStatement.transactions.filter(t => {
            if (!t.date) return false;
            const d = new Date(t.date);
            const monthStr = d.toLocaleDateString('en-GB', { month: 'long', year: 'numeric' });
            return monthStr.toLowerCase() === selectedMonth.toLowerCase();
        });
    }, [selectedStatement, selectedMonth]);

    // Monthly summary stats
    const totalCredits = filteredTransactions.filter(t => t.type === 'CREDIT').reduce((acc, t) => acc + (t.amount || 0), 0);
    const totalDebits = filteredTransactions.filter(t => t.type === 'DEBIT').reduce((acc, t) => acc + (t.amount || 0), 0);
    const taggedCount = filteredTransactions.filter(t => t.reconciliationStatus === 'TAGGED').length;

    return (
        <div className="space-y-6">

            {/* Top Overview & Action Bar */}
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-white p-5 rounded-3xl border border-slate-100 shadow-sm">
                <div>
                    <div className="flex items-center gap-2">
                        <h3 className="text-lg font-black text-slate-900">
                            Bank Statement Ledger & Reconciliation
                        </h3>
                        {selectedMonth !== 'ALL' && (
                            <span className="bg-indigo-50 text-indigo-700 text-xs font-bold px-2.5 py-0.5 rounded-full border border-indigo-200 flex items-center gap-1">
                                <Calendar size={12} /> {selectedMonth}
                            </span>
                        )}
                    </div>
                    <p className="text-xs text-slate-500 font-medium mt-0.5">
                        Upload your bank statement (PDF/Excel) to auto-extract transactions and tag payments against invoices & bills.
                    </p>
                </div>

                <div className="flex items-center gap-2">
                    <button
                        onClick={fetchStatements}
                        className="p-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-2xl transition"
                        title="Refresh"
                    >
                        <RefreshCw size={15} />
                    </button>
                    <button
                        onClick={() => {
                            setUploadedFile(null);
                            setParsedData(null);
                            setPasswordRequired(false);
                            setParseError('');
                            setShowUploadModal(true);
                        }}
                        className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2.5 rounded-2xl font-black text-xs uppercase tracking-wider transition shadow-md shadow-indigo-100 flex items-center gap-1.5"
                    >
                        <Upload size={15} /> Upload Statement (PDF/Excel)
                    </button>
                </div>
            </div>

            {/* Monthly KPI Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm space-y-1">
                    <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Total Money In (Credit)</span>
                    <p className="text-xl font-black text-emerald-600 font-mono">₹{totalCredits.toLocaleString('en-IN')}</p>
                    <p className="text-[10px] text-slate-500 font-medium">Customer Settlements & Inflow</p>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm space-y-1">
                    <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Total Money Out (Debit)</span>
                    <p className="text-xl font-black text-rose-600 font-mono">₹{totalDebits.toLocaleString('en-IN')}</p>
                    <p className="text-[10px] text-slate-500 font-medium">Vendor Bills & Expenses</p>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm space-y-1">
                    <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Net Period Balance</span>
                    <p className={`text-xl font-black font-mono ${totalCredits >= totalDebits ? 'text-indigo-900' : 'text-rose-700'}`}>
                        ₹{(totalCredits - totalDebits).toLocaleString('en-IN')}
                    </p>
                    <p className="text-[10px] text-slate-500 font-medium">Cash Flow Margin</p>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm space-y-1">
                    <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Reconciliation Status</span>
                    <p className="text-xl font-black text-slate-900 font-mono">
                        {taggedCount} / {filteredTransactions.length}
                    </p>
                    <p className="text-[10px] text-emerald-600 font-bold">Tagged & Matched Lines</p>
                </div>
            </div>

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
                            Upload your official bank statement (PDF, Excel, or CSV). The system will automatically detect the bank, decrypt the statement, and extract all transaction lines.
                        </p>
                    </div>

                    <div className="flex items-center justify-center gap-3 pt-2">
                        <button 
                            onClick={() => {
                                setUploadedFile(null);
                                setParsedData(null);
                                setShowUploadModal(true);
                            }}
                            className="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-3 rounded-2xl font-black text-xs uppercase tracking-wider transition shadow-lg shadow-indigo-200 flex items-center gap-2"
                        >
                            <Upload size={15} /> Upload Statement
                        </button>
                    </div>
                </div>
            ) : (
                <div className="space-y-4">
                    {/* Bank Account Switcher Tabs */}
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
                                    {filteredTransactions.length} Transactions {selectedMonth !== 'ALL' ? `(${selectedMonth})` : ''}
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
                                        {filteredTransactions.length === 0 ? (
                                            <tr>
                                                <td colSpan={7} className="text-center py-12 text-slate-400 font-medium">
                                                    No transactions recorded for the selected period ({selectedMonth}).
                                                </td>
                                            </tr>
                                        ) : (
                                            filteredTransactions.map((line) => (
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
                                                            className="bg-indigo-50 hover:bg-indigo-600 hover:text-white text-indigo-700 px-3 py-1.5 rounded-xl font-bold transition inline-flex items-center gap-1 text-xs shadow-xs"
                                                        >
                                                            <Link2 size={13} /> {line.reconciliationStatus === 'TAGGED' ? 'Re-tag' : 'Tag Payment'}
                                                        </button>
                                                    </td>
                                                </tr>
                                            ))
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* Frictionless Bank Statement Upload Modal */}
            {showUploadModal && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
                    <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl w-full max-w-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200 max-h-[92vh] flex flex-col">
                        <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50 shrink-0">
                            <div className="flex items-center gap-2.5">
                                <div className="w-8 h-8 rounded-xl bg-indigo-50 text-indigo-600 flex items-center justify-center">
                                    <Upload size={16} />
                                </div>
                                <div>
                                    <h3 className="font-black text-slate-900 text-sm">Upload Bank Statement</h3>
                                    <p className="text-[11px] text-slate-400">PDF, Excel (.xlsx, .xls), or CSV Statements</p>
                                </div>
                            </div>
                            <button onClick={() => setShowUploadModal(false)} className="text-slate-400 hover:text-slate-600">
                                <X size={18} />
                            </button>
                        </div>

                        <div className="p-6 space-y-4 text-xs overflow-y-auto flex-1">
                            
                            {/* Drag & Drop File Upload Box */}
                            <div className="border-2 border-dashed border-indigo-200 bg-indigo-50/20 hover:bg-indigo-50/40 transition rounded-3xl p-6 text-center space-y-3">
                                <div className="w-12 h-12 bg-indigo-100 text-indigo-700 rounded-2xl flex items-center justify-center mx-auto shadow-sm">
                                    <FileSpreadsheet size={24} />
                                </div>
                                <div>
                                    <h4 className="font-black text-slate-800 text-sm">Select or Drop Bank Statement File</h4>
                                    <p className="text-slate-500 text-[11px] mt-0.5">
                                        The parser automatically detects bank details and extracts all transaction rows.
                                    </p>
                                </div>

                                <input 
                                    type="file" 
                                    accept=".pdf,.xlsx,.xls,.csv" 
                                    onChange={(e) => handleFileChosen(e.target.files?.[0])}
                                    className="pt-1 text-xs" 
                                />

                                {uploadedFile && (
                                    <div className="pt-2 flex items-center justify-center gap-2">
                                        <span className="font-mono font-bold text-indigo-900 bg-white border border-indigo-200 px-3 py-1 rounded-xl shadow-xs">
                                            {uploadedFile.name}
                                        </span>
                                        {isParsing && <span className="text-slate-500 animate-pulse font-bold">Parsing...</span>}
                                    </div>
                                )}
                            </div>

                            {/* Password Protection Prompt */}
                            {passwordRequired && (
                                <form onSubmit={handleUnlockWithPassword} className="bg-amber-50/80 border-2 border-amber-200 rounded-2xl p-5 space-y-3 animate-in fade-in">
                                    <div className="flex items-center gap-2 text-amber-900 font-black">
                                        <Lock size={16} className="text-amber-700" />
                                        <span>Password Protected Statement Detected</span>
                                    </div>
                                    <p className="text-slate-600 text-[11px] leading-relaxed">
                                        This bank statement is password-locked. Please enter the password to decrypt and extract all transaction lines.
                                    </p>

                                    <div className="relative">
                                        <input 
                                            type={showPassword ? "text" : "password"} 
                                            value={pdfPassword}
                                            onChange={(e) => setPdfPassword(e.target.value)}
                                            placeholder="Enter statement password..."
                                            className="w-full bg-white border border-amber-300 rounded-xl px-3.5 py-2.5 text-xs font-mono font-bold text-slate-900 pr-10 focus:outline-none focus:ring-2 focus:ring-amber-500/30"
                                            required
                                        />
                                        <button
                                            type="button"
                                            onClick={() => setShowPassword(!showPassword)}
                                            className="absolute right-3 top-3 text-slate-400 hover:text-slate-600"
                                        >
                                            {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                                        </button>
                                    </div>

                                    {/* Bank Password Hint */}
                                    <div className="bg-white/80 border border-amber-200 rounded-xl p-3 text-[11px] text-amber-950 space-y-1">
                                        <strong className="block font-bold">Common Indian Bank Password Formats:</strong>
                                        <ul className="list-disc pl-4 space-y-0.5 text-[10px] text-slate-700">
                                            <li><strong>HDFC:</strong> Customer ID OR Name (4 letters lowercase) + DOB (DDMM)</li>
                                            <li><strong>SBI:</strong> Last 5 digits of mobile no + DOB (DDMM)</li>
                                            <li><strong>ICICI:</strong> First 4 letters of name in lowercase + DOB (DDMM)</li>
                                            <li><strong>Axis:</strong> First 4 letters in CAPITALS + 4-digit Year of birth</li>
                                            <li><strong>Kotak:</strong> CRN number OR First 4 letters of name + DOB (DDMM)</li>
                                        </ul>
                                    </div>

                                    <button 
                                        type="submit"
                                        disabled={isParsing}
                                        className="w-full bg-amber-600 hover:bg-amber-700 text-white font-black py-2.5 rounded-xl uppercase tracking-wider text-xs transition shadow-md shadow-amber-200 flex items-center justify-center gap-1.5"
                                    >
                                        {isParsing ? 'Decrypting...' : <><Unlock size={14} /> Unlock & Extract Transactions</>}
                                    </button>
                                </form>
                            )}

                            {/* Error Display */}
                            {parseError && (
                                <div className="bg-rose-50 border border-rose-200 rounded-xl p-3 text-rose-700 text-xs flex items-center gap-2 font-medium">
                                    <AlertCircle size={15} className="shrink-0" />
                                    <span>{parseError}</span>
                                </div>
                            )}

                            {/* Parsed Transactions Preview */}
                            {parsedData && (
                                <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4 space-y-3 animate-in fade-in">
                                    <div className="flex items-center justify-between border-b border-slate-200 pb-2">
                                        <div className="flex items-center gap-2">
                                            <span className="w-7 h-7 rounded-lg bg-emerald-100 text-emerald-700 flex items-center justify-center font-bold text-xs">
                                                ✓
                                            </span>
                                            <div>
                                                <h4 className="font-black text-slate-900 text-xs">{parsedData.bankName}</h4>
                                                <p className="text-[10px] text-slate-500 font-mono">{parsedData.accountNumber}</p>
                                            </div>
                                        </div>
                                        <span className="bg-emerald-100 text-emerald-800 text-[10px] font-black px-2.5 py-0.5 rounded-full">
                                            {parsedData.transactions.length} Transactions Extracted
                                        </span>
                                    </div>

                                    <div className="max-h-48 overflow-y-auto space-y-1.5 pr-1">
                                        {parsedData.transactions.map((tx, idx) => (
                                            <div key={idx} className="flex justify-between items-center bg-white p-2 rounded-xl border border-slate-100 text-[11px]">
                                                <div>
                                                    <span className="font-mono font-bold text-slate-500 text-[10px] mr-2">{tx.date}</span>
                                                    <span className="font-bold text-slate-800">{tx.description}</span>
                                                </div>
                                                <span className={`font-mono font-black ${tx.type === 'CREDIT' ? 'text-emerald-600' : 'text-rose-600'}`}>
                                                    {tx.type === 'CREDIT' ? '+' : '-'}₹{tx.amount?.toLocaleString('en-IN')}
                                                </span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Demo Statement Option */}
                            {!parsedData && !passwordRequired && (
                                <div className="text-center pt-2">
                                    <button
                                        type="button"
                                        onClick={handleLoadSampleStatement}
                                        className="text-indigo-600 hover:text-indigo-800 font-bold text-xs inline-flex items-center gap-1 underline underline-offset-2"
                                    >
                                        <Sparkles size={12} /> Or test with sample statement transactions
                                    </button>
                                </div>
                            )}
                        </div>

                        {/* Modal Footer */}
                        <div className="p-4 border-t border-slate-100 bg-slate-50 flex justify-end gap-2 shrink-0">
                            <button 
                                type="button" 
                                onClick={() => setShowUploadModal(false)}
                                className="px-4 py-2 rounded-xl text-slate-600 font-bold hover:bg-slate-200 transition"
                            >
                                Cancel
                            </button>
                            <button 
                                type="button"
                                disabled={!parsedData || isParsing}
                                onClick={handleSaveParsedStatement}
                                className="bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white px-6 py-2 rounded-xl font-bold transition shadow-md shadow-indigo-100 flex items-center gap-1.5"
                            >
                                <Check size={15} /> Save & Open in Ledger
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Tagging Modal */}
            {activeTagLine && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl w-full max-w-lg overflow-hidden animate-in fade-in zoom-in-95 duration-200">
                        <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50">
                            <h3 className="font-black text-slate-900 text-sm">
                                Tag Bank Transaction ({activeTagLine.type === 'CREDIT' ? 'Money In' : 'Money Out'})
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
                                <p className="text-slate-400 font-mono text-[10px]">Date: {activeTagLine.date ? new Date(activeTagLine.date).toLocaleDateString('en-GB') : '-'} • Ref/UTR: {activeTagLine.referenceNo || 'N/A'}</p>
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
                                    placeholder="e.g. Cleared via UPI / Cheque on 12th" 
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

        </div>
    );
};

export default BankStatementsTab;
