import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Upload, Plus, Check, Search, FileText, ArrowDownLeft, ArrowUpRight, Link2, X, RefreshCw } from 'lucide-react';

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
    const [selectedCategory, setSelectedCategory] = useState('Sales Collection');
    const [tagNotes, setTagNotes] = useState('');
    const [taggingLoading, setTaggingLoading] = useState(false);

    // New statement form state
    const [bankName, setBankName] = useState('HDFC Bank');
    const [accountNumber, setAccountNumber] = useState('');
    const [statementTitle, setStatementTitle] = useState('Current A/c Statement - 2026');
    const [manualRows, setManualRows] = useState([
        { date: new Date().toISOString().split('T')[0], description: 'NEFT INWARD - Lucky Constructions', referenceNo: 'UTR987654321', type: 'CREDIT', amount: 11800, balance: 11800 }
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

    const handleRowChange = (idx, field, val) => {
        const updated = [...manualRows];
        updated[idx][field] = val;
        setManualRows(updated);
    };

    const handleSaveStatement = async (e) => {
        e.preventDefault();
        if (!accountNumber) {
            alert('Please enter bank account number');
            return;
        }
        try {
            const { data } = await axios.post('/api/accounting/bank-statements', {
                bankName,
                accountNumber,
                statementTitle,
                transactions: manualRows
            }, config);
            setStatements([data, ...statements]);
            setSelectedStatement(data);
            setShowUploadModal(false);
            alert('Bank statement saved successfully!');
        } catch (error) {
            alert('Failed to save statement: ' + (error.response?.data?.message || error.message));
        }
    };

    const handleOpenTagModal = (line) => {
        setActiveTagLine(line);
        setSelectedVoucherId('');
        setSelectedCategory(line.type === 'CREDIT' ? 'Sales Invoicing Settlement' : 'Vendor Payment');
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
            alert('Bank transaction tagged and reconciled successfully!');
        } catch (error) {
            alert('Failed to tag transaction: ' + (error.response?.data?.message || error.message));
        } finally {
            setTaggingLoading(false);
        }
    };

    return (
        <div className="space-y-6">

            {/* Statements List & Active Statement View */}
            {loading ? (
                <div className="flex justify-center py-20">
                    <div className="w-10 h-10 border-4 border-slate-200 border-t-indigo-600 rounded-full animate-spin"></div>
                </div>
            ) : statements.length === 0 ? (
                <div className="bg-white rounded-3xl p-16 text-center border border-slate-100 shadow-sm space-y-4">
                    <div className="w-16 h-16 bg-indigo-50 text-indigo-600 rounded-3xl flex items-center justify-center mx-auto text-2xl">
                        🏦
                    </div>
                    <div>
                        <h4 className="font-black text-slate-900 text-base">No Bank Statements Added Yet</h4>
                        <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
                            Upload your business bank statement to review transactions and tag payments against sales invoices or operational bills.
                        </p>
                    </div>
                    <button 
                        onClick={() => setShowUploadModal(true)}
                        className="bg-indigo-600 text-white px-6 py-2.5 rounded-2xl font-bold text-xs uppercase hover:bg-indigo-700 transition"
                    >
                        + Add Bank Statement
                    </button>
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
                                <span className="font-mono text-[10px] opacity-75">({stmt.accountNumber.slice(-4)})</span>
                            </button>
                        ))}
                        <button
                            onClick={() => setShowUploadModal(true)}
                            className="px-4 py-2.5 rounded-2xl text-xs font-black uppercase tracking-wider transition shrink-0 flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-700 text-white shadow-md shadow-indigo-100"
                        >
                            <Plus size={14} /> Upload / Add Statement
                        </button>
                    </div>

                    {/* Statement Table */}
                    {selectedStatement && (
                        <div className="bg-white rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 overflow-hidden">
                            <div className="p-5 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
                                <div>
                                    <h4 className="font-black text-slate-900 text-sm">{selectedStatement.statementTitle}</h4>
                                    <p className="text-[11px] text-slate-500 font-mono mt-0.5">Account: {selectedStatement.accountNumber} ({selectedStatement.bankName})</p>
                                </div>
                                <span className="text-[10px] font-black uppercase tracking-wider bg-indigo-50 text-indigo-700 px-3 py-1 rounded-full border border-indigo-200">
                                    {selectedStatement.transactions?.length || 0} Transactions
                                </span>
                            </div>

                            <div className="overflow-x-auto">
                                <table className="w-full text-left border-collapse text-xs">
                                    <thead>
                                        <tr className="bg-slate-50 text-slate-400 font-black text-[10px] uppercase tracking-wider border-b border-slate-100">
                                            <th className="px-6 py-3.5">Date</th>
                                            <th className="px-6 py-3.5">Narration / Description</th>
                                            <th className="px-6 py-3.5">Reference / UTR</th>
                                            <th className="px-6 py-3.5 text-right">Debit (₹)</th>
                                            <th className="px-6 py-3.5 text-right">Credit (₹)</th>
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
                                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">Accounting Category Tag</label>
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
                                    placeholder="e.g. Paid via UPI on 12th Aug"
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

            {/* Add Statement Modal */}
            {showUploadModal && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
                    <div className="bg-white rounded-[2rem] border border-slate-200 shadow-2xl w-full max-w-3xl overflow-hidden animate-in fade-in zoom-in-95 duration-200">
                        <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50">
                            <h3 className="font-black text-slate-900 text-base">Add New Bank Statement Record</h3>
                            <button onClick={() => setShowUploadModal(false)} className="text-slate-400 hover:text-slate-600">
                                <X size={20} />
                            </button>
                        </div>

                        <form onSubmit={handleSaveStatement} className="p-6 space-y-4 text-xs">
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Bank Name *</label>
                                    <input 
                                        type="text" 
                                        value={bankName} 
                                        onChange={(e) => setBankName(e.target.value)}
                                        placeholder="e.g. HDFC Bank" 
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-bold text-slate-900" 
                                        required 
                                    />
                                </div>
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Account Number *</label>
                                    <input 
                                        type="text" 
                                        value={accountNumber} 
                                        onChange={(e) => setAccountNumber(e.target.value)}
                                        placeholder="50200012345678" 
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-mono text-slate-900" 
                                        required 
                                    />
                                </div>
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Statement Title</label>
                                    <input 
                                        type="text" 
                                        value={statementTitle} 
                                        onChange={(e) => setStatementTitle(e.target.value)}
                                        placeholder="Q1 Bank Statement" 
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 text-slate-900" 
                                    />
                                </div>
                            </div>

                            <div className="border border-slate-200 rounded-2xl p-4 space-y-3">
                                <div className="flex justify-between items-center">
                                    <h4 className="font-black text-slate-900 uppercase tracking-wide text-xs">Statement Transaction Rows</h4>
                                    <button 
                                        type="button" 
                                        onClick={handleAddRow}
                                        className="bg-indigo-50 text-indigo-700 px-3 py-1 rounded-xl font-bold flex items-center gap-1 text-[11px]"
                                    >
                                        <Plus size={13} /> Add Row
                                    </button>
                                </div>

                                <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                                    {manualRows.map((row, idx) => (
                                        <div key={idx} className="grid grid-cols-12 gap-2 bg-slate-50 p-2.5 rounded-xl items-center border border-slate-200/60">
                                            <input 
                                                type="date" 
                                                value={row.date} 
                                                onChange={(e) => handleRowChange(idx, 'date', e.target.value)} 
                                                className="col-span-3 bg-white border border-slate-200 rounded-lg p-1.5 font-bold" 
                                            />
                                            <input 
                                                type="text" 
                                                placeholder="Narration" 
                                                value={row.description} 
                                                onChange={(e) => handleRowChange(idx, 'description', e.target.value)} 
                                                className="col-span-4 bg-white border border-slate-200 rounded-lg p-1.5" 
                                            />
                                            <select 
                                                value={row.type} 
                                                onChange={(e) => handleRowChange(idx, 'type', e.target.value)}
                                                className="col-span-2 bg-white border border-slate-200 rounded-lg p-1.5 font-bold text-center"
                                            >
                                                <option value="CREDIT">CREDIT (+)</option>
                                                <option value="DEBIT">DEBIT (-)</option>
                                            </select>
                                            <input 
                                                type="number" 
                                                placeholder="Amount" 
                                                value={row.amount} 
                                                onChange={(e) => handleRowChange(idx, 'amount', e.target.value)} 
                                                className="col-span-3 bg-white border border-slate-200 rounded-lg p-1.5 font-mono font-bold text-right" 
                                            />
                                        </div>
                                    ))}
                                </div>
                            </div>

                            <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
                                <button 
                                    type="button" 
                                    onClick={() => setShowUploadModal(false)}
                                    className="px-4 py-2 rounded-xl text-slate-600 font-bold hover:bg-slate-100 transition"
                                >
                                    Cancel
                                </button>
                                <button 
                                    type="submit"
                                    className="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-2 rounded-xl font-bold transition shadow-md"
                                >
                                    Save Statement
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
