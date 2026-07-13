import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    Calculator, Plus, Settings, Download, FileText, Trash2, 
    ArrowUpRight, ArrowDownLeft, DollarSign, RefreshCw, X, Eye, 
    Upload, Camera, Check, FileCheck, CheckCircle, Printer, Share2, Copy
} from 'lucide-react';

const BookkeepingView = ({ token }) => {
    const [transactions, setTransactions] = useState([]);
    const [company, setCompany] = useState(null);
    const [loading, setLoading] = useState(true);
    const [showAddForm, setShowAddForm] = useState(false);
    const [showSettings, setShowSettings] = useState(false);
    const [uploadingBill, setUploadingBill] = useState(false);
    const [selectedInvoice, setSelectedInvoice] = useState(null);

    // Form states
    const [txType, setTxType] = useState('Sales');
    const [docNumber, setDocNumber] = useState('');
    const [docDate, setDocDate] = useState(new Date().toISOString().split('T')[0]);
    const [partyName, setPartyName] = useState('');
    const [partyGstin, setPartyGstin] = useState('');
    const [placeOfSupply, setPlaceOfSupply] = useState('Andhra Pradesh');
    const [isInterstate, setIsInterstate] = useState(false);
    const [itcEligibility, setItcEligibility] = useState('Inputs');
    const [notes, setNotes] = useState('');
    const [items, setItems] = useState([{ description: '', hsnSac: '', qty: 1, rate: 0, gstRate: 18 }]);

    // Company Settings Form states
    const [companyName, setCompanyName] = useState('');
    const [tradeName, setTradeName] = useState('');
    const [companyGstin, setCompanyGstin] = useState('');
    const [companyAddress, setCompanyAddress] = useState('');
    const [companyState, setCompanyState] = useState('Andhra Pradesh');
    const [bankName, setBankName] = useState('');
    const [bankAccount, setBankAccount] = useState('');
    const [bankIfsc, setBankIfsc] = useState('');

    const config = { headers: { Authorization: `Bearer ${token}` } };

    const fetchData = async () => {
        setLoading(true);
        try {
            const [txRes, compRes] = await Promise.allSettled([
                axios.get('/api/accounting/transactions', config),
                axios.get('/api/accounting/company', config)
            ]);

            if (txRes.status === 'fulfilled') setTransactions(txRes.value.data);
            if (compRes.status === 'fulfilled') {
                const c = compRes.value.data;
                setCompany(c);
                setCompanyName(c.companyName || '');
                setTradeName(c.tradeName || '');
                setCompanyGstin(c.gstin || '');
                setCompanyAddress(c.address || '');
                setCompanyState(c.state || '');
                if (c.bankDetails) {
                    setBankName(c.bankDetails.bankName || '');
                    setBankAccount(c.bankDetails.accountNumber || '');
                    setBankIfsc(c.bankDetails.ifscCode || '');
                }
            }
        } catch (error) {
            console.error('Error fetching bookkeeping data:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, []);

    const handleSaveCompany = async (e) => {
        e.preventDefault();
        try {
            const { data } = await axios.post('/api/accounting/company', {
                companyName,
                tradeName,
                gstin: companyGstin,
                address: companyAddress,
                state: companyState,
                bankDetails: {
                    bankName,
                    accountNumber: bankAccount,
                    ifscCode: bankIfsc
                }
            }, config);
            setCompany(data);
            setShowSettings(false);
            alert('Company details updated successfully!');
        } catch (error) {
            alert('Failed to update company settings: ' + (error.response?.data?.message || error.message));
        }
    };

    const handleAddItem = () => {
        setItems([...items, { description: '', hsnSac: '', qty: 1, rate: 0, gstRate: 18 }]);
    };

    const handleItemChange = (index, field, value) => {
        const updated = [...items];
        updated[index][field] = value;
        setItems(updated);
    };

    const handleRemoveItem = (index) => {
        if (items.length > 1) {
            setItems(items.filter((_, i) => i !== index));
        }
    };

    const handleAddTransaction = async (e) => {
        e.preventDefault();
        try {
            await axios.post('/api/accounting/transactions', {
                transactionType: txType,
                docNumber,
                docDate,
                partyName,
                partyGstin,
                placeOfSupply,
                isInterstate,
                itcEligibility: txType === 'Purchase' ? itcEligibility : 'N/A',
                notes,
                items
            }, config);

            // Reset form
            setDocNumber('');
            setPartyName('');
            setPartyGstin('');
            setNotes('');
            setItems([{ description: '', hsnSac: '', qty: 1, rate: 0, gstRate: 18 }]);
            setShowAddForm(false);
            fetchData();
        } catch (error) {
            alert('Failed to add transaction: ' + (error.response?.data?.message || error.message));
        }
    };

    const handleDeleteTransaction = async (id) => {
        if (window.confirm('Are you sure you want to delete this record?')) {
            try {
                await axios.delete(`/api/accounting/transactions/${id}`, config);
                fetchData();
            } catch (error) {
                alert('Failed to delete transaction');
            }
        }
    };

    const handleMockBillScan = () => {
        setUploadingBill(true);
        setTimeout(() => {
            // Mock OCR extraction
            setPartyName('Raju Gari Vendor Ltd');
            setPartyGstin('37AABCR1234F1Z5');
            setDocNumber('BILL-' + Math.floor(Math.random() * 10000));
            setDocDate(new Date().toISOString().split('T')[0]);
            setItems([
                { description: 'Consulting & Implementation Services', hsnSac: '9983', qty: 1, rate: 25000, gstRate: 18 }
            ]);
            setUploadingBill(false);
            alert('Bill successfully scanned! Form details filled out automatically.');
        }, 1500);
    };

    const handleDownloadTally = () => {
        window.open(`/api/accounting/export/tally?token=${token}`, '_blank');
    };

    const handleDownloadGstr = async () => {
        try {
            const { data } = await axios.get('/api/accounting/export/gstr1', config);
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
            const downloadAnchor = document.createElement('a');
            downloadAnchor.setAttribute("href",     dataStr);
            downloadAnchor.setAttribute("download", `GSTR1_Offline_${new Date().toISOString().slice(0,10)}.json`);
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
        } catch (error) {
            alert('Failed to generate GSTR1 offline file');
        }
    };

    const handleCopyShareLink = () => {
        const mockLink = `${window.location.origin}/invoice/view/${selectedInvoice._id}`;
        navigator.clipboard.writeText(mockLink);
        alert('Invoice share link copied to clipboard!');
    };

    // Calculate totals for dashboard cards
    const totalSales = transactions.filter(t => t.transactionType === 'Sales').reduce((acc, c) => acc + c.summary.totalAmount, 0);
    const totalPurchases = transactions.filter(t => t.transactionType === 'Purchase').reduce((acc, c) => acc + c.summary.totalAmount, 0);
    const totalExpenses = transactions.filter(t => t.transactionType === 'Expense').reduce((acc, c) => acc + c.summary.totalAmount, 0);
    const totalIncome = transactions.filter(t => t.transactionType === 'Income').reduce((acc, c) => acc + c.summary.totalAmount, 0);

    // Render printable GST invoice
    if (selectedInvoice) {
        const isSales = selectedInvoice.transactionType === 'Sales';
        return (
            <div className="space-y-6 pb-20 max-w-4xl mx-auto animate-in fade-in duration-300">
                <div className="flex justify-between items-center bg-white p-4 rounded-3xl border border-slate-200 sticky top-0 z-10 shadow-sm no-print">
                    <button 
                        onClick={() => setSelectedInvoice(null)} 
                        className="flex items-center gap-2 text-slate-600 font-bold text-sm hover:text-slate-900 transition"
                    >
                         ← Back to Ledger
                    </button>
                    <div className="flex gap-2">
                        <button 
                            onClick={handleCopyShareLink}
                            className="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2.5 rounded-xl font-bold text-xs flex items-center gap-1.5 transition"
                        >
                            <Share2 size={14} /> Copy Share Link
                        </button>
                        <button 
                            onClick={() => window.print()} 
                            className="bg-indigo-600 text-white px-5 py-2.5 rounded-xl font-bold text-xs hover:bg-indigo-700 transition flex items-center gap-1.5 shadow-lg shadow-indigo-100"
                        >
                            <Printer size={14} /> Print / Save PDF
                        </button>
                    </div>
                </div>

                {/* Standard GST Invoice Template */}
                <div className="bg-white p-8 md:p-12 rounded-[2.5rem] border border-slate-200 shadow-xl font-sans text-slate-800 printable-area">
                    {/* Header */}
                    <div className="flex justify-between items-start border-b-2 border-slate-800 pb-6 mb-8">
                        <div>
                            <h1 className="text-3xl font-black tracking-tight text-slate-900 leading-none">
                                {isSales ? (company?.companyName || 'TAX INVOICE') : (selectedInvoice.partyName)}
                            </h1>
                            <p className="text-xs font-black text-indigo-600 uppercase tracking-widest mt-1.5">
                                {isSales ? (company?.tradeName || 'GST Registered Supplier') : 'Supplier Vendor'}
                            </p>
                            
                            <div className="text-[11px] space-y-1 text-slate-500 font-medium mt-4">
                                <p>Address: {isSales ? (company?.address || 'N/A') : 'Refer to vendor records'}</p>
                                <p className="font-bold text-slate-800">GSTIN: {isSales ? (company?.gstin || 'N/A') : (selectedInvoice.partyGstin || 'N/A')}</p>
                                <p>State: {isSales ? (company?.state || 'N/A') : (selectedInvoice.placeOfSupply)}</p>
                            </div>
                        </div>

                        <div className="text-right">
                            <h2 className="text-2xl font-black text-slate-900 uppercase tracking-wide mb-1">
                                {isSales ? 'TAX INVOICE' : 'PURCHASE BILL'}
                            </h2>
                            <p className="text-xs font-bold text-slate-400">Invoice No: {selectedInvoice.docNumber}</p>
                            <p className="text-xs font-bold text-slate-500 mt-2">Date: {new Date(selectedInvoice.docDate).toLocaleDateString('en-IN')}</p>
                            <p className="text-[10px] font-black uppercase tracking-wider text-slate-400 bg-slate-100 px-2 py-1 rounded inline-block mt-3">
                                Pos: {selectedInvoice.placeOfSupply}
                            </p>
                        </div>
                    </div>

                    {/* Bill To */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
                        <div>
                            <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-2">Billed To (Recipient):</h3>
                            <p className="font-black text-slate-900 text-lg leading-none mb-2">
                                {isSales ? (selectedInvoice.partyName) : (company?.companyName || 'N/A')}
                            </p>
                            <p className="text-xs text-slate-600 leading-relaxed">
                                {isSales ? 'Recipient Client address' : (company?.address || 'N/A')}
                            </p>
                            <p className="text-xs font-bold text-slate-800 mt-2">
                                GSTIN: {isSales ? (selectedInvoice.partyGstin || 'N/A') : (company?.gstin || 'N/A')}
                            </p>
                        </div>

                        <div className="bg-slate-50 p-6 rounded-3xl border border-slate-100 flex flex-col justify-center gap-2 text-xs">
                            <div className="flex justify-between">
                                <span className="text-slate-400 font-bold uppercase text-[9px] tracking-wider">Place of Supply:</span>
                                <span className="font-bold text-slate-800">{selectedInvoice.placeOfSupply}</span>
                            </div>
                            <div className="flex justify-between">
                                <span className="text-slate-400 font-bold uppercase text-[9px] tracking-wider">Reverse Charge:</span>
                                <span className="font-bold text-slate-800">No</span>
                            </div>
                            {selectedInvoice.itcEligibility !== 'N/A' && (
                                <div className="flex justify-between">
                                    <span className="text-slate-400 font-bold uppercase text-[9px] tracking-wider">ITC Eligibility:</span>
                                    <span className="font-bold text-indigo-600">{selectedInvoice.itcEligibility}</span>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Table */}
                    <div className="overflow-x-auto mb-8">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-slate-900 text-white text-xs">
                                    <th className="p-3 font-bold rounded-l-xl">Description</th>
                                    <th className="p-3 font-bold text-center">HSN/SAC</th>
                                    <th className="p-3 font-bold text-center">Qty</th>
                                    <th className="p-3 font-bold text-right">Rate</th>
                                    <th className="p-3 font-bold text-right">CGST</th>
                                    <th className="p-3 font-bold text-right">SGST</th>
                                    <th className="p-3 font-bold text-right">IGST</th>
                                    <th className="p-3 font-bold text-right rounded-r-xl">Total</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100 text-xs">
                                {selectedInvoice.items.map((item, idx) => (
                                    <tr key={idx}>
                                        <td className="p-4 font-bold text-slate-900">{item.description}</td>
                                        <td className="p-4 text-center text-slate-500 font-bold">{item.hsnSac || '9999'}</td>
                                        <td className="p-4 text-center font-bold text-slate-800">{item.qty}</td>
                                        <td className="p-4 text-right font-medium">₹{item.rate.toLocaleString()}</td>
                                        <td className="p-4 text-right text-slate-600">₹{item.cgst.toLocaleString()} ({item.gstRate/2}%)</td>
                                        <td className="p-4 text-right text-slate-600">₹{item.sgst.toLocaleString()} ({item.gstRate/2}%)</td>
                                        <td className="p-4 text-right text-slate-600">₹{item.igst.toLocaleString()} ({item.gstRate}%)</td>
                                        <td className="p-4 text-right font-black text-slate-900">₹{item.amount.toLocaleString()}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>

                    {/* Totals */}
                    <div className="flex flex-col md:flex-row justify-between gap-6 border-t border-slate-100 pt-6">
                        <div className="space-y-4">
                            {company?.bankDetails?.accountNumber && (
                                <div className="p-4 bg-slate-50 border border-slate-100 rounded-2xl max-w-sm text-[11px]">
                                    <h4 className="font-black text-slate-800 mb-1.5 uppercase tracking-wide text-[9px]">Bank Details</h4>
                                    <p>Bank: {company.bankDetails.bankName}</p>
                                    <p>Account: {company.bankDetails.accountNumber}</p>
                                    <p>IFSC: {company.bankDetails.ifscCode}</p>
                                </div>
                            )}
                            <p className="text-[10px] text-slate-400 font-medium italic">Declaration: We declare that this invoice shows the actual price of the goods or services described and that all particulars are true and correct.</p>
                        </div>

                        <div className="w-80 space-y-3 text-sm">
                            <div className="flex justify-between">
                                <span className="font-bold text-slate-500">Taxable Subtotal:</span>
                                <span className="font-bold text-slate-900">₹{selectedInvoice.summary.totalTaxableValue.toLocaleString()}</span>
                            </div>
                            {selectedInvoice.summary.totalCgst > 0 && (
                                <div className="flex justify-between text-xs text-slate-600">
                                    <span>Central Tax (CGST):</span>
                                    <span>₹{selectedInvoice.summary.totalCgst.toLocaleString()}</span>
                                </div>
                            )}
                            {selectedInvoice.summary.totalSgst > 0 && (
                                <div className="flex justify-between text-xs text-slate-600">
                                    <span>State Tax (SGST):</span>
                                    <span>₹{selectedInvoice.summary.totalSgst.toLocaleString()}</span>
                                </div>
                            )}
                            {selectedInvoice.summary.totalIgst > 0 && (
                                <div className="flex justify-between text-xs text-slate-600">
                                    <span>Integrated Tax (IGST):</span>
                                    <span>₹{selectedInvoice.summary.totalIgst.toLocaleString()}</span>
                                </div>
                            )}
                            <div className="h-px bg-slate-200" />
                            <div className="flex justify-between text-lg">
                                <span className="font-black text-slate-900">Total Invoice Value:</span>
                                <span className="font-black text-indigo-600">₹{selectedInvoice.summary.totalAmount.toLocaleString()}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="space-y-8 pb-24 px-4 md:px-8 no-print">
            {/* Header */}
            <div className="flex justify-between items-center flex-wrap gap-4">
                <div>
                    <h2 className="text-3xl font-black text-slate-900 tracking-tight leading-none mb-2">Bookkeeping Hub</h2>
                    <p className="text-sm text-slate-500 font-medium">Record sales, purchases, income, and expenses for GST and bookkeeping.</p>
                </div>
                <div className="flex gap-2">
                    <button 
                        onClick={() => setShowSettings(true)}
                        className="bg-white text-slate-700 p-3 rounded-2xl border border-slate-300 hover:bg-slate-50 transition flex items-center gap-2 font-bold text-sm"
                    >
                        <Settings size={18} /> Company Settings
                    </button>
                    <button 
                        onClick={() => setShowAddForm(true)}
                        className="bg-indigo-600 text-white px-6 py-3 rounded-2xl hover:bg-indigo-700 transition flex items-center gap-2 font-bold text-sm shadow-lg shadow-indigo-100"
                    >
                        <Plus size={18} /> Add Entry
                    </button>
                </div>
            </div>

            {/* Dashboard Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm flex items-center justify-between">
                    <div className="space-y-2">
                        <p className="text-[10px] font-black uppercase text-slate-400 tracking-wider">Total Sales (Output)</p>
                        <h3 className="text-2xl font-black text-slate-800">₹{totalSales.toLocaleString()}</h3>
                    </div>
                    <div className="w-12 h-12 bg-emerald-50 text-emerald-600 rounded-2xl flex items-center justify-center">
                        <ArrowUpRight size={22} />
                    </div>
                </div>

                <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm flex items-center justify-between">
                    <div className="space-y-2">
                        <p className="text-[10px] font-black uppercase text-slate-400 tracking-wider">Total Purchases (ITC)</p>
                        <h3 className="text-2xl font-black text-slate-800">₹{totalPurchases.toLocaleString()}</h3>
                    </div>
                    <div className="w-12 h-12 bg-indigo-50 text-indigo-600 rounded-2xl flex items-center justify-center">
                        <ArrowDownLeft size={22} />
                    </div>
                </div>

                <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm flex items-center justify-between">
                    <div className="space-y-2">
                        <p className="text-[10px] font-black uppercase text-slate-400 tracking-wider">Other Income</p>
                        <h3 className="text-2xl font-black text-slate-800">₹{totalIncome.toLocaleString()}</h3>
                    </div>
                    <div className="w-12 h-12 bg-blue-50 text-blue-600 rounded-2xl flex items-center justify-center">
                        <DollarSign size={22} />
                    </div>
                </div>

                <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm flex items-center justify-between">
                    <div className="space-y-2">
                        <p className="text-[10px] font-black uppercase text-slate-400 tracking-wider">Expenses</p>
                        <h3 className="text-2xl font-black text-slate-800">₹{totalExpenses.toLocaleString()}</h3>
                    </div>
                    <div className="w-12 h-12 bg-rose-50 text-rose-600 rounded-2xl flex items-center justify-center">
                        <ArrowDownLeft size={22} className="rotate-180" />
                    </div>
                </div>
            </div>

            {/* Export options */}
            <div className="bg-slate-900 rounded-[2.5rem] p-8 text-white flex flex-col md:flex-row justify-between items-center gap-6 shadow-xl shadow-slate-200">
                <div className="space-y-2 text-center md:text-left">
                    <h3 className="text-lg font-black tracking-tight">Tally & GST Exporter</h3>
                    <p className="text-slate-400 text-xs font-medium">Download complete bookkeeping reports structured for direct imports and filings.</p>
                </div>
                <div className="flex gap-3 flex-wrap">
                    <button 
                        onClick={handleDownloadTally}
                        className="bg-white/10 text-white hover:bg-white/20 border border-white/10 px-5 py-3 rounded-2xl font-bold text-xs uppercase tracking-wider transition flex items-center gap-2"
                    >
                        <Download size={14} /> Tally XML Vouchers
                    </button>
                    <button 
                        onClick={handleDownloadGstr}
                        className="bg-emerald-600 hover:bg-emerald-500 text-white px-5 py-3 rounded-2xl font-bold text-xs uppercase tracking-wider transition flex items-center gap-2 shadow-lg shadow-emerald-900/20"
                    >
                        <FileCheck size={14} /> GSTR-1 JSON Offline tool
                    </button>
                </div>
            </div>

            {/* Transactions List */}
            <div className="bg-white rounded-[2.5rem] border border-slate-200 overflow-hidden shadow-xl shadow-slate-200/50">
                <div className="p-6 border-b border-slate-50 flex justify-between items-center">
                    <h3 className="font-black text-slate-800">Voucher list</h3>
                    <button onClick={fetchData} className="text-slate-400 hover:text-slate-600"><RefreshCw size={16} /></button>
                </div>

                {loading ? (
                    <div className="flex flex-col items-center justify-center py-20">
                        <div className="w-10 h-10 border-4 border-slate-200 border-t-indigo-600 rounded-full animate-spin mb-4"></div>
                        <p className="text-slate-400 text-xs font-bold uppercase tracking-wider">Loading Vouchers...</p>
                    </div>
                ) : transactions.length === 0 ? (
                    <div className="text-center py-20 text-slate-300">
                        <FileText size={48} className="mx-auto mb-4 opacity-30" />
                        <p className="font-bold">No accounting transactions found</p>
                        <p className="text-xs text-slate-400 mt-1">Configure company settings and record your first sales or purchases.</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-slate-50/50 text-slate-400">
                                    <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest">Type</th>
                                    <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest">Doc No</th>
                                    <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest">Date</th>
                                    <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest">Party Name</th>
                                    <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest">Taxable Value</th>
                                    <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest">Total Amount</th>
                                    <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest text-right">Action</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-50">
                                {transactions.map((tx) => (
                                    <tr key={tx._id} className="hover:bg-slate-50/80 transition group">
                                        <td className="px-8 py-5">
                                            <span className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wide ${
                                                tx.transactionType === 'Sales' ? 'bg-emerald-50 text-emerald-600' :
                                                tx.transactionType === 'Purchase' ? 'bg-indigo-50 text-indigo-600' :
                                                tx.transactionType === 'Income' ? 'bg-blue-50 text-blue-600' : 'bg-rose-50 text-rose-600'
                                            }`}>
                                                {tx.transactionType}
                                            </span>
                                        </td>
                                        <td className="px-8 py-5 font-bold text-slate-700">{tx.docNumber}</td>
                                        <td className="px-8 py-5 text-slate-500 font-medium">{new Date(tx.docDate).toLocaleDateString()}</td>
                                        <td className="px-8 py-5 font-bold text-slate-700">{tx.partyName}</td>
                                        <td className="px-8 py-5 font-semibold text-slate-600">₹{tx.summary.totalTaxableValue.toLocaleString()}</td>
                                        <td className="px-8 py-5 font-black text-slate-900">₹{tx.summary.totalAmount.toLocaleString()}</td>
                                        <td className="px-8 py-5 text-right space-x-1">
                                            <button 
                                                onClick={() => setSelectedInvoice(tx)}
                                                className="text-indigo-600 hover:text-indigo-800 p-2 rounded-xl hover:bg-indigo-50 transition inline-flex items-center"
                                                title="View Standard GST Invoice"
                                            >
                                                <Eye size={16} />
                                            </button>
                                            <button 
                                                onClick={() => handleDeleteTransaction(tx._id)}
                                                className="text-rose-500 hover:text-rose-700 p-2 rounded-xl hover:bg-rose-50 transition inline-flex items-center"
                                            >
                                                <Trash2 size={16} />
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* ADD TRANSACTION MODAL */}
            {showAddForm && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex justify-end animate-in fade-in duration-300">
                    <div className="bg-white w-full max-w-2xl h-full shadow-2xl overflow-y-auto flex flex-col p-8 animate-in slide-in-from-right duration-500">
                        <div className="flex justify-between items-center mb-8 border-b border-slate-100 pb-4">
                            <div>
                                <h3 className="text-xl font-black text-slate-900">Record New Transaction</h3>
                                <p className="text-slate-400 text-xs font-semibold">Enter transaction and items details manually or scan from photo.</p>
                            </div>
                            <button onClick={() => setShowAddForm(false)} className="text-slate-400 hover:text-slate-600">
                                <X size={24} />
                            </button>
                        </div>

                        {/* Scanner / Upload triggers */}
                        {txType === 'Purchase' && (
                            <div className="mb-6 p-4 bg-indigo-50 border border-indigo-100 rounded-2xl flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 bg-white rounded-xl flex items-center justify-center text-indigo-600">
                                        <Camera size={20} />
                                    </div>
                                    <div>
                                        <h4 className="font-black text-slate-800 text-xs">Fast Upload & Auto-Scan</h4>
                                        <p className="text-slate-400 text-[10px] font-bold uppercase">Extract details from vendor bills immediately</p>
                                    </div>
                                </div>
                                <button 
                                    type="button" 
                                    onClick={handleMockBillScan}
                                    disabled={uploadingBill}
                                    className="bg-indigo-600 text-white px-4 py-2 rounded-xl text-xs font-bold hover:bg-indigo-700 transition"
                                >
                                    {uploadingBill ? 'Scanning...' : 'Upload & Scan'}
                                </button>
                            </div>
                        )}

                        <form onSubmit={handleAddTransaction} className="space-y-6 flex-1">
                            {/* Transaction Type */}
                            <div className="grid grid-cols-4 gap-2 bg-slate-100 p-1 rounded-2xl">
                                {['Sales', 'Purchase', 'Income', 'Expense'].map(type => (
                                    <button 
                                        key={type}
                                        type="button"
                                        onClick={() => setTxType(type)}
                                        className={`py-2 rounded-xl text-xs font-black uppercase tracking-wider transition ${txType === type ? 'bg-white text-slate-950 shadow-sm' : 'text-slate-500'}`}
                                    >
                                        {type}
                                    </button>
                                ))}
                            </div>

                            {/* Main Document Details */}
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                <div className="space-y-1">
                                    <label className="text-[10px] font-black uppercase text-slate-400 tracking-wider">Document Number / Invoice No</label>
                                    <input 
                                        type="text" 
                                        value={docNumber} 
                                        onChange={e => setDocNumber(e.target.value)} 
                                        className="w-full bg-white border border-slate-300 rounded-xl px-4 py-3 text-sm font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600"
                                        required 
                                    />
                                </div>
                                <div className="space-y-1">
                                    <label className="text-[10px] font-black uppercase text-slate-400 tracking-wider">Document Date</label>
                                    <input 
                                        type="date" 
                                        value={docDate} 
                                        onChange={e => setDocDate(e.target.value)} 
                                        className="w-full bg-white border border-slate-300 rounded-xl px-4 py-3 text-sm font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600"
                                        required 
                                    />
                                </div>
                            </div>

                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                <div className="space-y-1">
                                    <label className="text-[10px] font-black uppercase text-slate-400 tracking-wider">{txType === 'Sales' ? 'Customer Name' : 'Vendor / Supplier Name'}</label>
                                    <input 
                                        type="text" 
                                        value={partyName} 
                                        onChange={e => setPartyName(e.target.value)} 
                                        className="w-full bg-white border border-slate-300 rounded-xl px-4 py-3 text-sm font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600"
                                        required 
                                    />
                                </div>
                                <div className="space-y-1">
                                    <label className="text-[10px] font-black uppercase text-slate-400 tracking-wider">GSTIN (Optional)</label>
                                    <input 
                                        type="text" 
                                        value={partyGstin} 
                                        onChange={e => setPartyGstin(e.target.value)} 
                                        maxLength={15}
                                        placeholder="e.g. 37AABCR1234F1Z5"
                                        className="w-full bg-white border border-slate-300 rounded-xl px-4 py-3 text-sm font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600 uppercase"
                                    />
                                </div>
                            </div>

                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                <div className="space-y-1">
                                    <label className="text-[10px] font-black uppercase text-slate-400 tracking-wider">Place of Supply (State)</label>
                                    <select 
                                        value={placeOfSupply} 
                                        onChange={e => setPlaceOfSupply(e.target.value)}
                                        className="w-full bg-white border border-slate-300 rounded-xl px-4 py-3 text-sm font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600"
                                    >
                                        <option value="Andhra Pradesh">Andhra Pradesh</option>
                                        <option value="Telangana">Telangana</option>
                                        <option value="Karnataka">Karnataka</option>
                                        <option value="Tamil Nadu">Tamil Nadu</option>
                                        <option value="Maharashtra">Maharashtra</option>
                                        <option value="Delhi">Delhi</option>
                                    </select>
                                </div>
                                <div className="flex items-center gap-3 pt-6">
                                    <input 
                                        type="checkbox" 
                                        id="interstate"
                                        checked={isInterstate} 
                                        onChange={e => setIsInterstate(e.target.checked)} 
                                        className="w-4 h-4 text-indigo-600 focus:ring-indigo-500 border-slate-300 rounded"
                                    />
                                    <label htmlFor="interstate" className="text-xs font-black text-slate-700 uppercase tracking-wide">Is Interstate Transaction (IGST)?</label>
                                </div>
                            </div>

                            {/* Item Lines */}
                            <div className="space-y-3">
                                <div className="flex justify-between items-center border-t border-slate-50 pt-4">
                                    <h4 className="font-black text-slate-800 text-sm">Line Items</h4>
                                    <button 
                                        type="button" 
                                        onClick={handleAddItem}
                                        className="text-xs font-bold text-indigo-600 flex items-center gap-1"
                                    >
                                        + Add Item
                                    </button>
                                </div>

                                {items.map((item, idx) => (
                                    <div key={idx} className="bg-slate-50 p-4 rounded-2xl border border-slate-200 space-y-3 relative group">
                                        {items.length > 1 && (
                                            <button 
                                                type="button" 
                                                onClick={() => handleRemoveItem(idx)}
                                                className="absolute top-2 right-2 text-rose-500 hover:text-rose-700"
                                            >
                                                <X size={16} />
                                            </button>
                                        )}
                                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                            <div className="space-y-1">
                                                <label className="text-[9px] font-black uppercase text-slate-400 tracking-wider">Item Description</label>
                                                <input 
                                                    type="text" 
                                                    value={item.description} 
                                                    onChange={e => handleItemChange(idx, 'description', e.target.value)} 
                                                    className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600"
                                                    required 
                                                />
                                            </div>
                                            <div className="space-y-1">
                                                <label className="text-[9px] font-black uppercase text-slate-400 tracking-wider">HSN/SAC Code</label>
                                                <input 
                                                    type="text" 
                                                    value={item.hsnSac} 
                                                    onChange={e => handleItemChange(idx, 'hsnSac', e.target.value)} 
                                                    className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600"
                                                />
                                            </div>
                                        </div>

                                        <div className="grid grid-cols-3 gap-2">
                                            <div className="space-y-1">
                                                <label className="text-[9px] font-black uppercase text-slate-400 tracking-wider">Qty</label>
                                                <input 
                                                    type="number" 
                                                    value={item.qty} 
                                                    onChange={e => handleItemChange(idx, 'qty', parseInt(e.target.value) || 0)} 
                                                    className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600"
                                                    min="1"
                                                    required 
                                                />
                                            </div>
                                            <div className="space-y-1">
                                                <label className="text-[9px] font-black uppercase text-slate-400 tracking-wider">Rate (₹)</label>
                                                <input 
                                                    type="number" 
                                                    value={item.rate} 
                                                    onChange={e => handleItemChange(idx, 'rate', parseFloat(e.target.value) || 0)} 
                                                    className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600"
                                                    min="0"
                                                    required 
                                                />
                                            </div>
                                            <div className="space-y-1">
                                                <label className="text-[9px] font-black uppercase text-slate-400 tracking-wider">GST Rate (%)</label>
                                                <select 
                                                    value={item.gstRate} 
                                                    onChange={e => handleItemChange(idx, 'gstRate', parseInt(e.target.value) || 0)}
                                                    className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600"
                                                >
                                                    <option value="0">0%</option>
                                                    <option value="5">5%</option>
                                                    <option value="12">12%</option>
                                                    <option value="18">18%</option>
                                                    <option value="28">28%</option>
                                                </select>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>

                            <button 
                                type="submit" 
                                className="w-full bg-indigo-600 text-white py-3.5 rounded-2xl font-bold text-sm hover:bg-indigo-700 transition shadow-lg shadow-indigo-100 mt-6"
                            >
                                Record Transaction
                            </button>
                        </form>
                    </div>
                </div>
            )}

            {/* COMPANY SETTINGS MODAL */}
            {showSettings && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in duration-300">
                    <div className="bg-white w-full max-w-lg rounded-[2.5rem] p-8 shadow-2xl relative overflow-y-auto max-h-[90vh] animate-in zoom-in-95 duration-500">
                        <button onClick={() => setShowSettings(false)} className="absolute top-6 right-6 text-slate-400 hover:text-slate-600">
                            <X size={20} />
                        </button>
                        <h3 className="text-xl font-black text-slate-900 mb-6">Company Bookkeeping Profile</h3>
                        
                        <form onSubmit={handleSaveCompany} className="space-y-4">
                            <div className="space-y-1">
                                <label className="text-[10px] font-black uppercase text-slate-400 tracking-wider">Legal Business Name</label>
                                <input 
                                    type="text" 
                                    value={companyName} 
                                    onChange={e => setCompanyName(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-4 py-2.5 text-sm font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600"
                                    required 
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="text-[10px] font-black uppercase text-slate-400 tracking-wider">Trade Name / Brand (Optional)</label>
                                <input 
                                    type="text" 
                                    value={tradeName} 
                                    onChange={e => setTradeName(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-4 py-2.5 text-sm font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600"
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="text-[10px] font-black uppercase text-slate-400 tracking-wider">Company GSTIN</label>
                                <input 
                                    type="text" 
                                    value={companyGstin} 
                                    onChange={e => setCompanyGstin(e.target.value)} 
                                    maxLength={15}
                                    className="w-full bg-white border border-slate-300 rounded-xl px-4 py-2.5 text-sm font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600 uppercase"
                                    required 
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="text-[10px] font-black uppercase text-slate-400 tracking-wider">Billing Address</label>
                                <textarea 
                                    value={companyAddress} 
                                    onChange={e => setCompanyAddress(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-4 py-2.5 text-sm font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600"
                                    rows="2"
                                    required 
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="text-[10px] font-black uppercase text-slate-400 tracking-wider">State</label>
                                <select 
                                    value={companyState} 
                                    onChange={e => setCompanyState(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-4 py-2.5 text-sm font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600"
                                >
                                    <option value="Andhra Pradesh">Andhra Pradesh</option>
                                    <option value="Telangana">Telangana</option>
                                    <option value="Karnataka">Karnataka</option>
                                    <option value="Tamil Nadu">Tamil Nadu</option>
                                    <option value="Maharashtra">Maharashtra</option>
                                    <option value="Delhi">Delhi</option>
                                </select>
                            </div>

                            {/* Bank Details */}
                            <div className="border-t border-slate-100 pt-4 space-y-3">
                                <h4 className="font-black text-slate-800 text-xs uppercase tracking-wide">Bank Details (For Invoicing)</h4>
                                <div className="grid grid-cols-2 gap-2">
                                    <input 
                                        type="text" 
                                        placeholder="Bank Name" 
                                        value={bankName} 
                                        onChange={e => setBankName(e.target.value)} 
                                        className="w-full bg-white border border-slate-300 rounded-xl px-4 py-2 text-xs font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600"
                                    />
                                    <input 
                                        type="text" 
                                        placeholder="Account Number" 
                                        value={bankAccount} 
                                        onChange={e => setBankAccount(e.target.value)} 
                                        className="w-full bg-white border border-slate-300 rounded-xl px-4 py-2 text-xs font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600"
                                    />
                                </div>
                                <input 
                                    type="text" 
                                    placeholder="IFSC Code" 
                                    value={bankIfsc} 
                                    onChange={e => setBankIfsc(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-4 py-2 text-xs font-bold text-slate-800 focus:outline-none focus:border-indigo-600 focus:ring-1 focus:ring-indigo-600 uppercase"
                                />
                            </div>

                            <button 
                                type="submit" 
                                className="w-full bg-indigo-600 text-white py-3 rounded-xl font-bold text-sm hover:bg-indigo-700 transition"
                            >
                                Save Settings
                            </button>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default BookkeepingView;
