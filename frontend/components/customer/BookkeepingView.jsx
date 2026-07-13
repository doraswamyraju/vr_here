import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    Plus, Settings, Download, FileText, Trash2, 
    ArrowUpRight, ArrowDownLeft, DollarSign, RefreshCw, X, Eye, 
    Upload, Camera, Check, FileCheck, CheckCircle, Printer, Share2, Search, Calendar, Filter, MoreVertical
} from 'lucide-react';

const BookkeepingView = ({ token }) => {
    const [transactions, setTransactions] = useState([]);
    const [company, setCompany] = useState(null);
    const [loading, setLoading] = useState(true);
    const [showAddForm, setShowAddForm] = useState(false);
    const [showSettings, setShowSettings] = useState(false);
    const [selectedInvoice, setSelectedInvoice] = useState(null);

    // Filtering states
    const [filterType, setFilterType] = useState('All'); // 'All' | 'Sales' | 'Purchase' | 'Income' | 'Expense'
    const [searchQuery, setSearchQuery] = useState('');

    // Form states
    const [txType, setTxType] = useState('Sales'); // 'Sales' | 'Purchase'
    const [docNumber, setDocNumber] = useState('');
    const [docDate, setDocDate] = useState(new Date().toISOString().split('T')[0]);
    const [partyName, setPartyName] = useState('');
    const [partyGstin, setPartyGstin] = useState('');
    const [placeOfSupply, setPlaceOfSupply] = useState('Andhra Pradesh');
    const [isInterstate, setIsInterstate] = useState(false);
    const [notes, setNotes] = useState('');
    const [paymentType, setPaymentType] = useState('Cash');
    
    // Vyapar style table items
    const [items, setItems] = useState([
        { description: '', qty: 1, unit: 'NONE', rate: 0, discountPercent: 0, gstRate: 18 }
    ]);

    // Company Settings
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

    // Set automatic invoice number
    useEffect(() => {
        if (showAddForm) {
            const prefix = txType === 'Sales' ? '270326' : 'BILL-';
            const count = transactions.filter(t => t.transactionType === txType).length + 1;
            const paddedCount = String(count).padStart(4, '0');
            setDocNumber(`${prefix}${paddedCount}`);
        }
    }, [showAddForm, txType, transactions]);

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
        setItems([...items, { description: '', qty: 1, unit: 'NONE', rate: 0, discountPercent: 0, gstRate: 18 }]);
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
            // Map Vyapar items format to backend Transaction items format
            const mappedItems = items.map(item => {
                const discountAmount = Number(item.qty * item.rate * (item.discountPercent / 100));
                const taxableVal = Number((item.qty * item.rate) - discountAmount);
                const gstAmt = Number(taxableVal * (item.gstRate / 100));
                
                return {
                    description: item.description,
                    hsnSac: '9999',
                    qty: item.qty,
                    rate: item.rate,
                    gstRate: item.gstRate,
                    discount: discountAmount,
                    cgst: isInterstate ? 0 : gstAmt / 2,
                    sgst: isInterstate ? 0 : gstAmt / 2,
                    igst: isInterstate ? gstAmt : 0,
                    amount: taxableVal + gstAmt
                };
            });

            await axios.post('/api/accounting/transactions', {
                transactionType: txType,
                docNumber,
                docDate,
                partyName,
                partyGstin,
                placeOfSupply,
                isInterstate,
                notes,
                items: mappedItems
            }, config);

            setPartyName('');
            setPartyGstin('');
            setNotes('');
            setItems([{ description: '', qty: 1, unit: 'NONE', rate: 0, discountPercent: 0, gstRate: 18 }]);
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

    const handleCopyShareLink = () => {
        const mockLink = `${window.location.origin}/invoice/view/${selectedInvoice._id}`;
        navigator.clipboard.writeText(mockLink);
        alert('Invoice share link copied to clipboard!');
    };

    const filteredTransactions = transactions.filter(t => {
        if (filterType !== 'All' && t.transactionType !== filterType) return false;
        if (searchQuery) {
            const query = searchQuery.toLowerCase();
            return t.partyName.toLowerCase().includes(query) || t.docNumber.toLowerCase().includes(query);
        }
        return true;
    });

    // Totals calculations
    const totalSales = transactions.filter(t => t.transactionType === 'Sales').reduce((acc, c) => acc + c.summary.totalAmount, 0);
    const totalPurchases = transactions.filter(t => t.transactionType === 'Purchase').reduce((acc, c) => acc + c.summary.totalAmount, 0);

    // Render GST Invoice View
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

                {/* GST Invoice visual layout */}
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
                        </div>
                    </div>

                    {/* Bill To */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
                        <div>
                            <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-2">Billed To (Recipient):</h3>
                            <p className="font-black text-slate-900 text-lg leading-none mb-2">
                                {isSales ? (selectedInvoice.partyName) : (company?.companyName || 'N/A')}
                            </p>
                            <p className="text-xs font-bold text-slate-800">
                                GSTIN: {isSales ? (selectedInvoice.partyGstin || 'N/A') : (company?.gstin || 'N/A')}
                            </p>
                        </div>

                        <div className="bg-slate-50 p-4 rounded-2xl border border-slate-100 flex flex-col justify-center gap-2 text-xs">
                            <div className="flex justify-between">
                                <span className="text-slate-400 font-bold uppercase text-[9px]">Place of Supply:</span>
                                <span className="font-bold text-slate-800">{selectedInvoice.placeOfSupply}</span>
                            </div>
                        </div>
                    </div>

                    {/* Table */}
                    <div className="overflow-x-auto mb-8">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-slate-900 text-white text-xs">
                                    <th className="p-3 font-bold rounded-l-xl">Description</th>
                                    <th className="p-3 font-bold text-center">Qty</th>
                                    <th className="p-3 font-bold text-right">Rate</th>
                                    <th className="p-3 font-bold text-right">Tax (%)</th>
                                    <th className="p-3 font-bold text-right rounded-r-xl">Total</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100 text-xs">
                                {selectedInvoice.items.map((item, idx) => (
                                    <tr key={idx}>
                                        <td className="p-4 font-bold text-slate-900">{item.description}</td>
                                        <td className="p-4 text-center font-bold text-slate-800">{item.qty}</td>
                                        <td className="p-4 text-right font-medium">₹{item.rate.toLocaleString()}</td>
                                        <td className="p-4 text-right text-slate-600">{item.gstRate}%</td>
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
                        </div>

                        <div className="w-80 space-y-3 text-sm">
                            <div className="flex justify-between">
                                <span className="font-bold text-slate-500">Taxable Subtotal:</span>
                                <span className="font-bold text-slate-900">₹{selectedInvoice.summary.totalTaxableValue.toLocaleString()}</span>
                            </div>
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
        <div className="space-y-6 pb-24 px-4 md:px-8">
            {/* Vyapar style sub topbar */}
            <div className="flex justify-between items-center border-b border-slate-200 pb-4 flex-wrap gap-4">
                <div className="flex items-center gap-4">
                    <h2 className="text-xl font-bold text-slate-800">
                        {filterType === 'Sales' ? 'Sale Invoices' : filterType === 'Purchase' ? 'Purchase Bills' : 'Transactions'}
                    </h2>
                    <select 
                        value={filterType} 
                        onChange={e => setFilterType(e.target.value)}
                        className="bg-white border border-slate-300 rounded-xl px-3 py-1.5 text-xs font-semibold focus:outline-none"
                    >
                        <option value="All">All Transactions</option>
                        <option value="Sales">Sale Invoices</option>
                        <option value="Purchase">Purchase Bills</option>
                    </select>
                </div>
                
                <div className="flex gap-2">
                    <button 
                        onClick={() => setShowSettings(true)}
                        className="bg-white text-slate-700 px-4 py-2 rounded-xl border border-slate-300 hover:bg-slate-50 transition flex items-center gap-1.5 font-bold text-xs"
                    >
                        <Settings size={14} /> Company Settings
                    </button>
                    <button 
                        onClick={() => { setTxType('Sales'); setShowAddForm(true); }}
                        className="bg-red-500 text-white px-5 py-2.5 rounded-xl hover:bg-red-600 transition flex items-center gap-1 font-bold text-xs shadow-md shadow-red-100"
                    >
                        <Plus size={14} /> Add Sale
                    </button>
                    <button 
                        onClick={() => { setTxType('Purchase'); setShowAddForm(true); }}
                        className="bg-blue-600 text-white px-5 py-2.5 rounded-xl hover:bg-blue-700 transition flex items-center gap-1 font-bold text-xs shadow-md shadow-blue-100"
                    >
                        <Plus size={14} /> Add Purchase
                    </button>
                </div>
            </div>

            {/* Vyapar style summary cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-white border border-slate-200 p-5 rounded-2xl shadow-sm flex flex-col justify-center">
                    <span className="text-slate-400 text-[10px] uppercase font-black tracking-wider">Total Sales Amount</span>
                    <span className="text-xl font-bold text-emerald-600 mt-1">₹{totalSales.toLocaleString()}</span>
                </div>
                <div className="bg-white border border-slate-200 p-5 rounded-2xl shadow-sm flex flex-col justify-center">
                    <span className="text-slate-400 text-[10px] uppercase font-black tracking-wider">Total Purchases Amount</span>
                    <span className="text-xl font-bold text-blue-600 mt-1">₹{totalPurchases.toLocaleString()}</span>
                </div>
                <div className="bg-white border border-slate-200 p-5 rounded-2xl shadow-sm flex flex-col justify-center">
                    <span className="text-slate-400 text-[10px] uppercase font-black tracking-wider">Net Balance</span>
                    <span className={`text-xl font-bold mt-1 ${totalSales - totalPurchases >= 0 ? 'text-emerald-600' : 'text-rose-600'}`}>
                        ₹{(totalSales - totalPurchases).toLocaleString()}
                    </span>
                </div>
            </div>

            {/* Table Search & Filters bar */}
            <div className="flex justify-between items-center gap-4 bg-white p-3 rounded-2xl border border-slate-200 flex-wrap">
                <div className="relative flex-1 max-w-md">
                    <Search className="absolute left-3.5 top-2.5 text-slate-400" size={16} />
                    <input 
                        type="text" 
                        placeholder="Search Transactions..."
                        value={searchQuery}
                        onChange={e => setSearchQuery(e.target.value)}
                        className="w-full bg-slate-50 border border-slate-300 rounded-xl pl-10 pr-4 py-2 text-xs focus:outline-none focus:bg-white"
                    />
                </div>
                <div className="flex gap-2 text-xs">
                    <button className="flex items-center gap-1 border border-slate-300 px-3 py-2 rounded-xl bg-white hover:bg-slate-50">
                        <Calendar size={14} /> Filter Date
                    </button>
                    <button onClick={fetchData} className="flex items-center gap-1 border border-slate-300 px-3 py-2 rounded-xl bg-white hover:bg-slate-50">
                        <RefreshCw size={14} /> Refresh
                    </button>
                </div>
            </div>

            {/* Ledger List */}
            <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
                {loading ? (
                    <div className="flex justify-center py-20">
                        <div className="w-8 h-8 border-4 border-slate-200 border-t-indigo-600 rounded-full animate-spin"></div>
                    </div>
                ) : filteredTransactions.length === 0 ? (
                    <div className="text-center py-20 text-slate-300">
                        <FileText size={48} className="mx-auto mb-3 opacity-30" />
                        <p className="font-bold text-sm text-slate-500">No records found</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse text-xs">
                            <thead>
                                <tr className="bg-slate-50/80 text-slate-500 font-bold border-b border-slate-200">
                                    <th className="px-6 py-4">Date</th>
                                    <th className="px-6 py-4">Invoice No</th>
                                    <th className="px-6 py-4">Party Name</th>
                                    <th className="px-6 py-4">Transaction</th>
                                    <th className="px-6 py-4">Amount</th>
                                    <th className="px-6 py-4 text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {filteredTransactions.map(tx => (
                                    <tr key={tx._id} className="hover:bg-slate-50/50 transition">
                                        <td className="px-6 py-4 text-slate-600">{new Date(tx.docDate).toLocaleDateString()}</td>
                                        <td className="px-6 py-4 font-bold text-slate-800">{tx.docNumber}</td>
                                        <td className="px-6 py-4 text-slate-700 font-medium">{tx.partyName}</td>
                                        <td className="px-6 py-4">
                                            <span className={`px-2.5 py-0.5 rounded-full text-[9px] font-bold ${
                                                tx.transactionType === 'Sales' ? 'bg-emerald-50 text-emerald-600' : 'bg-blue-50 text-blue-600'
                                            }`}>
                                                {tx.transactionType === 'Sales' ? 'Sale' : 'Purchase'}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 font-bold text-slate-900">₹{tx.summary.totalAmount.toLocaleString()}</td>
                                        <td className="px-6 py-4 text-right space-x-1">
                                            <button 
                                                onClick={() => setSelectedInvoice(tx)}
                                                className="text-indigo-600 hover:bg-indigo-50 p-2 rounded-lg transition"
                                                title="View Standard GST Invoice"
                                            >
                                                <Eye size={14} />
                                            </button>
                                            <button 
                                                onClick={() => handleDeleteTransaction(tx._id)}
                                                className="text-rose-500 hover:bg-rose-50 p-2 rounded-lg transition"
                                            >
                                                <Trash2 size={14} />
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* ADD TRANSACTION FORM MODAL */}
            {showAddForm && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex justify-center items-center p-4 animate-in fade-in duration-300">
                    <div className="bg-white w-full max-w-5xl rounded-3xl shadow-2xl overflow-y-auto max-h-[90vh] flex flex-col p-6 animate-in zoom-in-95 duration-300">
                        <div className="flex justify-between items-center mb-6 border-b border-slate-200 pb-3">
                            <h3 className="text-base font-bold text-slate-800">
                                Add {txType === 'Sales' ? 'Sale Invoice' : 'Purchase Bill'}
                            </h3>
                            <button onClick={() => setShowAddForm(false)} className="text-slate-400 hover:text-slate-600">
                                <X size={20} />
                            </button>
                        </div>

                        <form onSubmit={handleAddTransaction} className="space-y-6 flex-1 text-xs">
                            {/* Top info section */}
                            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 bg-slate-50 p-4 rounded-2xl border border-slate-200">
                                <div className="space-y-1">
                                    <label className="font-bold text-slate-600">Customer Name *</label>
                                    <input 
                                        type="text" 
                                        value={partyName} 
                                        onChange={e => setPartyName(e.target.value)} 
                                        placeholder="Enter customer name"
                                        className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none focus:border-indigo-600"
                                        required 
                                    />
                                </div>
                                <div className="space-y-1">
                                    <label className="font-bold text-slate-600">Invoice Number (Auto)</label>
                                    <input 
                                        type="text" 
                                        value={docNumber} 
                                        className="w-full bg-slate-100 border border-slate-200 rounded-xl px-3 py-2 text-xs text-slate-500 font-bold focus:outline-none"
                                        readOnly
                                    />
                                </div>
                                <div className="space-y-1">
                                    <label className="font-bold text-slate-600">Invoice Date *</label>
                                    <input 
                                        type="date" 
                                        value={docDate} 
                                        onChange={e => setDocDate(e.target.value)} 
                                        className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                        required 
                                    />
                                </div>
                                <div className="space-y-1">
                                    <label className="font-bold text-slate-600">State of Supply</label>
                                    <select 
                                        value={placeOfSupply} 
                                        onChange={e => setPlaceOfSupply(e.target.value)}
                                        className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                    >
                                        <option value="Andhra Pradesh">Andhra Pradesh</option>
                                        <option value="Telangana">Telangana</option>
                                        <option value="Karnataka">Karnataka</option>
                                        <option value="Tamil Nadu">Tamil Nadu</option>
                                        <option value="Maharashtra">Maharashtra</option>
                                        <option value="Delhi">Delhi</option>
                                    </select>
                                </div>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div className="space-y-1">
                                    <label className="font-bold text-slate-600">GSTIN (Optional)</label>
                                    <input 
                                        type="text" 
                                        value={partyGstin} 
                                        onChange={e => setPartyGstin(e.target.value)} 
                                        maxLength={15}
                                        placeholder="e.g. 37AABCR1234F1Z5"
                                        className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none uppercase"
                                    />
                                </div>
                                <div className="flex items-center gap-2 pt-5">
                                    <input 
                                        type="checkbox" 
                                        id="interstate"
                                        checked={isInterstate} 
                                        onChange={e => setIsInterstate(e.target.checked)} 
                                        className="w-4 h-4 text-indigo-600 border-slate-300 rounded focus:ring-0"
                                    />
                                    <label htmlFor="interstate" className="font-bold text-slate-600">Interstate Transaction (IGST)?</label>
                                </div>
                            </div>

                            {/* Vyapar style table items grid */}
                            <div className="border border-slate-200 rounded-2xl overflow-hidden">
                                <table className="w-full text-left border-collapse text-xs">
                                    <thead>
                                        <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-bold">
                                            <th className="p-3 w-10 text-center">#</th>
                                            <th className="p-3">ITEM DESCRIPTION</th>
                                            <th className="p-3 w-20">QTY</th>
                                            <th className="p-3 w-24">UNIT</th>
                                            <th className="p-3 w-32">PRICE/UNIT</th>
                                            <th className="p-3 w-24">DISCOUNT (%)</th>
                                            <th className="p-3 w-28">TAX (%)</th>
                                            <th className="p-3 w-10"></th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-200">
                                        {items.map((item, idx) => (
                                            <tr key={idx} className="bg-white hover:bg-slate-50/30">
                                                <td className="p-3 text-center text-slate-400 font-bold">{idx + 1}</td>
                                                <td className="p-3">
                                                    <input 
                                                        type="text" 
                                                        value={item.description} 
                                                        onChange={e => handleItemChange(idx, 'description', e.target.value)} 
                                                        placeholder="Item Name"
                                                        className="w-full bg-transparent border-b border-slate-200 focus:border-indigo-600 py-1 focus:outline-none"
                                                        required 
                                                    />
                                                </td>
                                                <td className="p-3">
                                                    <input 
                                                        type="number" 
                                                        value={item.qty} 
                                                        onChange={e => handleItemChange(idx, 'qty', parseInt(e.target.value) || 0)} 
                                                        className="w-full bg-transparent border-b border-slate-200 focus:border-indigo-600 py-1 focus:outline-none text-center"
                                                        min="1"
                                                        required 
                                                    />
                                                </td>
                                                <td className="p-3">
                                                    <select 
                                                        value={item.unit}
                                                        onChange={e => handleItemChange(idx, 'unit', e.target.value)}
                                                        className="w-full bg-transparent border-b border-slate-200 focus:border-indigo-600 py-1 focus:outline-none"
                                                    >
                                                        <option value="NONE">NONE</option>
                                                        <option value="BOX">BOX</option>
                                                        <option value="PCS">PCS</option>
                                                        <option value="KGS">KGS</option>
                                                    </select>
                                                </td>
                                                <td className="p-3">
                                                    <input 
                                                        type="number" 
                                                        value={item.rate} 
                                                        onChange={e => handleItemChange(idx, 'rate', parseFloat(e.target.value) || 0)} 
                                                        className="w-full bg-transparent border-b border-slate-200 focus:border-indigo-600 py-1 focus:outline-none"
                                                        min="0"
                                                        required 
                                                    />
                                                </td>
                                                <td className="p-3">
                                                    <input 
                                                        type="number" 
                                                        value={item.discountPercent} 
                                                        onChange={e => handleItemChange(idx, 'discountPercent', parseFloat(e.target.value) || 0)} 
                                                        className="w-full bg-transparent border-b border-slate-200 focus:border-indigo-600 py-1 focus:outline-none text-center"
                                                        min="0"
                                                        max="100"
                                                    />
                                                </td>
                                                <td className="p-3">
                                                    <select 
                                                        value={item.gstRate} 
                                                        onChange={e => handleItemChange(idx, 'gstRate', parseInt(e.target.value) || 0)}
                                                        className="w-full bg-transparent border-b border-slate-200 focus:border-indigo-600 py-1 focus:outline-none"
                                                    >
                                                        <option value="0">0%</option>
                                                        <option value="5">5%</option>
                                                        <option value="12">12%</option>
                                                        <option value="18">18%</option>
                                                        <option value="28">28%</option>
                                                    </select>
                                                </td>
                                                <td className="p-3 text-center">
                                                    {items.length > 1 && (
                                                        <button 
                                                            type="button" 
                                                            onClick={() => handleRemoveItem(idx)}
                                                            className="text-rose-500 hover:text-rose-700"
                                                        >
                                                            <X size={14} />
                                                        </button>
                                                    )}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                                <div className="p-3 bg-slate-50 border-t border-slate-200">
                                    <button 
                                        type="button" 
                                        onClick={handleAddItem}
                                        className="bg-white border border-slate-300 rounded-xl px-4 py-2 font-bold hover:bg-slate-100 transition"
                                    >
                                        + ADD ROW
                                    </button>
                                </div>
                            </div>

                            {/* Terms and Payment options */}
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-4 border-t border-slate-100">
                                <div className="space-y-1">
                                    <label className="font-bold text-slate-600">Payment Type</label>
                                    <select 
                                        value={paymentType} 
                                        onChange={e => setPaymentType(e.target.value)}
                                        className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                    >
                                        <option value="Cash">Cash</option>
                                        <option value="Bank">Bank Account / Transfer</option>
                                        <option value="UPI">UPI / GPay / PhonePe</option>
                                    </select>
                                </div>
                                <div className="space-y-1 md:col-span-2">
                                    <label className="font-bold text-slate-600">Notes / Remarks</label>
                                    <input 
                                        type="text" 
                                        value={notes} 
                                        onChange={e => setNotes(e.target.value)} 
                                        placeholder="Any additional remarks..."
                                        className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                    />
                                </div>
                            </div>

                            <div className="flex justify-end gap-2 pt-4">
                                <button 
                                    type="button" 
                                    onClick={() => setShowAddForm(false)}
                                    className="bg-slate-100 hover:bg-slate-200 text-slate-700 px-6 py-2.5 rounded-xl font-bold"
                                >
                                    Cancel
                                </button>
                                <button 
                                    type="submit" 
                                    className="bg-indigo-600 text-white px-8 py-2.5 rounded-xl hover:bg-indigo-700 transition font-bold shadow-md shadow-indigo-100"
                                >
                                    Save
                                </button>
                            </div>
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
                        
                        <form onSubmit={handleSaveCompany} className="space-y-4 text-xs">
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Legal Business Name</label>
                                <input 
                                    type="text" 
                                    value={companyName} 
                                    onChange={e => setCompanyName(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-4 py-2.5 text-xs font-bold text-slate-800 focus:outline-none"
                                    required 
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Trade Name / Brand (Optional)</label>
                                <input 
                                    type="text" 
                                    value={tradeName} 
                                    onChange={e => setTradeName(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-4 py-2.5 text-xs font-bold text-slate-800 focus:outline-none"
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Company GSTIN</label>
                                <input 
                                    type="text" 
                                    value={companyGstin} 
                                    onChange={e => setCompanyGstin(e.target.value)} 
                                    maxLength={15}
                                    className="w-full bg-white border border-slate-300 rounded-xl px-4 py-2.5 text-xs font-bold text-slate-800 focus:outline-none uppercase"
                                    required 
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Billing Address</label>
                                <textarea 
                                    value={companyAddress} 
                                    onChange={e => setCompanyAddress(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-4 py-2.5 text-xs font-bold text-slate-800 focus:outline-none"
                                    rows="2"
                                    required 
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">State</label>
                                <select 
                                    value={companyState} 
                                    onChange={e => setCompanyState(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-4 py-2.5 text-xs font-bold text-slate-800 focus:outline-none"
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
                                <h4 className="font-bold text-slate-800 text-xs">Bank Details (For Invoicing)</h4>
                                <div className="grid grid-cols-2 gap-2">
                                    <input 
                                        type="text" 
                                        placeholder="Bank Name" 
                                        value={bankName} 
                                        onChange={e => setBankName(e.target.value)} 
                                        className="w-full bg-white border border-slate-300 rounded-xl px-4 py-2 text-xs font-bold text-slate-800 focus:outline-none"
                                    />
                                    <input 
                                        type="text" 
                                        placeholder="Account Number" 
                                        value={bankAccount} 
                                        onChange={e => setBankAccount(e.target.value)} 
                                        className="w-full bg-white border border-slate-300 rounded-xl px-4 py-2 text-xs font-bold text-slate-800 focus:outline-none"
                                    />
                                </div>
                                <input 
                                    type="text" 
                                    placeholder="IFSC Code" 
                                    value={bankIfsc} 
                                    onChange={e => setBankIfsc(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-4 py-2 text-xs font-bold text-slate-800 focus:outline-none uppercase"
                                />
                            </div>

                            <button 
                                type="submit" 
                                className="w-full bg-indigo-600 text-white py-3 rounded-xl font-bold text-xs hover:bg-indigo-700 transition"
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
