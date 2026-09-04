import React, { useState, useEffect } from 'react';
import { X, Plus, Trash2, Camera, Upload, Check, AlertCircle } from 'lucide-react';

const TransactionFormModal = ({
    show,
    onClose,
    txType = 'Sales',
    onSubmit,
    parties = [],
    companyState = 'Andhra Pradesh',
    invoiceCount = 1,
    editingTransaction = null
}) => {
    if (!show) return null;

    const isSales = txType === 'Sales';
    const isPurchase = txType === 'Purchase';
    const isIncome = txType === 'Income';
    const isExpense = txType === 'Expense';

    const [docNumber, setDocNumber] = useState('');
    const [copyType, setCopyType] = useState('Original for Recipient');
    const [docDate, setDocDate] = useState(new Date().toISOString().split('T')[0]);
    const [dueDate, setDueDate] = useState(new Date().toISOString().split('T')[0]);
    const [paymentMode, setPaymentMode] = useState('Bank Transfer');
    const [paymentStatus, setPaymentStatus] = useState('Unpaid');

    // Bill To (Party)
    const [partyName, setPartyName] = useState('');
    const [partyGstin, setPartyGstin] = useState('');
    const [partyPan, setPartyPan] = useState('');
    const [partyAddress, setPartyAddress] = useState('');
    const [partyState, setPartyState] = useState(companyState || 'Andhra Pradesh');
    const [partyPhone, setPartyPhone] = useState('');
    const [partyEmail, setPartyEmail] = useState('');
    const [placeOfSupply, setPlaceOfSupply] = useState(companyState || 'Andhra Pradesh');
    const [isInterstate, setIsInterstate] = useState(false);

    // Ship To (Consignee)
    const [shipToSameAsBilling, setShipToSameAsBilling] = useState(true);
    const [shipToName, setShipToName] = useState('');
    const [shipToAddress, setShipToAddress] = useState('');
    const [shipToGstin, setShipToGstin] = useState('');
    const [shipToPan, setShipToPan] = useState('');
    const [shipToState, setShipToState] = useState(companyState || 'Andhra Pradesh');
    const [shipToMobile, setShipToMobile] = useState('');

    // Items
    const [items, setItems] = useState([
        { description: '', hsnSac: '', qty: 1, unit: 'PCS', rate: 0, discPercent: 0, gstRate: 18 }
    ]);

    const [itcEligibility, setItcEligibility] = useState(isPurchase ? 'Inputs' : 'N/A');
    const [notes, setNotes] = useState('');
    const [attachmentUrl, setAttachmentUrl] = useState('');
    const [uploading, setUploading] = useState(false);

    const units = ['PCS', 'BOX', 'KGS', 'LTRS', 'MTRS', 'NOS', 'HRS', 'SET', 'NONE'];
    const indianStates = [
        '37-Andhra Pradesh', '36-Telangana', '29-Karnataka', '33-Tamil Nadu', '32-Kerala',
        '27-Maharashtra', '07-Delhi', '24-Gujarat', '09-Uttar Pradesh', '19-West Bengal',
        '08-Rajasthan', '23-Madhya Pradesh', '06-Haryana', '03-Punjab', '21-Odisha', '10-Bihar'
    ];

    // Initialize or load edit data
    useEffect(() => {
        if (editingTransaction) {
            setDocNumber(editingTransaction.docNumber || '');
            setCopyType(editingTransaction.copyType || 'Original for Recipient');
            setDocDate(editingTransaction.docDate ? new Date(editingTransaction.docDate).toISOString().split('T')[0] : new Date().toISOString().split('T')[0]);
            setDueDate(editingTransaction.dueDate ? new Date(editingTransaction.dueDate).toISOString().split('T')[0] : new Date().toISOString().split('T')[0]);
            setPaymentMode(editingTransaction.paymentMode || 'Bank Transfer');
            setPaymentStatus(editingTransaction.paymentStatus || 'Unpaid');
            setPartyName(editingTransaction.partyName || '');
            setPartyGstin(editingTransaction.partyGstin || '');
            setPartyPan(editingTransaction.partyPan || '');
            setPartyAddress(editingTransaction.partyAddress || '');
            setPartyState(editingTransaction.partyState || companyState || 'Andhra Pradesh');
            setPartyPhone(editingTransaction.partyPhone || '');
            setPartyEmail(editingTransaction.partyEmail || '');
            setPlaceOfSupply(editingTransaction.placeOfSupply || companyState || 'Andhra Pradesh');
            setShipToSameAsBilling(editingTransaction.shipToSameAsBilling !== false);
            setShipToName(editingTransaction.shipToName || '');
            setShipToAddress(editingTransaction.shipToAddress || '');
            setShipToGstin(editingTransaction.shipToGstin || '');
            setShipToPan(editingTransaction.shipToPan || '');
            setShipToState(editingTransaction.shipToState || companyState || 'Andhra Pradesh');
            setShipToMobile(editingTransaction.shipToMobile || '');
            if (editingTransaction.items && editingTransaction.items.length > 0) {
                setItems(editingTransaction.items.map(it => ({
                    description: it.description || '',
                    hsnSac: it.hsnSac || '',
                    qty: it.qty || 1,
                    unit: it.unit || 'PCS',
                    rate: it.rate || 0,
                    discPercent: it.discPercent || 0,
                    gstRate: it.gstRate !== undefined ? it.gstRate : 18
                })));
            }
            setItcEligibility(editingTransaction.itcEligibility || (isPurchase ? 'Inputs' : 'N/A'));
            setNotes(editingTransaction.notes || '');
            setAttachmentUrl(editingTransaction.attachmentUrl || '');
        } else {
            const prefix = isSales ? 'INV-' : isPurchase ? 'BILL-' : isIncome ? 'INC-' : 'EXP-';
            const padded = String(invoiceCount).padStart(4, '0');
            setDocNumber(`${prefix}${padded}`);
            setCopyType('Original for Recipient');
            setDocDate(new Date().toISOString().split('T')[0]);
            setDueDate(new Date().toISOString().split('T')[0]);
            setPaymentMode('Bank Transfer');
            setPaymentStatus('Unpaid');
            setPartyName('');
            setPartyGstin('');
            setPartyPan('');
            setPartyAddress('');
            setPartyState(companyState || 'Andhra Pradesh');
            setPartyPhone('');
            setPartyEmail('');
            setPlaceOfSupply(companyState || 'Andhra Pradesh');
            setShipToSameAsBilling(true);
            setShipToName('');
            setShipToAddress('');
            setShipToGstin('');
            setShipToPan('');
            setShipToState(companyState || 'Andhra Pradesh');
            setShipToMobile('');
            setItems([{ description: '', hsnSac: '', qty: 1, unit: 'PCS', rate: 0, discPercent: 0, gstRate: 18 }]);
            setItcEligibility(isPurchase ? 'Inputs' : 'N/A');
            setNotes('');
            setAttachmentUrl('');
        }
    }, [editingTransaction, isSales, isPurchase, isIncome, isExpense, invoiceCount, companyState, show]);

    // Interstate check
    useEffect(() => {
        const cleanCompany = (companyState || '').toLowerCase().replace(/^[0-9]+-/, '').trim();
        const cleanPos = (placeOfSupply || '').toLowerCase().replace(/^[0-9]+-/, '').trim();
        setIsInterstate(cleanCompany !== cleanPos);
    }, [companyState, placeOfSupply]);

    // Quick party select
    const handlePartySelect = (e) => {
        const selected = parties.find(p => p.name === e.target.value);
        if (selected) {
            setPartyName(selected.name);
            setPartyGstin(selected.gstin || '');
            setPartyPan(selected.pan || (selected.gstin?.length === 15 ? selected.gstin.substring(2, 12) : ''));
            setPartyAddress(selected.billingAddress || selected.address || '');
            setPartyState(selected.state || companyState);
            setPartyPhone(selected.phone || '');
            setPartyEmail(selected.email || '');
            setPlaceOfSupply(selected.state || companyState);
        } else {
            setPartyName(e.target.value);
        }
    };

    const handleAddItem = () => {
        setItems([...items, { description: '', hsnSac: '', qty: 1, unit: 'PCS', rate: 0, discPercent: 0, gstRate: 18 }]);
    };

    const handleItemChange = (idx, field, val) => {
        const updated = [...items];
        updated[idx][field] = val;
        setItems(updated);
    };

    const handleRemoveItem = (idx) => {
        if (items.length > 1) {
            setItems(items.filter((_, i) => i !== idx));
        }
    };

    // Calculate live summary
    let totalTaxable = 0;
    let totalCgst = 0;
    let totalSgst = 0;
    let totalIgst = 0;

    items.forEach(it => {
        const q = Number(it.qty) || 0;
        const r = Number(it.rate) || 0;
        const d = Number(it.discPercent) || 0;
        const raw = q * r;
        const disc = Math.round((raw * (d / 100)) * 100) / 100;
        const taxable = Math.max(0, raw - disc);
        totalTaxable += taxable;

        const rate = Number(it.gstRate) || 0;
        if (rate > 0) {
            if (isInterstate) {
                totalIgst += Math.round((taxable * (rate / 100)) * 100) / 100;
            } else {
                const half = Math.round((taxable * ((rate / 2) / 100)) * 100) / 100;
                totalCgst += half;
                totalSgst += half;
            }
        }
    });

    const rawGrandTotal = totalTaxable + totalCgst + totalSgst + totalIgst;
    const roundedGrandTotal = Math.round(rawGrandTotal);
    const roundOff = Math.round((roundedGrandTotal - rawGrandTotal) * 100) / 100;

    const handleSubmit = (e) => {
        e.preventDefault();
        if (!partyName) {
            alert('Please enter or select a Party / Customer Name');
            return;
        }
        if (items.some(i => !i.description || !i.rate)) {
            alert('Please fill description and rate for all line items');
            return;
        }

        onSubmit({
            transactionType: txType,
            copyType,
            docNumber,
            docDate,
            dueDate,
            paymentMode,
            paymentStatus,
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
            shipToName: shipToSameAsBilling ? partyName : shipToName,
            shipToAddress: shipToSameAsBilling ? partyAddress : shipToAddress,
            shipToGstin: shipToSameAsBilling ? partyGstin : shipToGstin,
            shipToPan: shipToSameAsBilling ? partyPan : shipToPan,
            shipToState: shipToSameAsBilling ? partyState : shipToState,
            shipToMobile: shipToSameAsBilling ? partyPhone : shipToMobile,
            items,
            itcEligibility,
            notes,
            attachmentUrl
        }, editingTransaction?._id);
    };

    return (
        <div className="fixed inset-0 z-50 bg-slate-900/70 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
            <div className="bg-white rounded-[2rem] border border-slate-200 shadow-2xl w-full max-w-5xl max-h-[92vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
                
                {/* Header */}
                <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/50 shrink-0">
                    <div className="flex items-center gap-3">
                        <span className={`px-3 py-1 rounded-full text-xs font-black uppercase tracking-wider ${
                            isSales ? 'bg-emerald-100 text-emerald-800' :
                            isPurchase ? 'bg-indigo-100 text-indigo-800' :
                            isIncome ? 'bg-teal-100 text-teal-800' : 'bg-rose-100 text-rose-800'
                        }`}>
                            {editingTransaction ? `Edit ${isSales ? 'Tax Invoice' : isPurchase ? 'Purchase Bill' : isIncome ? 'Income Voucher' : 'Expense Voucher'}` : `New ${isSales ? 'Tax Invoice' : isPurchase ? 'Purchase Bill' : isIncome ? 'Income Voucher' : 'Expense Voucher'}`}
                        </span>
                        <h2 className="font-black text-slate-900 text-base">{docNumber}</h2>
                    </div>
                    <button onClick={onClose} className="text-slate-400 hover:text-slate-700 p-1.5 rounded-xl hover:bg-slate-100 transition">
                        <X size={20} />
                    </button>
                </div>

                {/* Body Form */}
                <form onSubmit={handleSubmit} className="p-6 overflow-y-auto space-y-6 text-xs flex-1">
                    
                    {/* Invoice Top Details */}
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 bg-slate-50 p-4 rounded-2xl border border-slate-200/70">
                        <div>
                            <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">Doc Number</label>
                            <input 
                                type="text"
                                value={docNumber}
                                onChange={(e) => setDocNumber(e.target.value)}
                                className="w-full bg-white border border-slate-200 rounded-xl px-3 py-2 font-mono font-bold text-slate-900 focus:outline-none focus:border-indigo-500"
                                required
                            />
                        </div>
                        <div>
                            <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">Doc Date</label>
                            <input 
                                type="date"
                                value={docDate}
                                onChange={(e) => setDocDate(e.target.value)}
                                className="w-full bg-white border border-slate-200 rounded-xl px-3 py-2 font-bold text-slate-800 focus:outline-none focus:border-indigo-500"
                                required
                            />
                        </div>
                        <div>
                            <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">Due Date</label>
                            <input 
                                type="date"
                                value={dueDate}
                                onChange={(e) => setDueDate(e.target.value)}
                                className="w-full bg-white border border-slate-200 rounded-xl px-3 py-2 text-slate-800 focus:outline-none focus:border-indigo-500"
                            />
                        </div>
                        <div>
                            <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">Payment Mode</label>
                            <select 
                                value={paymentMode}
                                onChange={(e) => setPaymentMode(e.target.value)}
                                className="w-full bg-white border border-slate-200 rounded-xl px-3 py-2 font-medium text-slate-800 focus:outline-none focus:border-indigo-500"
                            >
                                <option value="Bank Transfer">Bank Transfer / NEFT / IMPS</option>
                                <option value="UPI">UPI / QR Code</option>
                                <option value="Cash">Cash</option>
                                <option value="Cheque">Cheque</option>
                                <option value="Credit">Credit (Unpaid)</option>
                            </select>
                        </div>
                    </div>

                    {/* Party / Bill To */}
                    <div className="border border-slate-200 rounded-2xl p-4 space-y-4">
                        <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                            <h3 className="font-black text-slate-900 text-sm uppercase tracking-wide">
                                {isSales ? 'BILL TO (Customer Details)' : 'VENDOR (Supplier Details)'}
                            </h3>
                            {parties.length > 0 && (
                                <select onChange={handlePartySelect} className="bg-slate-100 border border-slate-200 rounded-xl px-3 py-1 font-bold text-indigo-700">
                                    <option value="">-- Quick Select from Directory --</option>
                                    {parties.map(p => (
                                        <option key={p._id || p.name} value={p.name}>{p.name} {p.gstin ? `(${p.gstin})` : ''}</option>
                                    ))}
                                </select>
                            )}
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 mb-1">Party / Business Name *</label>
                                <input 
                                    type="text" 
                                    value={partyName} 
                                    onChange={(e) => setPartyName(e.target.value)} 
                                    placeholder="e.g. Acme Tech Pvt Ltd"
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 font-bold text-slate-900 focus:outline-none focus:border-indigo-500"
                                    required 
                                />
                            </div>
                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 mb-1">Party GSTIN (15 Digits)</label>
                                <input 
                                    type="text" 
                                    value={partyGstin} 
                                    onChange={(e) => {
                                        const v = e.target.value.toUpperCase();
                                        setPartyGstin(v);
                                        if (v.length === 15) setPartyPan(v.substring(2, 12));
                                    }} 
                                    placeholder="37AAAAA0000A1Z5"
                                    maxLength={15}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 font-mono uppercase text-slate-900 focus:outline-none focus:border-indigo-500"
                                />
                            </div>
                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 mb-1">Party PAN</label>
                                <input 
                                    type="text" 
                                    value={partyPan} 
                                    onChange={(e) => setPartyPan(e.target.value.toUpperCase())} 
                                    placeholder="AAAAA0000A"
                                    maxLength={10}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 font-mono uppercase text-slate-900 focus:outline-none focus:border-indigo-500"
                                />
                            </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                            <div className="md:col-span-2">
                                <label className="block text-[10px] font-bold text-slate-500 mb-1">Billing Address</label>
                                <input 
                                    type="text" 
                                    value={partyAddress} 
                                    onChange={(e) => setPartyAddress(e.target.value)} 
                                    placeholder="Door No, Street, Landmark, City - PIN"
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-slate-800 focus:outline-none focus:border-indigo-500"
                                />
                            </div>
                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 mb-1">Place of Supply (State)</label>
                                <select 
                                    value={placeOfSupply} 
                                    onChange={(e) => setPlaceOfSupply(e.target.value)}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 font-bold text-slate-900 focus:outline-none focus:border-indigo-500"
                                >
                                    {indianStates.map(s => <option key={s} value={s}>{s}</option>)}
                                </select>
                            </div>
                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 mb-1">Tax Treatment</label>
                                <div className={`px-3 py-2 rounded-xl text-center font-bold font-mono text-[11px] ${
                                    isInterstate ? 'bg-amber-100 text-amber-900 border border-amber-300' : 'bg-blue-100 text-blue-900 border border-blue-300'
                                }`}>
                                    {isInterstate ? '⚡ INTER-STATE (IGST)' : '🔹 INTRA-STATE (CGST+SGST)'}
                                </div>
                            </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 mb-1">Mobile Number</label>
                                <input 
                                    type="text" 
                                    value={partyPhone} 
                                    onChange={(e) => setPartyPhone(e.target.value)} 
                                    placeholder="9876543210"
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-slate-800 focus:outline-none focus:border-indigo-500"
                                />
                            </div>
                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 mb-1">Email Address</label>
                                <input 
                                    type="email" 
                                    value={partyEmail} 
                                    onChange={(e) => setPartyEmail(e.target.value)} 
                                    placeholder="finance@client.com"
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-slate-800 focus:outline-none focus:border-indigo-500"
                                />
                            </div>
                        </div>

                        {/* Ship To Toggle */}
                        {isSales && (
                            <div className="border-t border-slate-100 pt-3">
                                <label className="inline-flex items-center gap-2 cursor-pointer font-bold text-slate-700">
                                    <input 
                                        type="checkbox" 
                                        checked={shipToSameAsBilling} 
                                        onChange={(e) => setShipToSameAsBilling(e.target.checked)} 
                                        className="rounded text-indigo-600 focus:ring-indigo-500 w-4 h-4"
                                    />
                                    <span>Ship to address is same as billing address</span>
                                </label>

                                {!shipToSameAsBilling && (
                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-3 p-3 bg-slate-50 rounded-xl border border-slate-200">
                                        <div>
                                            <label className="block text-[10px] font-bold text-slate-500 mb-1">Consignee / Ship Name</label>
                                            <input type="text" value={shipToName} onChange={(e)=>setShipToName(e.target.value)} placeholder="Consignee Name" className="w-full bg-white border border-slate-200 rounded-lg p-2" />
                                        </div>
                                        <div>
                                            <label className="block text-[10px] font-bold text-slate-500 mb-1">Shipping Address</label>
                                            <input type="text" value={shipToAddress} onChange={(e)=>setShipToAddress(e.target.value)} placeholder="Delivery Address" className="w-full bg-white border border-slate-200 rounded-lg p-2" />
                                        </div>
                                        <div>
                                            <label className="block text-[10px] font-bold text-slate-500 mb-1">Consignee Mobile</label>
                                            <input type="text" value={shipToMobile} onChange={(e)=>setShipToMobile(e.target.value)} placeholder="Mobile Number" className="w-full bg-white border border-slate-200 rounded-lg p-2" />
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>

                    {/* Line Items Table */}
                    <div className="border border-slate-200 rounded-2xl p-4 space-y-3">
                        <div className="flex justify-between items-center border-b border-slate-100 pb-2">
                            <h3 className="font-black text-slate-900 text-sm uppercase tracking-wide">
                                Line Items / Products & Services
                            </h3>
                            <button 
                                type="button" 
                                onClick={handleAddItem}
                                className="bg-indigo-50 text-indigo-700 hover:bg-indigo-600 hover:text-white px-3 py-1.5 rounded-xl font-bold transition flex items-center gap-1 text-xs"
                            >
                                <Plus size={14} /> Add Item Row
                            </button>
                        </div>

                        <div className="overflow-x-auto">
                            <table className="w-full text-left border-collapse min-w-[700px]">
                                <thead>
                                    <tr className="bg-slate-100 text-slate-600 text-[10px] font-black uppercase tracking-wider">
                                        <th className="p-2 w-8">#</th>
                                        <th className="p-2">Description</th>
                                        <th className="p-2 w-20">HSN/SAC</th>
                                        <th className="p-2 w-16">Qty</th>
                                        <th className="p-2 w-20">Unit</th>
                                        <th className="p-2 w-24">Rate (₹)</th>
                                        <th className="p-2 w-16">Disc %</th>
                                        <th className="p-2 w-20">GST %</th>
                                        <th className="p-2 w-24 text-right">Taxable</th>
                                        <th className="p-2 w-8"></th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-100">
                                    {items.map((item, idx) => {
                                        const q = Number(item.qty) || 0;
                                        const r = Number(item.rate) || 0;
                                        const d = Number(item.discPercent) || 0;
                                        const taxVal = Math.max(0, (q * r) - ((q * r) * (d / 100)));
                                        return (
                                            <tr key={idx} className="hover:bg-slate-50/50">
                                                <td className="p-2 text-slate-400 font-bold">{idx + 1}</td>
                                                <td className="p-2">
                                                    <input 
                                                        type="text" 
                                                        value={item.description} 
                                                        onChange={(e) => handleItemChange(idx, 'description', e.target.value)} 
                                                        placeholder="Item or service description"
                                                        className="w-full bg-white border border-slate-200 rounded-lg px-2.5 py-1.5 font-medium text-slate-900 focus:outline-none focus:border-indigo-500"
                                                        required 
                                                    />
                                                </td>
                                                <td className="p-2">
                                                    <input 
                                                        type="text" 
                                                        value={item.hsnSac} 
                                                        onChange={(e) => handleItemChange(idx, 'hsnSac', e.target.value)} 
                                                        placeholder="998311"
                                                        className="w-full bg-white border border-slate-200 rounded-lg px-2 py-1.5 font-mono text-center"
                                                    />
                                                </td>
                                                <td className="p-2">
                                                    <input 
                                                        type="number" 
                                                        min="1"
                                                        value={item.qty} 
                                                        onChange={(e) => handleItemChange(idx, 'qty', e.target.value)} 
                                                        className="w-full bg-white border border-slate-200 rounded-lg px-2 py-1.5 font-bold text-center"
                                                        required 
                                                    />
                                                </td>
                                                <td className="p-2">
                                                    <select 
                                                        value={item.unit} 
                                                        onChange={(e) => handleItemChange(idx, 'unit', e.target.value)}
                                                        className="w-full bg-white border border-slate-200 rounded-lg px-1.5 py-1.5 font-medium"
                                                    >
                                                        {units.map(u => <option key={u} value={u}>{u}</option>)}
                                                    </select>
                                                </td>
                                                <td className="p-2">
                                                    <input 
                                                        type="number" 
                                                        step="0.01"
                                                        min="0"
                                                        value={item.rate} 
                                                        onChange={(e) => handleItemChange(idx, 'rate', e.target.value)} 
                                                        placeholder="0.00"
                                                        className="w-full bg-white border border-slate-200 rounded-lg px-2 py-1.5 font-mono font-bold text-right"
                                                        required 
                                                    />
                                                </td>
                                                <td className="p-2">
                                                    <input 
                                                        type="number" 
                                                        min="0" 
                                                        max="100"
                                                        value={item.discPercent} 
                                                        onChange={(e) => handleItemChange(idx, 'discPercent', e.target.value)} 
                                                        placeholder="0"
                                                        className="w-full bg-white border border-slate-200 rounded-lg px-1.5 py-1.5 font-mono text-center text-slate-600"
                                                    />
                                                </td>
                                                <td className="p-2">
                                                    <select 
                                                        value={item.gstRate} 
                                                        onChange={(e) => handleItemChange(idx, 'gstRate', Number(e.target.value))}
                                                        className="w-full bg-white border border-slate-200 rounded-lg px-1 py-1.5 font-bold text-center text-indigo-900"
                                                    >
                                                        <option value={0}>0% (Exempt)</option>
                                                        <option value={5}>5%</option>
                                                        <option value={12}>12%</option>
                                                        <option value={18}>18%</option>
                                                        <option value={28}>28%</option>
                                                    </select>
                                                </td>
                                                <td className="p-2 text-right font-mono font-bold text-slate-900">
                                                    ₹{taxVal.toFixed(2)}
                                                </td>
                                                <td className="p-2 text-center">
                                                    {items.length > 1 && (
                                                        <button 
                                                            type="button" 
                                                            onClick={() => handleRemoveItem(idx)}
                                                            className="text-slate-300 hover:text-rose-600 transition"
                                                        >
                                                            <Trash2 size={14} />
                                                        </button>
                                                    )}
                                                </td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    {/* Summary & Calculations Preview */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 bg-slate-900 text-white p-5 rounded-2xl shadow-xl">
                        <div className="space-y-3">
                            <div className="text-[11px] text-slate-300">
                                <span className="font-bold text-indigo-300 uppercase tracking-wider block mb-1">Invoice Notes / Terms</span>
                                <textarea 
                                    rows={3} 
                                    value={notes} 
                                    onChange={(e) => setNotes(e.target.value)}
                                    placeholder="Add any internal remarks or payment instructions..."
                                    className="w-full bg-slate-800 border border-slate-700 rounded-xl p-2.5 text-xs text-white focus:outline-none focus:border-indigo-400"
                                />
                            </div>

                            {isPurchase && (
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-300 uppercase mb-1">ITC Eligibility (Input Tax Credit)</label>
                                    <select 
                                        value={itcEligibility} 
                                        onChange={(e) => setItcEligibility(e.target.value)}
                                        className="w-full bg-slate-800 border border-slate-700 rounded-xl p-2 font-bold text-emerald-400"
                                    >
                                        <option value="Inputs">Inputs (Raw materials / Goods)</option>
                                        <option value="Input Services">Input Services (Professional / Operations)</option>
                                        <option value="Capital Goods">Capital Goods (Assets / Machinery)</option>
                                        <option value="Ineligible">Ineligible (Blocked ITC u/s 17(5))</option>
                                    </select>
                                </div>
                            )}
                        </div>

                        <div className="space-y-2 text-xs border-l border-slate-800 pl-4 flex flex-col justify-between">
                            <div className="space-y-1.5">
                                <div className="flex justify-between text-slate-300">
                                    <span>Subtotal Taxable:</span>
                                    <span className="font-mono font-bold">₹{totalTaxable.toFixed(2)}</span>
                                </div>
                                {totalCgst > 0 && (
                                    <div className="flex justify-between text-slate-300">
                                        <span>CGST Output:</span>
                                        <span className="font-mono font-bold">₹{totalCgst.toFixed(2)}</span>
                                    </div>
                                )}
                                {totalSgst > 0 && (
                                    <div className="flex justify-between text-slate-300">
                                        <span>SGST Output:</span>
                                        <span className="font-mono font-bold">₹{totalSgst.toFixed(2)}</span>
                                    </div>
                                )}
                                {totalIgst > 0 && (
                                    <div className="flex justify-between text-slate-300">
                                        <span>IGST Output:</span>
                                        <span className="font-mono font-bold">₹{totalIgst.toFixed(2)}</span>
                                    </div>
                                )}
                                {roundOff !== 0 && (
                                    <div className="flex justify-between text-slate-400 text-[10px]">
                                        <span>Round Off:</span>
                                        <span className="font-mono">{roundOff > 0 ? `+${roundOff.toFixed(2)}` : roundOff.toFixed(2)}</span>
                                    </div>
                                )}
                            </div>

                            <div className="border-t border-slate-700 pt-3 flex justify-between items-center">
                                <span className="font-bold text-slate-200 uppercase tracking-wider">Grand Total:</span>
                                <span className="font-mono font-black text-2xl text-emerald-400">₹{roundedGrandTotal.toLocaleString('en-IN')}.00</span>
                            </div>
                        </div>
                    </div>

                    {/* Submit Bar */}
                    <div className="flex justify-end gap-3 pt-3 border-t border-slate-100">
                        <button 
                            type="button" 
                            onClick={onClose}
                            className="px-5 py-2.5 rounded-xl font-bold text-slate-600 hover:bg-slate-100 transition"
                        >
                            Cancel
                        </button>
                        <button 
                            type="submit"
                            className="bg-indigo-600 hover:bg-indigo-700 text-white px-8 py-2.5 rounded-xl font-black text-xs uppercase tracking-wider transition shadow-lg shadow-indigo-200"
                        >
                            {editingTransaction ? 'Save Changes' : `Save & Generate ${isSales ? 'Invoice' : 'Voucher'}`}
                        </button>
                    </div>
                </form>

            </div>
        </div>
    );
};

export default TransactionFormModal;
