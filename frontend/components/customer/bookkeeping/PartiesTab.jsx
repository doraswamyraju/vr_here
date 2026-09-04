import React, { useState } from 'react';
import { Plus, Search, User, Trash2, Edit2, Phone, Mail, MapPin, X, Building2 } from 'lucide-react';

const PartiesTab = ({
    parties = [],
    onAddParty,
    onDeleteParty,
    onEditParty
}) => {
    const [search, setSearch] = useState('');
    const [typeFilter, setTypeFilter] = useState('All');
    const [showModal, setShowModal] = useState(false);
    const [editingParty, setEditingParty] = useState(null);

    // Form states
    const [name, setName] = useState('');
    const [partyType, setPartyType] = useState('Customer');
    const [gstin, setGstin] = useState('');
    const [pan, setPan] = useState('');
    const [phone, setPhone] = useState('');
    const [email, setEmail] = useState('');
    const [billingAddress, setBillingAddress] = useState('');
    const [state, setState] = useState('Andhra Pradesh');
    const [openingBalance, setOpeningBalance] = useState(0);

    const filtered = parties.filter(p => {
        const matchesSearch = (p.name || '').toLowerCase().includes(search.toLowerCase()) ||
            (p.gstin || '').toLowerCase().includes(search.toLowerCase()) ||
            (p.phone || '').includes(search);
        const matchesType = typeFilter === 'All' || p.partyType === typeFilter || p.partyType === 'Both';
        return matchesSearch && matchesType;
    });

    const handleOpenAdd = () => {
        setEditingParty(null);
        setName('');
        setPartyType('Customer');
        setGstin('');
        setPan('');
        setPhone('');
        setEmail('');
        setBillingAddress('');
        setState('Andhra Pradesh');
        setOpeningBalance(0);
        setShowModal(true);
    };

    const handleOpenEdit = (p) => {
        setEditingParty(p);
        setName(p.name || '');
        setPartyType(p.partyType || 'Customer');
        setGstin(p.gstin || '');
        setPan(p.pan || '');
        setPhone(p.phone || '');
        setEmail(p.email || '');
        setBillingAddress(p.billingAddress || p.address || '');
        setState(p.state || 'Andhra Pradesh');
        setOpeningBalance(p.openingBalance || 0);
        setShowModal(true);
    };

    const handleSave = (e) => {
        e.preventDefault();
        if (!name) {
            alert('Party name is required');
            return;
        }

        const partyData = {
            name,
            partyType,
            gstin: gstin.toUpperCase(),
            pan: pan.toUpperCase() || (gstin.length === 15 ? gstin.substring(2, 12) : ''),
            phone,
            email,
            billingAddress,
            address: billingAddress,
            state,
            openingBalance: Number(openingBalance) || 0
        };

        if (editingParty) {
            if (onEditParty) onEditParty(editingParty._id || editingParty.name, partyData);
        } else {
            if (onAddParty) onAddParty(partyData);
        }
        setShowModal(false);
    };

    return (
        <div className="space-y-6">
            {/* Top Bar */}
            <div className="bg-white p-4 rounded-3xl border border-slate-100 shadow-sm flex flex-col md:flex-row gap-3 items-center justify-between">
                <div className="relative w-full md:w-80">
                    <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" size={16} />
                    <input 
                        type="text" 
                        value={search} 
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Search by name, GSTIN, phone..."
                        className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-2xl text-xs font-medium text-slate-900 focus:outline-none focus:border-indigo-500"
                    />
                </div>

                <div className="flex items-center gap-2 w-full md:w-auto justify-between md:justify-end">
                    <div className="flex bg-slate-100 p-1 rounded-2xl text-xs font-bold">
                        {['All', 'Customer', 'Vendor'].map(tab => (
                            <button
                                key={tab}
                                onClick={() => setTypeFilter(tab)}
                                className={`px-3 py-1.5 rounded-xl transition ${
                                    typeFilter === tab ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-600 hover:text-slate-900'
                                }`}
                            >
                                {tab}s
                            </button>
                        ))}
                    </div>

                    <button 
                        onClick={handleOpenAdd}
                        className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2.5 rounded-2xl font-black text-xs uppercase tracking-wider flex items-center gap-1.5 transition shadow-md shadow-indigo-100"
                    >
                        <Plus size={16} /> Add New Party
                    </button>
                </div>
            </div>

            {/* Parties Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filtered.map((party, idx) => (
                    <div 
                        key={party._id || idx}
                        className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm hover:border-indigo-200 transition space-y-3 relative group flex flex-col justify-between"
                    >
                        <div>
                            <div className="flex justify-between items-start gap-2">
                                <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 rounded-2xl bg-indigo-50 text-indigo-600 flex items-center justify-center font-black text-sm shrink-0">
                                        <Building2 size={18} />
                                    </div>
                                    <div>
                                        <h4 className="font-black text-slate-900 text-sm leading-tight">{party.name}</h4>
                                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full inline-block mt-0.5 ${
                                            party.partyType === 'Vendor' ? 'bg-amber-50 text-amber-700' : 'bg-emerald-50 text-emerald-700'
                                        }`}>
                                            {party.partyType || 'Customer'}
                                        </span>
                                    </div>
                                </div>
                                <div className="flex items-center gap-1 opacity-80 group-hover:opacity-100">
                                    <button 
                                        onClick={() => handleOpenEdit(party)}
                                        className="p-1.5 text-slate-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-lg transition"
                                    >
                                        <Edit2 size={14} />
                                    </button>
                                    <button 
                                        onClick={() => onDeleteParty(party._id || party.name)}
                                        className="p-1.5 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition"
                                    >
                                        <Trash2 size={14} />
                                    </button>
                                </div>
                            </div>

                            <div className="space-y-1 pt-3 text-[11px] text-slate-600 border-t border-slate-50">
                                {party.gstin && (
                                    <p className="font-mono"><span className="font-bold text-slate-400">GSTIN:</span> {party.gstin}</p>
                                )}
                                {party.pan && (
                                    <p className="font-mono"><span className="font-bold text-slate-400">PAN:</span> {party.pan}</p>
                                )}
                                {(party.phone || party.email) && (
                                    <div className="flex items-center gap-3 pt-1 text-slate-500">
                                        {party.phone && <span className="flex items-center gap-1"><Phone size={12} /> {party.phone}</span>}
                                        {party.email && <span className="flex items-center gap-1 truncate"><Mail size={12} /> {party.email}</span>}
                                    </div>
                                )}
                                {(party.billingAddress || party.address) && (
                                    <p className="text-[10.5px] text-slate-400 pt-1 truncate flex items-center gap-1">
                                        <MapPin size={11} className="shrink-0" /> {party.billingAddress || party.address}
                                    </p>
                                )}
                            </div>
                        </div>

                        <div className="pt-2 border-t border-slate-100 flex justify-between items-center text-xs">
                            <span className="text-[10px] font-bold text-slate-400 uppercase">State:</span>
                            <span className="font-bold text-slate-700">{party.state || 'Andhra Pradesh'}</span>
                        </div>
                    </div>
                ))}
            </div>

            {/* Modal */}
            {showModal && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl w-full max-w-lg overflow-hidden animate-in fade-in zoom-in-95 duration-200">
                        <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50">
                            <h3 className="font-black text-slate-900 text-sm">
                                {editingParty ? 'Edit Party Details' : 'Add Customer / Vendor to Directory'}
                            </h3>
                            <button onClick={() => setShowModal(false)} className="text-slate-400 hover:text-slate-600">
                                <X size={18} />
                            </button>
                        </div>

                        <form onSubmit={handleSave} className="p-6 space-y-3.5 text-xs">
                            <div className="grid grid-cols-2 gap-3">
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Party Type *</label>
                                    <select 
                                        value={partyType} 
                                        onChange={(e) => setPartyType(e.target.value)}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2 font-bold text-indigo-700"
                                    >
                                        <option value="Customer">Customer (Debtor)</option>
                                        <option value="Vendor">Vendor (Creditor)</option>
                                        <option value="Both">Both Customer & Vendor</option>
                                    </select>
                                </div>
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">State *</label>
                                    <input 
                                        type="text" 
                                        value={state} 
                                        onChange={(e) => setState(e.target.value)}
                                        placeholder="e.g. Andhra Pradesh"
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2 font-bold text-slate-800"
                                    />
                                </div>
                            </div>

                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 mb-1">Legal / Party Name *</label>
                                <input 
                                    type="text" 
                                    value={name} 
                                    onChange={(e) => setName(e.target.value)}
                                    placeholder="e.g. Lucky Constructions"
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-bold text-slate-900"
                                    required
                                />
                            </div>

                            <div className="grid grid-cols-2 gap-3">
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">GSTIN (15 Digits)</label>
                                    <input 
                                        type="text" 
                                        value={gstin} 
                                        onChange={(e) => {
                                            const v = e.target.value.toUpperCase();
                                            setGstin(v);
                                            if (v.length === 15) setPan(v.substring(2, 12));
                                        }}
                                        maxLength={15}
                                        placeholder="37AAAAA0000A1Z5"
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2 font-mono uppercase text-slate-900"
                                    />
                                </div>
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">PAN Number</label>
                                    <input 
                                        type="text" 
                                        value={pan} 
                                        onChange={(e) => setPan(e.target.value.toUpperCase())}
                                        maxLength={10}
                                        placeholder="AAAAA0000A"
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2 font-mono uppercase text-slate-900"
                                    />
                                </div>
                            </div>

                            <div className="grid grid-cols-2 gap-3">
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Phone Number</label>
                                    <input 
                                        type="text" 
                                        value={phone} 
                                        onChange={(e) => setPhone(e.target.value)}
                                        placeholder="9876543210"
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2 text-slate-800"
                                    />
                                </div>
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Email Address</label>
                                    <input 
                                        type="email" 
                                        value={email} 
                                        onChange={(e) => setEmail(e.target.value)}
                                        placeholder="billing@party.com"
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2 text-slate-800"
                                    />
                                </div>
                            </div>

                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 mb-1">Billing Address</label>
                                <textarea 
                                    rows={2} 
                                    value={billingAddress} 
                                    onChange={(e) => setBillingAddress(e.target.value)}
                                    placeholder="Street, City, Pincode"
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2 text-slate-800"
                                />
                            </div>

                            <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
                                <button 
                                    type="button" 
                                    onClick={() => setShowModal(false)}
                                    className="px-4 py-2 rounded-xl text-slate-600 font-bold hover:bg-slate-100 transition"
                                >
                                    Cancel
                                </button>
                                <button 
                                    type="submit"
                                    className="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-2 rounded-xl font-bold transition shadow-md"
                                >
                                    {editingParty ? 'Update Party' : 'Save Party'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default PartiesTab;
