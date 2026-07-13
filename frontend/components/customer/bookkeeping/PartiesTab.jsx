import React, { useState } from 'react';
import { User, X, Plus, Search, Trash2, Edit2, Download } from 'lucide-react';

const PartiesTab = ({ 
    parties, 
    onShowAddPartyModal, 
    showAddPartyModal, 
    onCloseAddPartyModal, 
    onSaveParty,
    onDeleteParty
}) => {
    const [searchPartyQuery, setSearchPartyQuery] = useState('');
    const [editingIndex, setEditingIndex] = useState(null);

    // Form inputs state for Quick Add/Edit Modal
    const [pName, setPName] = useState('');
    const [pGstin, setPGstin] = useState('');
    const [pPhone, setPPhone] = useState('');
    const [pAddress, setPAddress] = useState('');

    const handleOpenAdd = () => {
        setEditingIndex(null);
        setPName('');
        setPGstin('');
        setPPhone('');
        setPAddress('');
        onShowAddPartyModal();
    };

    const handleOpenEdit = (idx, party) => {
        setEditingIndex(idx);
        setPName(party.name);
        setPGstin(party.gstin || '');
        setPPhone(party.phone || '');
        setPAddress(party.address || '');
        onShowAddPartyModal();
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        onSaveParty({
            index: editingIndex,
            name: pName,
            gstin: pGstin.toUpperCase(),
            phone: pPhone,
            address: pAddress
        });
        onCloseAddPartyModal();
    };

    // Download customer database as CSV
    const exportCSV = () => {
        const headers = ['Customer Name', 'GSTIN', 'Phone Number', 'Billing Address'];
        const rows = parties.map(p => [
            p.name,
            p.gstin || 'N/A',
            p.phone || 'N/A',
            (p.address || 'N/A').replace(/,/g, ' ')
        ]);
        
        const csvContent = "data:text/csv;charset=utf-8," 
            + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
        
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", `customers_master_${new Date().toISOString().split('T')[0]}.csv`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    const filteredParties = parties.filter(p => {
        const q = searchPartyQuery.toLowerCase();
        return p.name.toLowerCase().includes(q) || 
               (p.gstin || '').toLowerCase().includes(q) || 
               (p.phone || '').toLowerCase().includes(q);
    });

    return (
        <div className="space-y-4 animate-in fade-in duration-300">
            <div className="flex justify-between items-center bg-white p-4 border border-slate-200 rounded-2xl flex-wrap gap-4">
                <div className="flex items-center gap-3">
                    <h3 className="font-bold text-slate-800 text-sm">Customers & Parties Listing</h3>
                    <span className="bg-indigo-50 text-indigo-600 px-2 py-0.5 rounded-lg text-[10px] font-bold">
                        {parties.length} Saved
                    </span>
                </div>
                
                <div className="flex gap-2">
                    <button 
                        onClick={exportCSV}
                        className="bg-slate-100 text-slate-700 hover:bg-slate-200 px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-1.5"
                        title="Export customer list to Excel/CSV"
                    >
                        <Download size={14} /> Export CSV
                    </button>
                    <button 
                        onClick={handleOpenAdd} 
                        className="bg-indigo-600 text-white px-4 py-2 rounded-xl text-xs font-bold hover:bg-indigo-700 transition"
                    >
                        + Add New Customer
                    </button>
                </div>
            </div>

            {/* Search Input bar */}
            <div className="relative max-w-md bg-white border border-slate-200 rounded-xl p-1.5 flex items-center">
                <Search className="text-slate-400 ml-2" size={16} />
                <input 
                    type="text" 
                    placeholder="Search customers by name, GSTIN, or phone..."
                    value={searchPartyQuery}
                    onChange={e => setSearchPartyQuery(e.target.value)}
                    className="w-full bg-transparent border-0 pl-2 pr-4 py-1.5 text-xs text-slate-800 focus:outline-none"
                />
            </div>

            <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
                <table className="w-full text-left border-collapse text-xs">
                    <thead>
                        <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-bold">
                            <th className="p-4">Customer Name</th>
                            <th className="p-4">GSTIN</th>
                            <th className="p-4">Phone Number</th>
                            <th className="p-4">Billing Address</th>
                            <th className="p-4 text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                        {filteredParties.length === 0 ? (
                            <tr>
                                <td colSpan="5" className="p-8 text-center text-slate-400 font-medium">
                                    No matching customers found.
                                </td>
                            </tr>
                        ) : filteredParties.map((p, idx) => (
                            <tr key={idx} className="hover:bg-slate-50/50 transition">
                                <td className="p-4 font-bold text-slate-800">{p.name}</td>
                                <td className="p-4 font-semibold text-slate-500">{p.gstin || 'N/A'}</td>
                                <td className="p-4 text-slate-600">{p.phone || 'N/A'}</td>
                                <td className="p-4 text-slate-500">{p.address || 'N/A'}</td>
                                <td className="p-4 text-right space-x-1.5">
                                    <button 
                                        onClick={() => handleOpenEdit(idx, p)}
                                        className="text-indigo-600 hover:bg-indigo-50 p-2 rounded-lg transition"
                                        title="Edit Customer"
                                    >
                                        <Edit2 size={13} />
                                    </button>
                                    <button 
                                        onClick={() => onDeleteParty(idx)}
                                        className="text-rose-500 hover:bg-rose-50 p-2 rounded-lg transition"
                                        title="Delete Customer"
                                    >
                                        <Trash2 size={13} />
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {/* QUICK ADD / EDIT CUSTOMER MODAL */}
            {showAddPartyModal && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in duration-300">
                    <div className="bg-white w-full max-w-md rounded-[2rem] p-6 shadow-2xl relative animate-in zoom-in-95 duration-300">
                        <button onClick={onCloseAddPartyModal} className="absolute top-5 right-5 text-slate-400 hover:text-slate-600">
                            <X size={20} />
                        </button>
                        <h3 className="text-base font-bold text-slate-800 mb-4 flex items-center gap-2">
                            <User size={18} className="text-indigo-600" /> {editingIndex !== null ? 'Edit Customer Details' : 'Add New Customer / Party'}
                        </h3>
                        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Customer / Firm Name *</label>
                                <input 
                                    type="text" 
                                    value={pName}
                                    onChange={e => setPName(e.target.value)}
                                    placeholder="e.g. Lucky Constructions"
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                    required 
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">GSTIN (Optional)</label>
                                <input 
                                    type="text" 
                                    value={pGstin}
                                    onChange={e => setPGstin(e.target.value)}
                                    maxLength={15}
                                    placeholder="15-digit GSTIN"
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none uppercase"
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Phone Number (Optional)</label>
                                <input 
                                    type="text" 
                                    value={pPhone}
                                    onChange={e => setPPhone(e.target.value)}
                                    placeholder="10-digit mobile"
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Billing Address (Optional)</label>
                                <textarea 
                                    value={pAddress}
                                    onChange={e => setPAddress(e.target.value)}
                                    placeholder="Complete billing address"
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                    rows="2"
                                />
                            </div>
                            <button 
                                type="submit" 
                                className="w-full bg-indigo-600 text-white py-3 rounded-xl font-bold hover:bg-indigo-700 transition"
                            >
                                {editingIndex !== null ? 'Save Changes' : 'Save Customer'}
                            </button>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default PartiesTab;
