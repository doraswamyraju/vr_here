import React from 'react';
import { User, X, Plus } from 'lucide-react';

const PartiesTab = ({ parties, onShowAddPartyModal, showAddPartyModal, onCloseAddPartyModal, onSaveParty }) => {
    return (
        <div className="space-y-4">
            <div className="flex justify-between items-center bg-white p-4 border border-slate-200 rounded-2xl">
                <h3 className="font-bold text-slate-800 text-sm">Customers & Parties Listing</h3>
                <button 
                    onClick={onShowAddPartyModal} 
                    className="bg-indigo-600 text-white px-4 py-2 rounded-xl text-xs font-bold hover:bg-indigo-700 transition"
                >
                    + Add New Customer
                </button>
            </div>

            <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
                <table className="w-full text-left border-collapse text-xs">
                    <thead>
                        <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-bold">
                            <th className="p-4">Customer Name</th>
                            <th className="p-4">GSTIN</th>
                            <th className="p-4">Phone Number</th>
                            <th className="p-4">Billing Address</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                        {parties.map((p, idx) => (
                            <tr key={idx} className="hover:bg-slate-50/50">
                                <td className="p-4 font-bold text-slate-800">{p.name}</td>
                                <td className="p-4 font-semibold text-slate-500">{p.gstin || 'N/A'}</td>
                                <td className="p-4 text-slate-600">{p.phone || 'N/A'}</td>
                                <td className="p-4 text-slate-500">{p.address || 'N/A'}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {/* QUICK ADD CUSTOMER MODAL */}
            {showAddPartyModal && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in duration-300">
                    <div className="bg-white w-full max-w-md rounded-[2rem] p-6 shadow-2xl relative animate-in zoom-in-95 duration-300">
                        <button onClick={onCloseAddPartyModal} className="absolute top-5 right-5 text-slate-400 hover:text-slate-600">
                            <X size={20} />
                        </button>
                        <h3 className="text-base font-bold text-slate-800 mb-4 flex items-center gap-2">
                            <User size={18} className="text-indigo-600" /> Add New Customer / Party
                        </h3>
                        <form onSubmit={onSaveParty} className="space-y-4 text-xs">
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Customer / Firm Name *</label>
                                <input 
                                    type="text" 
                                    name="pName"
                                    placeholder="e.g. Lucky Constructions"
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                    required 
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">GSTIN (Optional)</label>
                                <input 
                                    type="text" 
                                    name="pGstin"
                                    maxLength={15}
                                    placeholder="15-digit GSTIN"
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none uppercase"
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Phone Number (Optional)</label>
                                <input 
                                    type="text" 
                                    name="pPhone"
                                    placeholder="10-digit mobile"
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Billing Address (Optional)</label>
                                <textarea 
                                    name="pAddress"
                                    placeholder="Complete billing address"
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                    rows="2"
                                />
                            </div>
                            <button 
                                type="submit" 
                                className="w-full bg-indigo-600 text-white py-3 rounded-xl font-bold hover:bg-indigo-700 transition"
                            >
                                Save Party
                            </button>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default PartiesTab;
