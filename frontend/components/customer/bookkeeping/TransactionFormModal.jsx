import React from 'react';
import { X, Camera, Plus } from 'lucide-react';

const TransactionFormModal = ({
    show, onClose, onSubmit,
    txType, setTxType,
    docNumber, setDocNumber,
    docDate, setDocDate,
    placeOfSupply, setPlaceOfSupply,
    isInterstate,
    partyName, setPartyName,
    partyGstin, setPartyGstin,
    parties, onShowAddPartyModal,
    onPartySelect,
    availableUnits, onShowAddUnitInline,
    items, onAddItem, onRemoveItem, onItemChange,
    paymentType, setPaymentType,
    notes, setNotes,
    uploadingBill, onOCRUpload
}) => {
    if (!show) return null;

    return (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex justify-center items-center p-4 animate-in fade-in duration-300">
            <div className="bg-white w-full max-w-5xl rounded-3xl shadow-2xl overflow-y-auto max-h-[90vh] flex flex-col p-6 animate-in zoom-in-95 duration-300">
                <div className="flex justify-between items-center mb-6 border-b border-slate-200 pb-3">
                    <h3 className="text-base font-bold text-slate-800">
                        Record Entry: {txType}
                    </h3>
                    <div className="flex items-center gap-2">
                        <span className="text-[10px] font-black text-slate-400 uppercase">Change Type:</span>
                        {['Sales', 'Purchase', 'Income', 'Expense'].map(type => (
                            <button 
                                key={type}
                                type="button"
                                onClick={() => setTxType(type)}
                                className={`px-3 py-1 rounded-lg text-[10px] font-bold uppercase transition ${txType === type ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-600'}`}
                            >
                                {type}
                            </button>
                        ))}
                    </div>
                </div>

                {/* OCR Upload component */}
                {(txType === 'Purchase' || txType === 'Expense') && (
                    <div className="mb-4 p-4 bg-indigo-50 border border-indigo-100 rounded-2xl flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <div className="w-9 h-9 bg-white rounded-xl flex items-center justify-center text-indigo-600 shadow-sm">
                                <Camera size={18} />
                            </div>
                            <div>
                                <h4 className="font-bold text-slate-800 text-xs">OCR Bill scanner & Photo upload</h4>
                                <p className="text-slate-400 text-[10px]">Select or snap a receipt to automatically parse transaction detail fields</p>
                            </div>
                        </div>
                        <label className="bg-indigo-600 text-white px-4 py-2 rounded-xl text-xs font-bold hover:bg-indigo-700 transition cursor-pointer">
                            {uploadingBill ? 'Extracting...' : 'Scan / Upload Receipt'}
                            <input type="file" accept="image/*" onChange={onOCRUpload} className="hidden" />
                        </label>
                    </div>
                )}

                <form onSubmit={onSubmit} className="space-y-6 flex-1 text-xs">
                    {/* Top info section */}
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 bg-slate-50 p-4 rounded-2xl border border-slate-200">
                        <div className="space-y-1">
                            <label className="font-bold text-slate-600">Party / Customer Name *</label>
                            <div className="flex gap-1.5">
                                <select 
                                    value={partyName} 
                                    onChange={e => onPartySelect(e.target.value)} 
                                    className="flex-1 bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                    required
                                >
                                    <option value="">-- Choose Customer --</option>
                                    {parties.map((p, idx) => (
                                        <option key={idx} value={p.name}>{p.name}</option>
                                    ))}
                                </select>
                                <button 
                                    type="button" 
                                    onClick={onShowAddPartyModal}
                                    className="bg-slate-900 text-white p-2 rounded-xl hover:bg-slate-800"
                                    title="Add New Customer"
                                >
                                    <Plus size={16} />
                                </button>
                            </div>
                        </div>
                        <div className="space-y-1">
                            <label className="font-bold text-slate-600">Voucher / Invoice No</label>
                            <input 
                                type="text" 
                                value={docNumber} 
                                onChange={e => setDocNumber(e.target.value)}
                                className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none font-bold"
                                required
                            />
                        </div>
                        <div className="space-y-1">
                            <label className="font-bold text-slate-600">Document Date *</label>
                            <input 
                                type="date" 
                                value={docDate} 
                                onChange={e => setDocDate(e.target.value)} 
                                className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                required 
                            />
                        </div>
                        <div className="space-y-1">
                            <label className="font-bold text-slate-600">Place of Supply</label>
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

                    {/* Tax auto warning */}
                    <div className="flex justify-between items-center bg-slate-50 p-3 rounded-xl border border-slate-200">
                        <div>
                            <span className="font-bold text-slate-700">GST Registration: </span>
                            <span className="text-slate-500 font-semibold uppercase">{partyGstin || 'Unregistered Client'}</span>
                        </div>
                        <div>
                            <span className="font-bold text-slate-700">Tax Type Detected: </span>
                            <span className={`font-bold px-2 py-0.5 rounded ${isInterstate ? 'bg-amber-100 text-amber-800' : 'bg-emerald-100 text-emerald-800'}`}>
                                {isInterstate ? 'INTERSTATE (IGST)' : 'INTRASTATE (CGST + SGST)'}
                            </span>
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
                                    <th className="p-3 w-32">UNIT</th>
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
                                                onChange={e => onItemChange(idx, 'description', e.target.value)} 
                                                placeholder="Item Name"
                                                className="w-full bg-transparent border-b border-slate-200 focus:border-indigo-600 py-1 focus:outline-none"
                                                required 
                                            />
                                        </td>
                                        <td className="p-3">
                                            <input 
                                                type="number" 
                                                value={item.qty} 
                                                onChange={e => onItemChange(idx, 'qty', parseInt(e.target.value) || 0)} 
                                                className="w-full bg-transparent border-b border-slate-200 focus:border-indigo-600 py-1 focus:outline-none text-center"
                                                min="1"
                                                required 
                                            />
                                        </td>
                                        <td className="p-3">
                                            <div className="flex items-center gap-1">
                                                <select 
                                                    value={item.unit}
                                                    onChange={e => onItemChange(idx, 'unit', e.target.value)}
                                                    className="flex-1 bg-transparent border-b border-slate-200 focus:border-indigo-600 py-1 focus:outline-none"
                                                >
                                                    {availableUnits.map((u, ui) => (
                                                        <option key={ui} value={u}>{u}</option>
                                                    ))}
                                                </select>
                                                <button 
                                                    type="button" 
                                                    onClick={onShowAddUnitInline}
                                                    className="text-indigo-600 hover:text-indigo-800"
                                                    title="Add custom unit"
                                                >
                                                    +
                                                </button>
                                            </div>
                                        </td>
                                        <td className="p-3">
                                            <input 
                                                type="number" 
                                                value={item.rate} 
                                                onChange={e => onItemChange(idx, 'rate', parseFloat(e.target.value) || 0)} 
                                                className="w-full bg-transparent border-b border-slate-200 focus:border-indigo-600 py-1 focus:outline-none"
                                                min="0"
                                                required 
                                            />
                                        </td>
                                        <td className="p-3">
                                            <input 
                                                type="number" 
                                                value={item.discountPercent} 
                                                onChange={e => onItemChange(idx, 'discountPercent', parseFloat(e.target.value) || 0)} 
                                                className="w-full bg-transparent border-b border-slate-200 focus:border-indigo-600 py-1 focus:outline-none text-center"
                                                min="0"
                                                max="100"
                                            />
                                        </td>
                                        <td className="p-3">
                                            <select 
                                                value={item.gstRate} 
                                                onChange={e => onItemChange(idx, 'gstRate', parseInt(e.target.value) || 0)}
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
                                                    onClick={() => onRemoveItem(idx)}
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
                                        onClick={onAddItem}
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
                                    onClick={onClose}
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
    );
};

export default TransactionFormModal;
