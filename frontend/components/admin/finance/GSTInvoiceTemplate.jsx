import React from 'react';
import { Mail, Phone, MapPin, Globe } from 'lucide-react';

const GSTInvoiceTemplate = ({ data }) => {
    if (!data) return null;

    const { type, number, date, dueDate, client, items, totals, notes, terms } = data;

    return (
        <div className="bg-white p-8 max-w-[800px] mx-auto shadow-2xl border border-slate-100 font-sans text-slate-800 printable-area">
            {/* Header */}
            <div className="flex justify-between items-start border-b-2 border-slate-900 pb-6 mb-8">
                <div>
                    <div className="flex items-center gap-3 mb-4">
                        <div className="w-12 h-12 bg-slate-900 rounded-xl flex items-center justify-center text-white font-black text-xl">VR</div>
                        <div>
                            <h1 className="text-2xl font-black tracking-tighter text-slate-900 leading-none">VR HERE</h1>
                            <p className="text-[10px] font-black text-red-600 uppercase tracking-widest mt-1">Business Solutions</p>
                        </div>
                    </div>
                    <div className="text-[10px] space-y-1 text-slate-500 font-medium">
                        <p className="flex items-center gap-1"><MapPin size={10} /> Hyderabad, Telangana, India</p>
                        <p className="flex items-center gap-1"><Phone size={10} /> +91 80085 30606</p>
                        <p className="flex items-center gap-1"><Mail size={10} /> support@vrhere.in</p>
                        <p className="flex items-center gap-1"><Globe size={10} /> www.vrhere.in</p>
                        <p className="mt-2 font-bold text-slate-900">GSTIN: 36XXXXXXXXXXXXX</p>
                    </div>
                </div>
                <div className="text-right">
                    <h2 className="text-4xl font-black text-slate-900 uppercase tracking-tighter mb-2">{type}</h2>
                    <div className="space-y-1">
                        <p className="text-xs font-bold text-slate-400 uppercase tracking-widest">#{number}</p>
                        <p className="text-sm font-black text-slate-900">{new Date(date).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' })}</p>
                        {dueDate && (
                            <p className="text-[10px] font-bold text-red-600 uppercase tracking-widest">Due: {new Date(dueDate).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' })}</p>
                        )}
                    </div>
                </div>
            </div>

            {/* Bill To / Ship To */}
            <div className="grid grid-cols-2 gap-8 mb-8">
                <div>
                    <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-3">Bill To:</h3>
                    <div className="space-y-1">
                        <p className="font-black text-slate-900 text-lg leading-none mb-2">{client.name}</p>
                        <p className="text-xs text-slate-600 font-medium leading-relaxed whitespace-pre-wrap">{client.address}</p>
                        <p className="text-xs font-bold text-slate-900 mt-2">GSTIN: {client.gstin || 'N/A'}</p>
                        <p className="text-xs text-slate-500">{client.email} | {client.phone}</p>
                    </div>
                </div>
                <div className="bg-slate-50 p-4 rounded-2xl border border-slate-100 flex flex-col justify-center">
                    <div className="flex justify-between items-center mb-2">
                        <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Place of Supply:</span>
                        <span className="text-xs font-black text-slate-900">Telangana (36)</span>
                    </div>
                    <div className="flex justify-between items-center">
                        <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Reverse Charge:</span>
                        <span className="text-xs font-black text-slate-900">No</span>
                    </div>
                </div>
            </div>

            {/* Items Table */}
            <div className="mb-8">
                <table className="w-full text-left border-collapse">
                    <thead>
                        <tr className="bg-slate-900 text-white">
                            <th className="p-3 text-[10px] font-black uppercase tracking-widest rounded-l-xl">Description</th>
                            <th className="p-3 text-[10px] font-black uppercase tracking-widest text-center">HSN/SAC</th>
                            <th className="p-3 text-[10px] font-black uppercase tracking-widest text-center">Qty</th>
                            <th className="p-3 text-[10px] font-black uppercase tracking-widest text-right">Rate</th>
                            <th className="p-3 text-[10px] font-black uppercase tracking-widest text-right">GST</th>
                            <th className="p-3 text-[10px] font-black uppercase tracking-widest text-right rounded-r-xl">Amount</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                        {items.map((item, index) => (
                            <tr key={index} className="group">
                                <td className="p-4">
                                    <p className="text-sm font-black text-slate-900">{item.description}</p>
                                </td>
                                <td className="p-4 text-center text-xs text-slate-500 font-bold">{item.hsn || '998311'}</td>
                                <td className="p-4 text-center text-xs text-slate-900 font-black">{item.qty}</td>
                                <td className="p-4 text-right text-xs text-slate-900 font-bold">₹{item.rate.toLocaleString()}</td>
                                <td className="p-4 text-right text-xs text-slate-500 font-medium">{item.taxRate}%</td>
                                <td className="p-4 text-right text-sm font-black text-slate-900">₹{item.amount.toLocaleString()}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {/* Totals Section */}
            <div className="flex justify-end mb-12">
                <div className="w-64 space-y-3">
                    <div className="flex justify-between items-center text-sm">
                        <span className="font-bold text-slate-500">Subtotal</span>
                        <span className="font-black text-slate-900">₹{totals.subtotal.toLocaleString()}</span>
                    </div>
                    {totals.cgst > 0 && (
                        <div className="flex justify-between items-center text-xs">
                            <span className="font-medium text-slate-400 tracking-widest uppercase">CGST</span>
                            <span className="font-bold text-slate-900">₹{totals.cgst.toLocaleString()}</span>
                        </div>
                    )}
                    {totals.sgst > 0 && (
                        <div className="flex justify-between items-center text-xs">
                            <span className="font-medium text-slate-400 tracking-widest uppercase">SGST</span>
                            <span className="font-bold text-slate-900">₹{totals.sgst.toLocaleString()}</span>
                        </div>
                    )}
                    {totals.igst > 0 && (
                        <div className="flex justify-between items-center text-xs">
                            <span className="font-medium text-slate-400 tracking-widest uppercase">IGST</span>
                            <span className="font-bold text-slate-900">₹{totals.igst.toLocaleString()}</span>
                        </div>
                    )}
                    <div className="pt-3 border-t-2 border-slate-900 flex justify-between items-center">
                        <span className="text-lg font-black text-slate-900 tracking-tighter uppercase">Total</span>
                        <span className="text-2xl font-black text-slate-900 tracking-tighter">₹{totals.total.toLocaleString()}</span>
                    </div>
                </div>
            </div>

            {/* Footer / Bank Details */}
            <div className="grid grid-cols-2 gap-12 pt-8 border-t border-slate-100">
                <div>
                    <h4 className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-3">Bank Details:</h4>
                    <div className="text-[10px] space-y-1 text-slate-600 font-bold">
                        <p>Bank: HDFC BANK LTD</p>
                        <p>A/c Name: VR HERE BUSINESS SOLUTIONS</p>
                        <p>A/c No: XXXXXXXXXXXXXXXX</p>
                        <p>IFSC: HDFC000XXXX</p>
                        <p>Branch: HYDERABAD</p>
                    </div>
                    {notes && (
                        <div className="mt-6">
                            <h4 className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1">Notes:</h4>
                            <p className="text-[10px] text-slate-500 font-medium leading-relaxed">{notes}</p>
                        </div>
                    )}
                </div>
                <div className="text-right flex flex-col justify-between items-end">
                    <div className="text-center">
                        <p className="text-[10px] font-black text-slate-900 uppercase tracking-widest mb-12">Authorized Signatory</p>
                        <div className="w-40 h-px bg-slate-900 mb-2"></div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">VR HERE BUSINESS SOLUTIONS</p>
                    </div>
                    <p className="text-[8px] text-slate-400 font-bold uppercase tracking-widest italic mt-8">
                        This is a computer generated document and does not require a physical signature.
                    </p>
                </div>
            </div>
        </div>
    );
};

export default GSTInvoiceTemplate;
