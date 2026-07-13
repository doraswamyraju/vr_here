import React from 'react';
import { Printer, Share2 } from 'lucide-react';

const GSTInvoiceView = ({ selectedInvoice, company, onBack, onCopyShareLink }) => {
    if (!selectedInvoice) return null;
    const isSales = selectedInvoice.transactionType === 'Sales';

    return (
        <div className="space-y-6 pb-20 max-w-4xl mx-auto animate-in fade-in duration-300">
            <div className="flex justify-between items-center bg-white p-4 rounded-3xl border border-slate-200 sticky top-0 z-10 shadow-sm no-print text-xs">
                <button 
                    onClick={onBack} 
                    className="flex items-center gap-2 text-slate-600 font-bold hover:text-slate-900 transition"
                >
                     ← Back to Ledger
                </button>
                <div className="flex gap-2">
                    <button 
                        onClick={onCopyShareLink}
                        className="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2.5 rounded-xl font-bold flex items-center gap-1.5 transition"
                    >
                        <Share2 size={14} /> Copy Share Link
                    </button>
                    <button 
                        onClick={() => window.print()} 
                        className="bg-indigo-600 text-white px-5 py-2.5 rounded-xl font-bold hover:bg-indigo-700 transition flex items-center gap-1.5 shadow-lg shadow-indigo-100"
                    >
                        <Printer size={14} /> Print / Save PDF
                    </button>
                </div>
            </div>

            {/* Standard GST Invoice visual layout */}
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
};

export default GSTInvoiceView;
