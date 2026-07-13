import React from 'react';
import { Printer, Share2, Award, ShieldCheck } from 'lucide-react';

const GSTInvoiceView = ({ selectedInvoice, company, onBack, onCopyShareLink }) => {
    if (!selectedInvoice) return null;
    
    const isSales = selectedInvoice.transactionType === 'Sales';
    const isVoucher = selectedInvoice.transactionType === 'Income' || selectedInvoice.transactionType === 'Expense';

    // Safe variables
    const docNumber = selectedInvoice.docNumber || 'N/A';
    const docDate = selectedInvoice.docDate ? new Date(selectedInvoice.docDate).toLocaleDateString('en-IN') : 'N/A';
    const partyName = selectedInvoice.partyName || 'N/A';
    const partyGstin = selectedInvoice.partyGstin || 'N/A';
    const placeOfSupply = selectedInvoice.placeOfSupply || 'N/A';
    const notes = selectedInvoice.notes || '';
    const items = selectedInvoice.items || [];
    const totalAmount = selectedInvoice.summary?.totalAmount || 0;
    const totalTaxableValue = selectedInvoice.summary?.totalTaxableValue || 0;
    const paymentMode = selectedInvoice.paymentType || 'Cash';

    // Bank Details from company
    const bankDetails = company?.bankDetails || {};
    const bankName = bankDetails.bankName || 'N/A';
    const bankAccount = bankDetails.accountNumber || 'N/A';
    const bankIfsc = bankDetails.ifscCode || 'N/A';

    return (
        <div className="space-y-6 pb-20 max-w-4xl mx-auto animate-in fade-in duration-300">
            {/* Inject CSS print stylesheet to hide entire dashboard body, sidebar, footer during print */}
            <style>{`
                @media print {
                    body {
                        background-color: white !important;
                        color: black !important;
                    }
                    /* Hide everything in the page */
                    body * {
                        visibility: hidden;
                    }
                    /* Show only the printable invoice card */
                    .printable-area, .printable-area * {
                        visibility: visible;
                    }
                    .printable-area {
                        position: absolute;
                        left: 0;
                        top: 0;
                        width: 100%;
                        border: none !important;
                        box-shadow: none !important;
                        padding: 0 !important;
                        margin: 0 !important;
                    }
                    .no-print {
                        display: none !important;
                    }
                }
            `}</style>

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
            <div className="bg-white p-8 md:p-12 rounded-[2.5rem] border border-slate-200 shadow-xl font-sans text-slate-800 printable-area space-y-8">
                {/* Header */}
                <div className="flex justify-between items-start border-b-2 border-slate-800 pb-6">
                    <div className="flex items-start gap-4">
                        {/* Beautiful generated logo badge */}
                        <div className="w-14 h-14 bg-slate-900 rounded-2xl flex flex-col items-center justify-center text-white font-black text-lg shadow-md shrink-0">
                            {company?.companyName ? company.companyName.split(' ').map(n=>n[0]).join('').slice(0, 3).toUpperCase() : 'CO'}
                        </div>
                        <div>
                            <h1 className="text-2xl font-black tracking-tight text-slate-900 leading-none">
                                {isSales ? (company?.companyName || 'TAX INVOICE') : partyName}
                            </h1>
                            <p className="text-xs font-black text-indigo-600 uppercase tracking-widest mt-1.5">
                                {isSales ? (company?.tradeName || 'GST Registered Supplier') : 'Supplier Vendor'}
                            </p>
                            
                            <div className="text-[11px] space-y-1 text-slate-500 font-medium mt-3">
                                <p>Address: {isSales ? (company?.address || 'N/A') : 'Refer to vendor records'}</p>
                                <p className="font-bold text-slate-800">GSTIN: {isSales ? (company?.gstin || 'N/A') : partyGstin}</p>
                                <p>State: {isSales ? (company?.state || 'N/A') : placeOfSupply}</p>
                            </div>
                        </div>
                    </div>

                    <div className="text-right">
                        <h2 className="text-2xl font-black text-slate-900 uppercase tracking-wide mb-1">
                            {isSales ? 'TAX INVOICE' : isVoucher ? (selectedInvoice.transactionType === 'Expense' ? 'PAYMENT VOUCHER' : 'RECEIPT VOUCHER') : 'PURCHASE BILL'}
                        </h2>
                        <p className="text-xs font-bold text-slate-400">No: {docNumber}</p>
                        <p className="text-xs font-bold text-slate-500 mt-2">Date: {docDate}</p>
                    </div>
                </div>

                {/* Bill To & Supply Jurisdictions */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <div>
                        <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-2">Billed To (Recipient):</h3>
                        <p className="font-black text-slate-900 text-lg leading-none mb-2">
                            {isSales ? partyName : (company?.companyName || 'N/A')}
                        </p>
                        <p className="text-xs text-slate-600 leading-relaxed mb-2">
                            {isSales ? 'Recipient billing address' : (company?.address || 'N/A')}
                        </p>
                        <p className="text-xs font-bold text-slate-800">
                            GSTIN: {isSales ? partyGstin : (company?.gstin || 'N/A')}
                        </p>
                    </div>

                    <div className="bg-slate-50 p-6 rounded-3xl border border-slate-100 flex flex-col justify-center gap-2 text-xs">
                        <div className="flex justify-between">
                            <span className="text-slate-400 font-bold uppercase text-[9px] tracking-wider">Place of Supply:</span>
                            <span className="font-bold text-slate-800">{placeOfSupply}</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-slate-400 font-bold uppercase text-[9px] tracking-wider">Payment Mode:</span>
                            <span className="font-bold text-slate-800">{paymentMode}</span>
                        </div>
                        {selectedInvoice.itcEligibility && selectedInvoice.itcEligibility !== 'N/A' && (
                            <div className="flex justify-between">
                                <span className="text-slate-400 font-bold uppercase text-[9px] tracking-wider">ITC Eligibility:</span>
                                <span className="font-bold text-indigo-600">{selectedInvoice.itcEligibility}</span>
                            </div>
                        )}
                    </div>
                </div>

                {/* Table details */}
                <div className="border border-slate-200 rounded-2xl overflow-hidden">
                    <table className="w-full text-left border-collapse text-xs">
                        <thead>
                            <tr className="bg-slate-900 text-white font-bold">
                                <th className="p-3 pl-6">Particulars / Item Description</th>
                                {!isVoucher && <th className="p-3 text-center">Qty</th>}
                                {!isVoucher && <th className="p-3 text-right">Price/Unit</th>}
                                {!isVoucher && <th className="p-3 text-right">Tax Rate</th>}
                                <th className="p-3 text-right pr-6">Amount</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-200">
                            {items.map((item, idx) => (
                                <tr key={idx} className="hover:bg-slate-50/20">
                                    <td className="p-4 pl-6 font-bold text-slate-900">{item.description}</td>
                                    {!isVoucher && <td className="p-4 text-center font-bold text-slate-800">{item.qty}</td>}
                                    {!isVoucher && <td className="p-4 text-right font-medium">₹{item.rate?.toLocaleString() || '0'}</td>}
                                    {!isVoucher && <td className="p-4 text-right text-slate-600">{item.gstRate}%</td>}
                                    <td className="p-4 text-right pr-6 font-black text-slate-900">₹{item.amount?.toLocaleString() || '0'}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>

                {/* Totals & Signatures Block */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8 pt-4 border-t border-slate-100">
                    <div className="space-y-4">
                        {/* Bank Details */}
                        {bankAccount && bankAccount !== 'N/A' && (
                            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl max-w-sm text-xs">
                                <h4 className="font-black text-slate-800 mb-2 uppercase tracking-wide text-[9px] text-indigo-600">Bank Details (For Transfers)</h4>
                                <p className="font-semibold">Bank: {bankName}</p>
                                <p className="font-semibold">A/c Number: {bankAccount}</p>
                                <p className="font-semibold">IFSC Code: {bankIfsc}</p>
                            </div>
                        )}
                        <p className="text-[10px] text-slate-400 font-medium italic leading-relaxed">
                            Declaration: We declare that this voucher/invoice shows the actual price of the goods or services described and that all particulars are true and correct.
                        </p>
                    </div>

                    <div className="flex flex-col justify-between items-end gap-6">
                        {/* Invoice summary values */}
                        <div className="w-full space-y-2 text-xs">
                            <div className="flex justify-between">
                                <span className="font-bold text-slate-500">Subtotal Taxable Amount:</span>
                                <span className="font-bold text-slate-950">₹{totalTaxableValue.toLocaleString()}</span>
                            </div>
                            <div className="h-px bg-slate-200" />
                            <div className="flex justify-between text-base">
                                <span className="font-black text-slate-900">Grand Total:</span>
                                <span className="font-black text-indigo-600">₹{totalAmount.toLocaleString()}</span>
                            </div>
                        </div>

                        {/* Signatures block */}
                        <div className="text-center pt-8 border-t border-slate-100 w-64">
                            {/* Signature Placeholder script */}
                            <p className="font-script text-indigo-700 text-lg leading-none select-none tracking-widest italic font-bold">
                                {company?.companyName || 'Signatory'}
                            </p>
                            <div className="h-px bg-slate-300 w-full my-1" />
                            <p className="text-[9px] font-black uppercase text-slate-400 tracking-wider">Authorized Signatory</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default GSTInvoiceView;
