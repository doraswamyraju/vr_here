import React from 'react';
import { Printer, Share2, ArrowLeft, Download, MessageCircle } from 'lucide-react';

const GSTInvoiceView = ({ selectedInvoice, company, onBack, onCopyShareLink }) => {
    if (!selectedInvoice) return null;
    
    const isSales = selectedInvoice.transactionType === 'Sales';
    const isPurchase = selectedInvoice.transactionType === 'Purchase';

    // Invoice info
    const copyType = selectedInvoice.copyType || 'Original for Recipient';
    const docNumber = selectedInvoice.docNumber || 'INV-0001';
    const docDate = selectedInvoice.docDate ? new Date(selectedInvoice.docDate).toLocaleDateString('en-GB') : 'DD/MM/YYYY';
    const dueDate = selectedInvoice.dueDate ? new Date(selectedInvoice.dueDate).toLocaleDateString('en-GB') : docDate;
    const paymentMode = selectedInvoice.paymentMode || selectedInvoice.paymentType || 'Bank Transfer';
    const placeOfSupply = selectedInvoice.placeOfSupply || company?.state || 'Andhra Pradesh';

    // Supplier Info (For sales: our company. For purchase: party)
    const supplierName = isSales ? (company?.companyName || 'Business Name') : selectedInvoice.partyName;
    const supplierTrade = isSales ? (company?.tradeName || '') : '';
    const supplierAddress = isSales ? (company?.address || 'Address Line, City, State - PIN') : (selectedInvoice.partyAddress || '');
    const supplierGstin = isSales ? (company?.gstin || 'N/A') : selectedInvoice.partyGstin;
    const supplierState = isSales ? (company?.state || 'State') : placeOfSupply;
    const supplierPhone = isSales ? (company?.phone || '') : selectedInvoice.partyPhone;
    const supplierEmail = isSales ? (company?.email || '') : selectedInvoice.partyEmail;

    // Bill To (Customer / Recipient)
    const billToName = isSales ? selectedInvoice.partyName : (company?.companyName || 'Business Name');
    const billToAddress = isSales ? (selectedInvoice.partyAddress || 'N/A') : (company?.address || 'N/A');
    const billToGstin = isSales ? (selectedInvoice.partyGstin || 'URP / N/A') : (company?.gstin || 'N/A');
    const billToPan = isSales ? (selectedInvoice.partyPan || (selectedInvoice.partyGstin?.length === 15 ? selectedInvoice.partyGstin.substring(2, 12) : 'N/A')) : 'N/A';
    const billToState = isSales ? (selectedInvoice.partyState || placeOfSupply) : (company?.state || 'N/A');
    const billToPhone = isSales ? (selectedInvoice.partyPhone || 'N/A') : (company?.phone || 'N/A');
    const billToEmail = isSales ? (selectedInvoice.partyEmail || 'N/A') : (company?.email || 'N/A');

    // Ship To (Consignee)
    const shipToSame = selectedInvoice.shipToSameAsBilling !== false;
    const shipToName = shipToSame ? billToName : (selectedInvoice.shipToName || billToName);
    const shipToAddress = shipToSame ? billToAddress : (selectedInvoice.shipToAddress || billToAddress);
    const shipToGstin = shipToSame ? billToGstin : (selectedInvoice.shipToGstin || billToGstin);
    const shipToPan = shipToSame ? billToPan : (selectedInvoice.shipToPan || billToPan);
    const shipToState = shipToSame ? billToState : (selectedInvoice.shipToState || billToState);
    const shipToPhone = shipToSame ? billToPhone : (selectedInvoice.shipToMobile || billToPhone);
    const shipToEmail = shipToSame ? billToEmail : (selectedInvoice.shipToEmail || billToEmail);

    // Items & summary
    const items = selectedInvoice.items || [];
    const summary = selectedInvoice.summary || {
        totalTaxableValue: 0,
        totalCgst: 0,
        totalSgst: 0,
        totalIgst: 0,
        roundOff: 0,
        totalAmount: 0,
        amountInWords: ''
    };

    // Bank Details
    const bankDetails = company?.bankDetails || {};
    const bankName = bankDetails.bankName || 'HDFC Bank';
    const bankAccount = bankDetails.accountNumber || '50200012345678';
    const bankIfsc = bankDetails.ifscCode || 'HDFC0001234';
    const bankBranch = bankDetails.accountName ? `${bankDetails.accountName} A/c` : 'Main Branch';
    const upiId = company?.upiId || '';

    // Terms
    const defaultTerms = [
        '1. Payment: Payment must be made as per the terms and due date mentioned in the invoice.',
        '2. Taxes: GST and other applicable taxes will be charged as per prevailing laws.',
        '3. Disputes: Any discrepancy in the invoice must be reported within 7 days of receipt.',
        "4. Jurisdiction: Any disputes shall be subject to the jurisdiction of the seller's place of business."
    ];
    const terms = selectedInvoice.termsAndConditions && selectedInvoice.termsAndConditions.length > 0 
        ? selectedInvoice.termsAndConditions 
        : defaultTerms;

    const handleWhatsAppShare = () => {
        const text = `*Tax Invoice from ${supplierName}*%0AInvoice No: ${docNumber}%0ADate: ${docDate}%0ATotal Amount: ₹${summary.totalAmount.toLocaleString('en-IN')}%0APlease let us know if you have any questions!`;
        const phone = selectedInvoice.partyPhone ? selectedInvoice.partyPhone.replace(/[^0-9]/g, '') : '';
        const url = phone ? `https://wa.me/91${phone}?text=${text}` : `https://wa.me/?text=${text}`;
        window.open(url, '_blank');
    };

    return (
        <div className="space-y-6 pb-20 max-w-5xl mx-auto animate-in fade-in duration-300">
            {/* Print Styles */}
            <style>{`
                @media print {
                    @page {
                        size: A4;
                        margin: 8mm;
                    }
                    body {
                        background-color: white !important;
                        color: black !important;
                    }
                    body * {
                        visibility: hidden;
                    }
                    .printable-area, .printable-area * {
                        visibility: visible;
                    }
                    .printable-area {
                        position: absolute;
                        left: 0;
                        top: 0;
                        width: 100% !important;
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

            {/* Actions Bar */}
            <div className="flex flex-wrap justify-between items-center bg-white p-4 rounded-3xl border border-slate-200/80 sticky top-0 z-10 shadow-sm no-print text-xs gap-3">
                <button 
                    onClick={onBack} 
                    className="flex items-center gap-2 text-slate-700 font-bold hover:text-slate-900 transition px-3 py-2 rounded-xl hover:bg-slate-100"
                >
                    <ArrowLeft size={16} /> Back to Invoices
                </button>
                <div className="flex items-center gap-2 flex-wrap">
                    <button 
                        onClick={handleWhatsAppShare}
                        className="bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-xl font-bold flex items-center gap-1.5 transition shadow-sm"
                    >
                        <MessageCircle size={15} /> WhatsApp
                    </button>
                    <button 
                        onClick={onCopyShareLink}
                        className="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-xl font-bold flex items-center gap-1.5 transition"
                    >
                        <Share2 size={15} /> Share Link
                    </button>
                    <button 
                        onClick={() => window.print()} 
                        className="bg-indigo-600 text-white px-5 py-2 rounded-xl font-bold hover:bg-indigo-700 transition flex items-center gap-1.5 shadow-md shadow-indigo-200"
                    >
                        <Printer size={15} /> Print / Save PDF
                    </button>
                </div>
            </div>

            {/* Printable Invoice matching SALES INVOICE TEMPLATE.xlsx */}
            <div className="bg-white p-6 md:p-10 rounded-3xl border border-slate-300 shadow-xl font-sans text-slate-900 printable-area text-[11px] leading-tight">
                
                {/* Top Copy Indicator */}
                <div className="flex justify-end mb-1">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest bg-slate-100 px-2.5 py-0.5 rounded border border-slate-200">
                        copy : {copyType.toLowerCase()}
                    </span>
                </div>

                {/* Company & Invoice Header */}
                <div className="grid grid-cols-12 border-2 border-slate-900 rounded-t-xl p-4 gap-4 bg-slate-50/40">
                    <div className="col-span-7 flex gap-3">
                        {company?.logo && (
                            <img src={company.logo} alt="Logo" className="w-16 h-16 object-contain rounded border border-slate-200 bg-white p-1 shrink-0" />
                        )}
                        <div className="space-y-1">
                            <h1 className="text-xl font-black text-slate-900 leading-none">{supplierName}</h1>
                            {supplierTrade && <p className="text-[10px] font-bold text-indigo-600 uppercase tracking-wider">{supplierTrade}</p>}
                            <p className="text-slate-600">{supplierAddress}</p>
                            <p className="font-bold text-slate-800">
                                GSTIN: <span className="font-mono">{supplierGstin}</span> &nbsp;|&nbsp; State: {supplierState}
                            </p>
                            {(supplierPhone || supplierEmail) && (
                                <p className="text-slate-600">
                                    {supplierPhone && `Phone: ${supplierPhone}`} {supplierEmail && ` | Email: ${supplierEmail}`}
                                </p>
                            )}
                        </div>
                    </div>

                    <div className="col-span-5 border-l border-slate-300 pl-4 space-y-1.5 text-right">
                        <div className="text-center bg-slate-900 text-white py-1 rounded font-black tracking-wider text-sm uppercase mb-2">
                            {isSales ? 'TAX INVOICE' : 'PURCHASE INVOICE'}
                        </div>
                        <div className="grid grid-cols-2 text-left gap-y-1 text-[11px]">
                            <span className="font-bold text-slate-600">Invoice No.:</span>
                            <span className="font-bold text-slate-900 font-mono text-right">{docNumber}</span>
                            
                            <span className="font-bold text-slate-600">Invoice Date:</span>
                            <span className="text-slate-900 text-right">{docDate}</span>
                            
                            <span className="font-bold text-slate-600">Due Date:</span>
                            <span className="text-slate-900 text-right">{dueDate}</span>
                            
                            <span className="font-bold text-slate-600">Place of Supply:</span>
                            <span className="text-slate-900 text-right">{placeOfSupply}</span>
                            
                            <span className="font-bold text-slate-600">Payment Mode:</span>
                            <span className="text-slate-900 text-right font-medium">{paymentMode}</span>
                        </div>
                    </div>
                </div>

                {/* Parties Block: BILL TO and SHIP TO */}
                <div className="grid grid-cols-2 border-x-2 border-b-2 border-slate-900">
                    {/* BILL TO */}
                    <div className="p-3 border-r border-slate-300 space-y-1 bg-white">
                        <div className="font-black text-slate-900 uppercase tracking-wider border-b border-slate-200 pb-1 mb-1.5 text-xs text-indigo-900 flex items-center justify-between">
                            <span>BILL TO</span>
                        </div>
                        <p className="font-bold text-slate-900 text-xs">{billToName}</p>
                        <p className="text-slate-600">{billToAddress}</p>
                        <div className="grid grid-cols-2 gap-x-2 pt-1 font-mono text-[10px]">
                            <p><span className="font-sans font-bold text-slate-700">GSTIN:</span> {billToGstin}</p>
                            <p><span className="font-sans font-bold text-slate-700">PAN:</span> {billToPan}</p>
                        </div>
                        <div className="grid grid-cols-2 gap-x-2 text-[10px] text-slate-600">
                            <p><span className="font-bold text-slate-700">State:</span> {billToState}</p>
                            <p><span className="font-bold text-slate-700">Mobile:</span> {billToPhone}</p>
                        </div>
                        {billToEmail && <p className="text-[10px] text-slate-600"><span className="font-bold text-slate-700">Email:</span> {billToEmail}</p>}
                    </div>

                    {/* SHIP TO */}
                    <div className="p-3 space-y-1 bg-white">
                        <div className="font-black text-slate-900 uppercase tracking-wider border-b border-slate-200 pb-1 mb-1.5 text-xs text-slate-800 flex items-center justify-between">
                            <span>SHIP TO (Consignee)</span>
                            {shipToSame && <span className="text-[9px] font-normal text-slate-500 lowercase">(same as billing)</span>}
                        </div>
                        <p className="font-bold text-slate-900 text-xs">{shipToName}</p>
                        <p className="text-slate-600">{shipToAddress}</p>
                        <div className="grid grid-cols-2 gap-x-2 pt-1 font-mono text-[10px]">
                            <p><span className="font-sans font-bold text-slate-700">GSTIN:</span> {shipToGstin}</p>
                            <p><span className="font-sans font-bold text-slate-700">PAN:</span> {shipToPan}</p>
                        </div>
                        <div className="grid grid-cols-2 gap-x-2 text-[10px] text-slate-600">
                            <p><span className="font-bold text-slate-700">State:</span> {shipToState}</p>
                            <p><span className="font-bold text-slate-700">Mobile:</span> {shipToPhone}</p>
                        </div>
                        {shipToEmail && <p className="text-[10px] text-slate-600"><span className="font-bold text-slate-700">Email:</span> {shipToEmail}</p>}
                    </div>
                </div>

                {/* Items Table matching SALES INVOICE TEMPLATE.xlsx 15 columns */}
                <div className="border-x-2 border-b-2 border-slate-900 overflow-x-auto">
                    <table className="w-full text-left border-collapse text-[10.5px]">
                        <thead>
                            <tr className="bg-slate-900 text-white font-bold text-center">
                                <th className="p-1.5 border-r border-slate-700 w-7">#</th>
                                <th className="p-1.5 border-r border-slate-700 text-left">Item / Service Description</th>
                                <th className="p-1.5 border-r border-slate-700 w-16">HSN/SAC</th>
                                <th className="p-1.5 border-r border-slate-700 w-10">Qty</th>
                                <th className="p-1.5 border-r border-slate-700 w-11">Unit</th>
                                <th className="p-1.5 border-r border-slate-700 w-16 text-right">Rate (₹)</th>
                                <th className="p-1.5 border-r border-slate-700 w-12 text-right">Disc %</th>
                                <th className="p-1.5 border-r border-slate-700 w-20 text-right">Taxable (₹)</th>
                                <th className="p-1.5 border-r border-slate-700 w-11 text-right">CGST %</th>
                                <th className="p-1.5 border-r border-slate-700 w-14 text-right">CGST (₹)</th>
                                <th className="p-1.5 border-r border-slate-700 w-11 text-right">SGST %</th>
                                <th className="p-1.5 border-r border-slate-700 w-14 text-right">SGST (₹)</th>
                                <th className="p-1.5 border-r border-slate-700 w-11 text-right">IGST %</th>
                                <th className="p-1.5 border-r border-slate-700 w-14 text-right">IGST (₹)</th>
                                <th className="p-1.5 w-20 text-right">Total (₹)</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-300">
                            {items.map((item, idx) => {
                                const isInter = selectedInvoice.isInterstate;
                                const halfRate = (item.gstRate || 0) / 2;
                                return (
                                    <tr key={idx} className="hover:bg-slate-50/50">
                                        <td className="p-1.5 border-r border-slate-300 text-center font-bold text-slate-500">{idx + 1}</td>
                                        <td className="p-1.5 border-r border-slate-300 font-bold text-slate-900">{item.description}</td>
                                        <td className="p-1.5 border-r border-slate-300 text-center font-mono text-slate-600">{item.hsnSac || '-'}</td>
                                        <td className="p-1.5 border-r border-slate-300 text-center">{item.qty}</td>
                                        <td className="p-1.5 border-r border-slate-300 text-center text-slate-600">{item.unit || 'PCS'}</td>
                                        <td className="p-1.5 border-r border-slate-300 text-right font-mono">{Number(item.rate).toFixed(2)}</td>
                                        <td className="p-1.5 border-r border-slate-300 text-right font-mono text-slate-600">{item.discPercent ? `${item.discPercent}%` : '-'}</td>
                                        <td className="p-1.5 border-r border-slate-300 text-right font-mono font-bold">{Number(item.taxableValue).toFixed(2)}</td>
                                        <td className="p-1.5 border-r border-slate-300 text-right font-mono text-slate-600">{!isInter && item.gstRate ? `${halfRate}%` : '-'}</td>
                                        <td className="p-1.5 border-r border-slate-300 text-right font-mono">{!isInter ? Number(item.cgst || 0).toFixed(2) : '-'}</td>
                                        <td className="p-1.5 border-r border-slate-300 text-right font-mono text-slate-600">{!isInter && item.gstRate ? `${halfRate}%` : '-'}</td>
                                        <td className="p-1.5 border-r border-slate-300 text-right font-mono">{!isInter ? Number(item.sgst || 0).toFixed(2) : '-'}</td>
                                        <td className="p-1.5 border-r border-slate-300 text-right font-mono text-slate-600">{isInter && item.gstRate ? `${item.gstRate}%` : '-'}</td>
                                        <td className="p-1.5 border-r border-slate-300 text-right font-mono">{isInter ? Number(item.igst || 0).toFixed(2) : '-'}</td>
                                        <td className="p-1.5 text-right font-mono font-black text-slate-900">{Number(item.total).toFixed(2)}</td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>

                {/* Totals and Calculations Block */}
                <div className="grid grid-cols-12 border-x-2 border-b-2 border-slate-900">
                    <div className="col-span-7 p-3 border-r border-slate-300 flex flex-col justify-between space-y-3 bg-slate-50/20">
                        <div>
                            <span className="font-bold text-slate-700 uppercase tracking-wider text-[10px]">Amount in Words:</span>
                            <p className="font-black text-slate-900 italic text-xs mt-0.5 capitalize">
                                {summary.amountInWords || 'Rupees Zero Only'}
                            </p>
                        </div>

                        {selectedInvoice.notes && (
                            <div className="border-t border-slate-200 pt-2 text-[10px] text-slate-600">
                                <span className="font-bold text-slate-700">Special Notes: </span>
                                {selectedInvoice.notes}
                            </div>
                        )}
                    </div>

                    <div className="col-span-5 p-3 space-y-1.5 text-[11px] bg-slate-50/40">
                        <div className="flex justify-between text-slate-700">
                            <span>Subtotal (Taxable Value):</span>
                            <span className="font-mono font-bold">₹{summary.totalTaxableValue.toFixed(2)}</span>
                        </div>
                        {summary.totalCgst > 0 && (
                            <div className="flex justify-between text-slate-700">
                                <span>Total CGST:</span>
                                <span className="font-mono font-bold">₹{summary.totalCgst.toFixed(2)}</span>
                            </div>
                        )}
                        {summary.totalSgst > 0 && (
                            <div className="flex justify-between text-slate-700">
                                <span>Total SGST:</span>
                                <span className="font-mono font-bold">₹{summary.totalSgst.toFixed(2)}</span>
                            </div>
                        )}
                        {summary.totalIgst > 0 && (
                            <div className="flex justify-between text-slate-700">
                                <span>Total IGST:</span>
                                <span className="font-mono font-bold">₹{summary.totalIgst.toFixed(2)}</span>
                            </div>
                        )}
                        {summary.roundOff !== 0 && (
                            <div className="flex justify-between text-slate-500 text-[10px]">
                                <span>Round Off:</span>
                                <span className="font-mono">{summary.roundOff > 0 ? `+${summary.roundOff.toFixed(2)}` : summary.roundOff.toFixed(2)}</span>
                            </div>
                        )}
                        <div className="flex justify-between border-t-2 border-slate-900 pt-2 text-sm font-black text-slate-900">
                            <span>GRAND TOTAL:</span>
                            <span className="font-mono text-base text-indigo-950">₹{summary.totalAmount.toLocaleString('en-IN')}.00</span>
                        </div>
                    </div>
                </div>

                {/* Footer: Bank Details, Terms & Conditions, Declaration, Authorized Signatory */}
                <div className="grid grid-cols-12 border-x-2 border-b-2 border-slate-900 rounded-b-xl">
                    {/* Bank Details */}
                    <div className="col-span-5 p-3 border-r border-slate-300 space-y-1.5 bg-white">
                        <div className="font-black text-slate-900 uppercase tracking-wider text-[10.5px] border-b border-slate-200 pb-1">
                            BANK DETAILS
                        </div>
                        <div className="space-y-0.5 text-[10px]">
                            <p><span className="font-bold text-slate-700">Bank Name:</span> {bankName}</p>
                            <p><span className="font-bold text-slate-700">Account No.:</span> <span className="font-mono font-bold">{bankAccount}</span></p>
                            <p><span className="font-bold text-slate-700">IFSC Code:</span> <span className="font-mono font-bold">{bankIfsc}</span></p>
                            <p><span className="font-bold text-slate-700">Branch:</span> {bankBranch}</p>
                            {upiId && <p><span className="font-bold text-slate-700">UPI ID:</span> <span className="font-mono font-bold text-indigo-700">{upiId}</span></p>}
                        </div>
                    </div>

                    {/* Terms and Conditions */}
                    <div className="col-span-7 p-3 space-y-1 bg-white flex flex-col justify-between">
                        <div>
                            <div className="font-black text-slate-900 uppercase tracking-wider text-[10.5px] border-b border-slate-200 pb-1 mb-1">
                                TERMS & CONDITIONS
                            </div>
                            <div className="text-[9.5px] text-slate-600 space-y-0.5 leading-snug">
                                {terms.map((t, idx) => (
                                    <p key={idx}>{t}</p>
                                ))}
                            </div>
                        </div>
                    </div>

                    {/* Declaration & Authorized Signatory */}
                    <div className="col-span-12 border-t border-slate-300 p-3 grid grid-cols-12 gap-4 bg-slate-50/50">
                        <div className="col-span-8 flex items-center text-[10px] text-slate-600 italic">
                            <p>
                                <span className="font-bold not-italic">Declaration:</span> We declare that this invoice shows the actual price of the goods/services described and that all particulars are true and correct.
                            </p>
                        </div>
                        <div className="col-span-4 text-center space-y-2 flex flex-col justify-end items-center">
                            {company?.signature ? (
                                <img src={company.signature} alt="Signature" className="h-10 object-contain mx-auto" />
                            ) : (
                                <div className="h-10"></div>
                            )}
                            <div className="border-t border-slate-400 pt-1 w-full text-center">
                                <p className="font-black text-slate-900 text-[10.5px]">Authorized Signatory</p>
                                <p className="text-[9px] text-slate-500 font-bold uppercase">{supplierName}</p>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    );
};

export default GSTInvoiceView;
