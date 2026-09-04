import React, { useState } from 'react';
import { Download, ShieldCheck, FileSpreadsheet, CheckCircle2, AlertCircle, RefreshCw } from 'lucide-react';

const GstReturnsTab = ({
    selectedClient,
    gstr3bData,
    onDownloadGstr1,
    onRefresh
}) => {
    return (
        <div className="space-y-6">
            {/* Top Return Generators */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm flex flex-col justify-between space-y-4">
                    <div>
                        <div className="flex items-center gap-2">
                            <span className="w-8 h-8 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center font-black text-xs">
                                1
                            </span>
                            <h4 className="font-black text-slate-900 text-base">GSTR-1 Monthly Return Payload</h4>
                        </div>
                        <p className="text-xs text-slate-500 mt-2 leading-relaxed">
                            Generates the complete, validated JSON schema for direct upload into the GST Offline Tool and GST Portal (Includes B2B, B2CS, Table 12 HSN Summary, and Table 13 Documents Issued).
                        </p>
                    </div>

                    <button 
                        onClick={onDownloadGstr1}
                        className="bg-emerald-600 hover:bg-emerald-700 text-white px-5 py-2.5 rounded-2xl font-bold text-xs uppercase tracking-wider transition flex items-center justify-center gap-2 shadow-md shadow-emerald-200"
                    >
                        <Download size={15} /> Download GSTR-1 JSON
                    </button>
                </div>

                <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm flex flex-col justify-between space-y-4">
                    <div>
                        <div className="flex items-center gap-2">
                            <span className="w-8 h-8 rounded-xl bg-indigo-50 text-indigo-600 flex items-center justify-center font-black text-xs">
                                2
                            </span>
                            <h4 className="font-black text-slate-900 text-base">GSTR-2B vs Purchases Verification</h4>
                        </div>
                        <p className="text-xs text-slate-500 mt-2 leading-relaxed">
                            Reconciles the client’s inward purchase register with supplier-filed returns to ensure maximum eligible ITC claims without interest or penalties.
                        </p>
                    </div>

                    <div className="p-2.5 bg-slate-50 rounded-2xl border border-slate-200 text-center font-bold text-xs text-slate-600">
                        ✨ Real-Time ITC Eligibility Engine Active
                    </div>
                </div>
            </div>

            {/* GSTR-3B Computation Sheet */}
            {gstr3bData && (
                <div className="bg-white rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 p-6 space-y-6">
                    <div className="flex justify-between items-center border-b border-slate-100 pb-4">
                        <div>
                            <h4 className="font-black text-slate-900 text-lg">GSTR-3B Computation Summary Sheet</h4>
                            <p className="text-xs text-slate-500 font-medium">Auto-computed outward supplies, ITC entitlement, and net cash liability</p>
                        </div>
                        <button 
                            onClick={onRefresh}
                            className="p-2 bg-slate-100 hover:bg-slate-200 text-slate-600 rounded-xl transition"
                        >
                            <RefreshCw size={15} />
                        </button>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-xs">
                        {/* Table 3.1 */}
                        <div className="bg-slate-50 p-5 rounded-2xl border border-slate-200 space-y-3">
                            <div className="flex items-center justify-between border-b border-slate-200 pb-2">
                                <h5 className="font-black text-slate-900 uppercase tracking-wider text-xs">Table 3.1 Outward Taxable</h5>
                                <span className="text-[10px] font-bold text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded">Output Tax</span>
                            </div>
                            <div className="space-y-1.5 text-slate-700">
                                <p className="flex justify-between"><span>Taxable Value:</span> <span className="font-mono font-bold text-slate-900">₹{gstr3bData.table3_1?.outwardTaxableSupplies?.taxableValue?.toLocaleString('en-IN')}</span></p>
                                <p className="flex justify-between"><span>Integrated Tax (IGST):</span> <span className="font-mono font-bold">₹{gstr3bData.table3_1?.outwardTaxableSupplies?.igst?.toLocaleString('en-IN')}</span></p>
                                <p className="flex justify-between"><span>Central Tax (CGST):</span> <span className="font-mono font-bold">₹{gstr3bData.table3_1?.outwardTaxableSupplies?.cgst?.toLocaleString('en-IN')}</span></p>
                                <p className="flex justify-between"><span>State Tax (SGST):</span> <span className="font-mono font-bold">₹{gstr3bData.table3_1?.outwardTaxableSupplies?.sgst?.toLocaleString('en-IN')}</span></p>
                            </div>
                        </div>

                        {/* Table 4 Eligible ITC */}
                        <div className="bg-slate-50 p-5 rounded-2xl border border-slate-200 space-y-3">
                            <div className="flex items-center justify-between border-b border-slate-200 pb-2">
                                <h5 className="font-black text-emerald-800 uppercase tracking-wider text-xs">Table 4 Eligible ITC</h5>
                                <span className="text-[10px] font-bold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded">Input Credit</span>
                            </div>
                            <div className="space-y-1.5 text-slate-700">
                                <p className="flex justify-between"><span>Purchases Taxable:</span> <span className="font-mono font-bold text-slate-900">₹{gstr3bData.table4?.eligibleItc?.taxableValue?.toLocaleString('en-IN')}</span></p>
                                <p className="flex justify-between"><span>ITC IGST:</span> <span className="font-mono font-bold">₹{gstr3bData.table4?.eligibleItc?.igst?.toLocaleString('en-IN')}</span></p>
                                <p className="flex justify-between"><span>ITC CGST:</span> <span className="font-mono font-bold">₹{gstr3bData.table4?.eligibleItc?.cgst?.toLocaleString('en-IN')}</span></p>
                                <p className="flex justify-between"><span>ITC SGST:</span> <span className="font-mono font-bold">₹{gstr3bData.table4?.eligibleItc?.sgst?.toLocaleString('en-IN')}</span></p>
                            </div>
                        </div>

                        {/* Net Cash Liability */}
                        <div className="bg-slate-900 text-white p-5 rounded-2xl space-y-3 shadow-xl">
                            <div className="flex items-center justify-between border-b border-slate-700 pb-2">
                                <h5 className="font-black text-indigo-300 uppercase tracking-wider text-xs">Net Cash Tax Payable</h5>
                                <span className="text-[10px] font-bold text-emerald-400 bg-emerald-950 px-2 py-0.5 rounded border border-emerald-800">Challan PMT-06</span>
                            </div>
                            <div className="space-y-1.5 text-slate-300">
                                <p className="flex justify-between"><span>Net IGST Payable:</span> <span className="font-mono font-bold text-emerald-400">₹{gstr3bData.netPayable?.igst?.toLocaleString('en-IN')}</span></p>
                                <p className="flex justify-between"><span>Net CGST Payable:</span> <span className="font-mono font-bold text-emerald-400">₹{gstr3bData.netPayable?.cgst?.toLocaleString('en-IN')}</span></p>
                                <p className="flex justify-between"><span>Net SGST Payable:</span> <span className="font-mono font-bold text-emerald-400">₹{gstr3bData.netPayable?.sgst?.toLocaleString('en-IN')}</span></p>
                                <div className="border-t border-slate-700 pt-2 flex justify-between font-black text-sm text-white">
                                    <span>Total Cash to Pay:</span>
                                    <span className="font-mono text-emerald-300 text-base">
                                        ₹{(gstr3bData.netPayable?.igst + gstr3bData.netPayable?.cgst + gstr3bData.netPayable?.sgst).toLocaleString('en-IN')}
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default GstReturnsTab;
