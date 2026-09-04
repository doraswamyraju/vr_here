import React from 'react';
import { FileSpreadsheet, Download, CheckCircle2, Layers, Cpu } from 'lucide-react';

const TallyExportTab = ({
    selectedClient,
    onDownloadTally,
    transactionsCount = 0
}) => {
    return (
        <div className="space-y-6">
            <div className="bg-white p-8 rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 space-y-6">
                <div className="flex items-start justify-between border-b border-slate-100 pb-6">
                    <div className="flex items-center gap-4">
                        <div className="w-16 h-16 bg-slate-900 text-white rounded-3xl flex items-center justify-center font-black text-xl shadow-md">
                            XML
                        </div>
                        <div>
                            <h3 className="text-xl font-black text-slate-900 leading-tight">
                                Tally Prime Master Multi-Voucher XML Exporter
                            </h3>
                            <p className="text-xs text-slate-500 font-medium mt-1">
                                Generates complete standard Tally XML vouchers with chart-of-accounts mappings for 1-click import into Tally Prime / ERP 9.
                            </p>
                        </div>
                    </div>

                    <button 
                        onClick={onDownloadTally}
                        className="bg-slate-900 hover:bg-slate-800 text-white px-6 py-3 rounded-2xl font-bold text-xs uppercase tracking-wider transition flex items-center gap-2 shadow-lg shadow-slate-300"
                    >
                        <Download size={16} /> Export Tally XML
                    </button>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
                    <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200/80 space-y-1">
                        <div className="flex items-center gap-1.5 font-black text-slate-800 uppercase text-[10px]">
                            <CheckCircle2 size={14} className="text-emerald-600" /> Sales Vouchers
                        </div>
                        <p className="text-slate-600">Auto-creates Party Ledger Dr, Sales A/c Cr, Output CGST/SGST/IGST Cr entries.</p>
                    </div>

                    <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200/80 space-y-1">
                        <div className="flex items-center gap-1.5 font-black text-slate-800 uppercase text-[10px]">
                            <CheckCircle2 size={14} className="text-emerald-600" /> Purchase Vouchers
                        </div>
                        <p className="text-slate-600">Auto-creates Purchase A/c Dr, Input Tax Dr, and Vendor Ledger Cr entries.</p>
                    </div>

                    <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200/80 space-y-1">
                        <div className="flex items-center gap-1.5 font-black text-slate-800 uppercase text-[10px]">
                            <CheckCircle2 size={14} className="text-emerald-600" /> Journal & Receipts
                        </div>
                        <p className="text-slate-600">Auto-generates Bank receipt / payment entries tagged to invoice vouchers.</p>
                    </div>
                </div>

                <div className="bg-indigo-50/60 p-4 rounded-2xl border border-indigo-100 flex items-center justify-between text-xs">
                    <span className="font-bold text-indigo-950">
                        Ready to export: {transactionsCount} validated vouchers for {selectedClient?.name}
                    </span>
                    <span className="text-[10px] font-mono font-black text-indigo-700 bg-white px-3 py-1 rounded-xl shadow-sm border border-indigo-200">
                        Tally XML Schema 4.0+
                    </span>
                </div>
            </div>
        </div>
    );
};

export default TallyExportTab;
