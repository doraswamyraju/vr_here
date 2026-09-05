import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    Download, ShieldCheck, FileSpreadsheet, CheckCircle2, 
    AlertCircle, RefreshCw, Layers, Check, Calendar, Hash, Save
} from 'lucide-react';
import Gstr2bMatcherModal from './Gstr2bMatcherModal';

const GstReturnsTab = ({
    token,
    selectedClient,
    selectedMonth = 'September 2026',
    transactions = [],
    gstr3bData,
    onDownloadGstr1,
    onRefresh
}) => {
    const [show2bMatcher, setShow2bMatcher] = useState(false);
    const purchaseTransactions = transactions.filter(t => t.transactionType === 'Purchase');

    // Filing sign-off state
    const [gstr1Status, setGstr1Status] = useState('Pending');
    const [gstr1Arn, setGstr1Arn] = useState('');
    const [gstr1FilingDate, setGstr1FilingDate] = useState('');
    const [gstr3bStatus, setGstr3bStatus] = useState('Pending');
    const [gstr3bArn, setGstr3bArn] = useState('');
    const [gstr3bFilingDate, setGstr3bFilingDate] = useState('');
    const [auditorNotes, setAuditorNotes] = useState('');
    const [savingFiling, setSavingFiling] = useState(false);

    const config = { headers: { Authorization: `Bearer ${token}` } };

    // Fetch existing filing record for this client & month
    useEffect(() => {
        if (!selectedClient) return;
        const fetchFiling = async () => {
            try {
                const { data } = await axios.get(`/api/accounting/filings/${selectedClient._id}/${selectedMonth}`, config);
                if (data) {
                    setGstr1Status(data.gstr1Status || 'Pending');
                    setGstr1Arn(data.gstr1Arn || '');
                    setGstr1FilingDate(data.gstr1FilingDate ? new Date(data.gstr1FilingDate).toISOString().slice(0, 10) : '');
                    setGstr3bStatus(data.gstr3bStatus || 'Pending');
                    setGstr3bArn(data.gstr3bArn || '');
                    setGstr3bFilingDate(data.gstr3bFilingDate ? new Date(data.gstr3bFilingDate).toISOString().slice(0, 10) : '');
                    setAuditorNotes(data.auditorNotes || '');
                }
            } catch (err) {
                console.error('Error fetching filing sign-off:', err);
            }
        };
        fetchFiling();
    }, [selectedClient, selectedMonth]);

    const handleSaveFiling = async () => {
        if (!selectedClient) return;
        setSavingFiling(true);
        try {
            await axios.post('/api/accounting/filings', {
                clientId: selectedClient._id,
                month: selectedMonth,
                gstr1Status,
                gstr1Arn,
                gstr1FilingDate: gstr1FilingDate || undefined,
                gstr3bStatus,
                gstr3bArn,
                gstr3bFilingDate: gstr3bFilingDate || undefined,
                bookkeepingStatus: (gstr1Status === 'Filed' && gstr3bStatus === 'Filed') ? 'Completed' : 'In Progress',
                auditorNotes
            }, config);

            alert('GST Filing Sign-Off recorded successfully!');
            if (onRefresh) onRefresh();
        } catch (error) {
            alert('Failed to save filing details: ' + (error.response?.data?.message || error.message));
        } finally {
            setSavingFiling(false);
        }
    };

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
                            Reconciles the client’s inward purchase register ({purchaseTransactions.length} bills logged) with supplier-filed 2B returns to ensure 100% eligible ITC claims without notices or penalties.
                        </p>
                    </div>

                    <button 
                        onClick={() => setShow2bMatcher(true)}
                        className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2.5 rounded-2xl font-bold text-xs uppercase tracking-wider transition flex items-center justify-center gap-2 shadow-md shadow-indigo-200"
                    >
                        <Layers size={15} /> Open GSTR-2B ITC Matcher Desk
                    </button>
                </div>
            </div>

            {/* GSTR-2B Matcher Modal */}
            <Gstr2bMatcherModal 
                isOpen={show2bMatcher}
                onClose={() => setShow2bMatcher(false)}
                clientPurchases={purchaseTransactions}
                clientName={selectedClient?.companyName || selectedClient?.name || 'Client'}
            />

            {/* GSTR-3B Computation Sheet */}
            {gstr3bData && (
                <div className="bg-white rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 p-6 space-y-6">
                    <div className="flex justify-between items-center border-b border-slate-100 pb-4">
                        <div>
                            <h4 className="font-black text-slate-900 text-lg">GSTR-3B Computation Summary Sheet</h4>
                            <p className="text-xs text-slate-500 font-medium">Auto-computed outward supplies, ITC entitlement, and net cash liability for <strong className="text-slate-800">{selectedMonth}</strong></p>
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

            {/* Monthly Filing Compliance Sign-Off Desk */}
            <div className="bg-white rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 p-6 space-y-5">
                <div className="flex items-center justify-between border-b border-slate-100 pb-4">
                    <div className="flex items-center gap-2">
                        <div className="w-8 h-8 rounded-xl bg-indigo-50 text-indigo-600 flex items-center justify-center font-black">
                            <ShieldCheck size={18} />
                        </div>
                        <div>
                            <h4 className="font-black text-slate-900 text-base">Monthly Statutory Filing Sign-Off Desk</h4>
                            <p className="text-xs text-slate-500 font-medium">Record official GST Portal ARNs, filing dates, and sign-off verification for {selectedMonth}</p>
                        </div>
                    </div>

                    <button
                        onClick={handleSaveFiling}
                        disabled={savingFiling}
                        className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2.5 rounded-2xl font-black text-xs uppercase tracking-wider transition flex items-center gap-1.5 shadow-md shadow-indigo-200 disabled:opacity-50"
                    >
                        <Save size={14} />
                        <span>{savingFiling ? 'Saving...' : 'Save Filing Sign-Off'}</span>
                    </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
                    {/* GSTR-1 Sign-Off */}
                    <div className="bg-slate-50 p-5 rounded-2xl border border-slate-200 space-y-3">
                        <div className="flex items-center justify-between border-b border-slate-200 pb-2">
                            <h5 className="font-black text-slate-900 uppercase tracking-wider">GSTR-1 Outward Return Sign-Off</h5>
                            <select
                                value={gstr1Status}
                                onChange={(e) => setGstr1Status(e.target.value)}
                                className="bg-white border border-slate-300 rounded-lg px-2.5 py-1 font-bold text-xs focus:outline-none"
                            >
                                <option value="Pending">Pending Preparation</option>
                                <option value="Prepared">JSON Prepared</option>
                                <option value="Filed">Filed on Portal</option>
                            </select>
                        </div>

                        <div className="space-y-3">
                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">GSTR-1 ARN Reference Number</label>
                                <input
                                    type="text"
                                    value={gstr1Arn}
                                    onChange={(e) => setGstr1Arn(e.target.value)}
                                    placeholder="e.g. AA3709260012345"
                                    className="w-full bg-white border border-slate-200 rounded-xl px-3 py-2 font-mono uppercase font-bold text-slate-900 focus:outline-none focus:border-indigo-500"
                                />
                            </div>

                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">GSTR-1 Filing Date</label>
                                <input
                                    type="date"
                                    value={gstr1FilingDate}
                                    onChange={(e) => setGstr1FilingDate(e.target.value)}
                                    className="w-full bg-white border border-slate-200 rounded-xl px-3 py-2 text-slate-800 focus:outline-none focus:border-indigo-500 font-bold"
                                />
                            </div>
                        </div>
                    </div>

                    {/* GSTR-3B Sign-Off */}
                    <div className="bg-slate-50 p-5 rounded-2xl border border-slate-200 space-y-3">
                        <div className="flex items-center justify-between border-b border-slate-200 pb-2">
                            <h5 className="font-black text-slate-900 uppercase tracking-wider">GSTR-3B Tax Return & PMT-06 Sign-Off</h5>
                            <select
                                value={gstr3bStatus}
                                onChange={(e) => setGstr3bStatus(e.target.value)}
                                className="bg-white border border-slate-300 rounded-lg px-2.5 py-1 font-bold text-xs focus:outline-none"
                            >
                                <option value="Pending">Pending</option>
                                <option value="Computed">Tax Computed</option>
                                <option value="Challan Generated">Challan Generated</option>
                                <option value="Filed">Filed on Portal</option>
                            </select>
                        </div>

                        <div className="space-y-3">
                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">GSTR-3B ARN / Challan Reference</label>
                                <input
                                    type="text"
                                    value={gstr3bArn}
                                    onChange={(e) => setGstr3bArn(e.target.value)}
                                    placeholder="e.g. CP2609370098765"
                                    className="w-full bg-white border border-slate-200 rounded-xl px-3 py-2 font-mono uppercase font-bold text-slate-900 focus:outline-none focus:border-indigo-500"
                                />
                            </div>

                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">GSTR-3B Filing Date</label>
                                <input
                                    type="date"
                                    value={gstr3bFilingDate}
                                    onChange={(e) => setGstr3bFilingDate(e.target.value)}
                                    className="w-full bg-white border border-slate-200 rounded-xl px-3 py-2 text-slate-800 focus:outline-none focus:border-indigo-500 font-bold"
                                />
                            </div>
                        </div>
                    </div>
                </div>

                <div>
                    <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">Auditor Monthly Review Notes</label>
                    <textarea
                        rows={2}
                        value={auditorNotes}
                        onChange={(e) => setAuditorNotes(e.target.value)}
                        placeholder="Add internal notes on tax adjustments, ITC reversals under Rule 42/43, or client communications..."
                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-xs text-slate-800 focus:outline-none focus:border-indigo-500 font-medium"
                    />
                </div>
            </div>
        </div>
    );
};

export default GstReturnsTab;
