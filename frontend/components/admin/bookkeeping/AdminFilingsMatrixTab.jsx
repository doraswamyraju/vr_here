import React, { useState } from 'react';
import { 
    Search, Building2, ShieldCheck, FileSpreadsheet, ArrowRight, 
    CheckCircle2, Clock, AlertCircle, RefreshCw, FileText, Landmark,
    TrendingUp, Award, Download
} from 'lucide-react';

const AdminFilingsMatrixTab = ({
    matrixData = null,
    selectedMonth,
    onSelectClient,
    onRefresh,
    loading = false
}) => {
    const [search, setSearch] = useState('');
    const [statusFilter, setStatusFilter] = useState('All');

    const clientsList = matrixData?.clients || [];
    const summary = matrixData?.summary || {
        totalClients: 0,
        gstr1FiledCount: 0,
        gstr1FiledPercentage: 0,
        gstr3bFiledCount: 0,
        gstr3bFiledPercentage: 0,
        fullyReconciledBankCount: 0
    };

    const filtered = clientsList.filter(item => {
        const c = item.client;
        const matchesSearch = 
            (c.name || '').toLowerCase().includes(search.toLowerCase()) ||
            (c.companyName || '').toLowerCase().includes(search.toLowerCase()) ||
            (c.email || '').toLowerCase().includes(search.toLowerCase()) ||
            (c.gstin || '').toLowerCase().includes(search.toLowerCase());

        const g1 = item.filing?.gstr1Status || 'Pending';
        const g3 = item.filing?.gstr3bStatus || 'Pending';
        const isFiled = g1 === 'Filed' && g3 === 'Filed';
        const isAudited = item.filing?.bookkeepingStatus === 'Audited';
        const isPending = !isFiled && !isAudited;

        if (statusFilter === 'Filed') return matchesSearch && isFiled;
        if (statusFilter === 'Audited') return matchesSearch && isAudited;
        if (statusFilter === 'Pending') return matchesSearch && isPending;
        return matchesSearch;
    });

    return (
        <div className="space-y-6">
            {/* Top Compliance Executive KPIs */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Active Portfolios</p>
                        <h3 className="text-2xl font-black text-slate-900 mt-1">{summary.totalClients}</h3>
                        <p className="text-[11px] text-indigo-600 font-semibold mt-0.5">Assigned Businesses</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-indigo-50 text-indigo-600 flex items-center justify-center font-black">
                        <Building2 size={22} />
                    </div>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Bank Recon Rate</p>
                        <h3 className="text-2xl font-black text-teal-600 mt-1">
                            {summary.fullyReconciledBankCount} / {summary.totalClients}
                        </h3>
                        <p className="text-[11px] text-slate-500 font-semibold mt-0.5">100% Tagged Accounts</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-teal-50 text-teal-600 flex items-center justify-center font-black">
                        <Landmark size={22} />
                    </div>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">GSTR-1 Portal Filings</p>
                        <h3 className="text-2xl font-black text-emerald-600 mt-1">{summary.gstr1FiledPercentage}%</h3>
                        <p className="text-[11px] text-slate-500 font-semibold mt-0.5">{summary.gstr1FiledCount} of {summary.totalClients} Signed Off</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-emerald-50 text-emerald-600 flex items-center justify-center font-black">
                        <ShieldCheck size={22} />
                    </div>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">GSTR-3B Cash Settled</p>
                        <h3 className="text-2xl font-black text-rose-600 mt-1">{summary.gstr3bFiledPercentage}%</h3>
                        <p className="text-[11px] text-slate-500 font-semibold mt-0.5">{summary.gstr3bFiledCount} Filed & Tax Paid</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-rose-50 text-rose-600 flex items-center justify-center font-black">
                        <CheckCircle2 size={22} />
                    </div>
                </div>
            </div>

            {/* Filter and Search Bar */}
            <div className="bg-white p-4 rounded-3xl border border-slate-100 shadow-sm flex flex-col md:flex-row gap-3 items-center justify-between">
                <div className="relative w-full md:w-80">
                    <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" size={16} />
                    <input 
                        type="text" 
                        value={search} 
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Search business, client, GSTIN..."
                        className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-2xl text-xs font-medium text-slate-900 focus:outline-none focus:border-indigo-500"
                    />
                </div>

                <div className="flex items-center gap-2 flex-wrap w-full md:w-auto justify-end">
                    <div className="flex bg-slate-100 p-1 rounded-2xl text-xs font-bold">
                        {['All', 'Pending', 'Audited', 'Filed'].map(tab => (
                            <button
                                key={tab}
                                onClick={() => setStatusFilter(tab)}
                                className={`px-3 py-1.5 rounded-xl transition text-[11px] ${
                                    statusFilter === tab ? 'bg-white text-indigo-600 shadow-sm font-black' : 'text-slate-600 hover:text-slate-900'
                                }`}
                            >
                                {tab}
                            </button>
                        ))}
                    </div>

                    <button 
                        onClick={onRefresh}
                        className="p-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-2xl transition"
                        title="Refresh Compliance Matrix"
                    >
                        <RefreshCw size={15} />
                    </button>
                </div>
            </div>

            {/* Client Compliance Grid / Table */}
            <div className="bg-white rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 overflow-hidden">
                <div className="p-5 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
                    <div>
                        <h4 className="font-black text-slate-900 text-sm">Monthly Filings & Bookkeeping Compliance Matrix</h4>
                        <p className="text-[11px] text-slate-500 font-medium">Compliance tracker for <strong className="text-slate-900">{selectedMonth}</strong></p>
                    </div>
                    <span className="text-[10px] font-black uppercase tracking-wider bg-indigo-50 text-indigo-700 px-3 py-1 rounded-full border border-indigo-200">
                        {filtered.length} Portfolios Listed
                    </span>
                </div>

                {loading ? (
                    <div className="flex justify-center py-20">
                        <div className="w-10 h-10 border-4 border-slate-200 border-t-indigo-600 rounded-full animate-spin"></div>
                    </div>
                ) : filtered.length === 0 ? (
                    <div className="text-center py-20 text-slate-400">
                        <Building2 size={48} className="mx-auto mb-3 opacity-30" />
                        <p className="font-bold text-sm">No client portfolios match the selected filters</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse text-xs">
                            <thead>
                                <tr className="bg-slate-50/75 text-slate-400 font-black text-[10px] uppercase tracking-wider border-b border-slate-100">
                                    <th className="px-6 py-4">Client / Enterprise</th>
                                    <th className="px-6 py-4">Vouchers Inward</th>
                                    <th className="px-6 py-4">Bank Reconciliation</th>
                                    <th className="px-6 py-4">GSTR-1 Status</th>
                                    <th className="px-6 py-4">GSTR-3B Status</th>
                                    <th className="px-6 py-4">Audit Stage</th>
                                    <th className="px-6 py-4 text-right">Audit & Sign-Off</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {filtered.map((row) => {
                                    const c = row.client;
                                    const m = row.metrics;
                                    const f = row.filing;

                                    return (
                                        <tr key={c._id} className="hover:bg-slate-50/60 transition group">
                                            <td className="px-6 py-4">
                                                <div className="flex items-center gap-3">
                                                    <div className="w-10 h-10 rounded-2xl bg-indigo-50 text-indigo-600 font-black text-xs flex items-center justify-center shrink-0">
                                                        {(c.companyName || c.name).charAt(0).toUpperCase()}
                                                    </div>
                                                    <div className="min-w-0">
                                                        <p className="font-black text-slate-900 text-xs truncate max-w-xs">{c.companyName || c.name}</p>
                                                        <div className="flex items-center gap-2 mt-0.5">
                                                            {c.gstin ? (
                                                                <span className="font-mono text-[10px] text-slate-500 bg-slate-100 px-1.5 py-0.5 rounded font-bold">{c.gstin}</span>
                                                            ) : (
                                                                <span className="text-[10px] text-slate-400 font-mono">{c.email}</span>
                                                            )}
                                                        </div>
                                                    </div>
                                                </div>
                                            </td>

                                            <td className="px-6 py-4">
                                                <div className="space-y-0.5">
                                                    <p className="font-bold text-slate-800 text-xs">
                                                        {m.salesCount} Invoices | {m.purchaseCount} Bills
                                                    </p>
                                                    <p className="text-[10px] text-slate-400 font-medium">
                                                        Turnover: ₹{m.totalSalesAmount.toLocaleString('en-IN')}
                                                    </p>
                                                </div>
                                            </td>

                                            <td className="px-6 py-4">
                                                <div className="space-y-1.5 w-32">
                                                    <div className="flex justify-between text-[10px] font-bold">
                                                        <span className="text-slate-600">{m.taggedBankTxCount}/{m.totalBankTxCount} Txns</span>
                                                        <span className={m.bankReconPercentage === 100 ? 'text-emerald-600 font-black' : 'text-amber-600'}>
                                                            {m.bankReconPercentage}%
                                                        </span>
                                                    </div>
                                                    <div className="w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
                                                        <div 
                                                            className={`h-full rounded-full ${m.bankReconPercentage === 100 ? 'bg-emerald-500' : 'bg-indigo-500'}`}
                                                            style={{ width: `${m.bankReconPercentage}%` }}
                                                        />
                                                    </div>
                                                </div>
                                            </td>

                                            <td className="px-6 py-4">
                                                <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                                                    f.gstr1Status === 'Filed' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                                                    f.gstr1Status === 'Prepared' ? 'bg-indigo-50 text-indigo-700 border border-indigo-200' :
                                                    'bg-amber-50 text-amber-700 border border-amber-200'
                                                }`}>
                                                    {f.gstr1Status || 'Pending'}
                                                </span>
                                                {f.gstr1Arn && (
                                                    <p className="text-[9px] font-mono text-slate-400 mt-1 truncate max-w-[110px]" title={f.gstr1Arn}>
                                                        ARN: {f.gstr1Arn}
                                                    </p>
                                                )}
                                            </td>

                                            <td className="px-6 py-4">
                                                <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                                                    f.gstr3bStatus === 'Filed' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                                                    f.gstr3bStatus === 'Computed' ? 'bg-indigo-50 text-indigo-700 border border-indigo-200' :
                                                    'bg-slate-100 text-slate-600 border border-slate-200'
                                                }`}>
                                                    {f.gstr3bStatus || 'Pending'}
                                                </span>
                                            </td>

                                            <td className="px-6 py-4">
                                                <span className={`px-2.5 py-1 rounded-full text-[10px] font-black uppercase tracking-wider ${
                                                    f.bookkeepingStatus === 'Completed' ? 'bg-emerald-100 text-emerald-800' :
                                                    f.bookkeepingStatus === 'Audited' ? 'bg-indigo-100 text-indigo-800' :
                                                    f.bookkeepingStatus === 'In Progress' ? 'bg-blue-100 text-blue-800' :
                                                    'bg-amber-100 text-amber-800'
                                                }`}>
                                                    {f.bookkeepingStatus || 'Pending'}
                                                </span>
                                            </td>

                                            <td className="px-6 py-4 text-right">
                                                <button
                                                    onClick={() => onSelectClient(c)}
                                                    className="bg-indigo-600 hover:bg-indigo-700 text-white px-3.5 py-1.5 rounded-xl font-bold text-xs transition flex items-center gap-1.5 ml-auto shadow-sm"
                                                >
                                                    <span>Open Desk</span>
                                                    <ArrowRight size={13} />
                                                </button>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
};

export default AdminFilingsMatrixTab;
