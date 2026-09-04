import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    Calculator, Settings, Download, FileText, CheckCircle2, 
    AlertCircle, RefreshCw, Eye, Search, User, Filter, Check, X,
    FileSpreadsheet, ShieldCheck, Users, ArrowLeft, Building2
} from 'lucide-react';
import GSTInvoiceView from '../customer/bookkeeping/GSTInvoiceView';

const AdminBookkeepingView = ({ token }) => {
    const [clients, setClients] = useState([]);
    const [selectedClient, setSelectedClient] = useState(null);
    const [loading, setLoading] = useState(true);
    const [transactions, setTransactions] = useState([]);
    const [payrollRecords, setPayrollRecords] = useState([]);
    const [selectedInvoice, setSelectedInvoice] = useState(null);
    const [activeAdminTab, setActiveAdminTab] = useState('ledger'); // 'ledger' | 'gst' | 'tally' | 'payroll'

    // GSTR-3B State
    const [gstr3bData, setGstr3bData] = useState(null);

    // Filter states
    const [searchClient, setSearchClient] = useState('');

    const config = { headers: { Authorization: `Bearer ${token}` } };

    const fetchClients = async () => {
        setLoading(true);
        try {
            const { data } = await axios.get('/api/auth/users', config);
            const clientUsers = data.filter(u => u.role === 'client');
            setClients(clientUsers);
        } catch (error) {
            console.error('Failed to fetch clients:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchClients();
    }, []);

    const fetchClientData = async (client) => {
        setSelectedClient(client);
        setTransactions([]);
        setPayrollRecords([]);
        try {
            const [txRes, payRes, gstrRes] = await Promise.allSettled([
                axios.get(`/api/accounting/transactions?clientId=${client._id}`, config),
                axios.get(`/api/accounting/payroll?clientId=${client._id}`, config),
                axios.get(`/api/accounting/export/gstr3b?clientId=${client._id}`, config)
            ]);

            if (txRes.status === 'fulfilled') setTransactions(txRes.value.data);
            if (payRes.status === 'fulfilled') setPayrollRecords(payRes.value.data);
            if (gstrRes.status === 'fulfilled') setGstr3bData(gstrRes.value.data);
        } catch (error) {
            console.error('Failed to fetch client bookkeeping data:', error);
        }
    };

    const handleVerify = async (id, status) => {
        try {
            await axios.put(`/api/accounting/transactions/${id}`, { status }, config);
            if (selectedClient) fetchClientData(selectedClient);
        } catch (error) {
            alert('Failed to update status');
        }
    };

    const handleDownloadTally = () => {
        if (!selectedClient) return;
        window.open(`/api/accounting/export/tally?clientId=${selectedClient._id}&token=${token}`, '_blank');
    };

    const handleDownloadGstr1 = async () => {
        if (!selectedClient) return;
        try {
            const { data } = await axios.get(`/api/accounting/export/gstr1?clientId=${selectedClient._id}`, config);
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
            const downloadAnchor = document.createElement('a');
            downloadAnchor.setAttribute("href", dataStr);
            downloadAnchor.setAttribute("download", `GSTR1_Offline_${selectedClient.name}_${new Date().toISOString().slice(0, 10)}.json`);
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
        } catch (error) {
            alert('Failed to generate GSTR1 offline file');
        }
    };

    const filteredClients = clients.filter(c => 
        (c.name || '').toLowerCase().includes(searchClient.toLowerCase()) ||
        (c.email || '').toLowerCase().includes(searchClient.toLowerCase())
    );

    // If Viewing a specific invoice
    if (selectedInvoice) {
        return (
            <GSTInvoiceView 
                selectedInvoice={selectedInvoice}
                company={null}
                onBack={() => setSelectedInvoice(null)}
                onCopyShareLink={() => alert('Copied!')}
            />
        );
    }

    return (
        <div className="space-y-6 pb-20 max-w-7xl mx-auto animate-in fade-in duration-300">
            {selectedClient ? (
                <div className="space-y-6">
                    {/* Header */}
                    <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-4 sticky top-0 z-10">
                        <div className="flex items-center gap-3">
                            <button 
                                onClick={() => { setSelectedClient(null); setTransactions([]); }}
                                className="p-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl transition font-bold text-xs flex items-center gap-1"
                            >
                                <ArrowLeft size={16} /> All Clients
                            </button>
                            <div className="h-6 w-px bg-slate-200" />
                            <div>
                                <span className="text-[10px] font-black text-indigo-600 uppercase tracking-widest block leading-none">Auditing Client:</span>
                                <h3 className="text-lg font-black text-slate-900 leading-none mt-1">
                                    {selectedClient.name} <span className="text-xs font-normal text-slate-400 font-mono">({selectedClient.email})</span>
                                </h3>
                            </div>
                        </div>

                        <div className="flex items-center gap-2 flex-wrap">
                            <button 
                                onClick={handleDownloadTally}
                                className="bg-slate-900 hover:bg-slate-800 text-white px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-1.5 shadow-sm"
                            >
                                <FileSpreadsheet size={14} /> Tally XML Export
                            </button>
                            <button 
                                onClick={handleDownloadGstr1}
                                className="bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-1.5 shadow-sm"
                            >
                                <Download size={14} /> GSTR-1 Portal JSON
                            </button>
                        </div>
                    </div>

                    {/* Admin Inner Sub-Tabs */}
                    <div className="bg-white p-2 rounded-2xl border border-slate-100 shadow-sm flex items-center gap-2 overflow-x-auto">
                        <button
                            onClick={() => setActiveAdminTab('ledger')}
                            className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-1.5 ${
                                activeAdminTab === 'ledger' ? 'bg-indigo-600 text-white shadow-md' : 'text-slate-600 hover:bg-slate-100'
                            }`}
                        >
                            <FileText size={15} /> Ledger Audit & Vouchers ({transactions.length})
                        </button>
                        <button
                            onClick={() => setActiveAdminTab('gst')}
                            className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-1.5 ${
                                activeAdminTab === 'gst' ? 'bg-indigo-600 text-white shadow-md' : 'text-slate-600 hover:bg-slate-100'
                            }`}
                        >
                            <ShieldCheck size={15} /> GSTR-3B Computation Sheet
                        </button>
                        <button
                            onClick={() => setActiveAdminTab('payroll')}
                            className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-1.5 ${
                                activeAdminTab === 'payroll' ? 'bg-indigo-600 text-white shadow-md' : 'text-slate-600 hover:bg-slate-100'
                            }`}
                        >
                            <Users size={15} /> Payroll & Form 16 / TDS ({payrollRecords.length})
                        </button>
                    </div>

                    {/* Tab 1: Ledger & Vouchers */}
                    {activeAdminTab === 'ledger' && (
                        <div className="bg-white rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 overflow-hidden">
                            <div className="p-5 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
                                <h4 className="font-black text-slate-900 text-sm">Transactional Vouchers & Line Verification</h4>
                                <button onClick={() => fetchClientData(selectedClient)} className="text-slate-400 hover:text-slate-600">
                                    <RefreshCw size={15} />
                                </button>
                            </div>

                            {transactions.length === 0 ? (
                                <div className="text-center py-20 text-slate-400">
                                    <FileText size={48} className="mx-auto mb-3 opacity-30" />
                                    <p className="font-bold">No bookkeeping records found for this client</p>
                                </div>
                            ) : (
                                <div className="overflow-x-auto">
                                    <table className="w-full text-left border-collapse text-xs">
                                        <thead>
                                            <tr className="bg-slate-50/75 text-slate-400 font-black text-[10px] uppercase tracking-wider border-b border-slate-100">
                                                <th className="px-6 py-4">Type</th>
                                                <th className="px-6 py-4">Doc No</th>
                                                <th className="px-6 py-4">Date</th>
                                                <th className="px-6 py-4">Party Name</th>
                                                <th className="px-6 py-4">Taxable</th>
                                                <th className="px-6 py-4">Total Amount</th>
                                                <th className="px-6 py-4">Status</th>
                                                <th className="px-6 py-4 text-right">Audit Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-slate-100">
                                            {transactions.map((tx) => (
                                                <tr key={tx._id} className="hover:bg-slate-50/60 transition group">
                                                    <td className="px-6 py-4">
                                                        <span className={`px-2.5 py-1 rounded-full text-[10px] font-black uppercase tracking-wide ${
                                                            tx.transactionType === 'Sales' ? 'bg-emerald-50 text-emerald-700' :
                                                            tx.transactionType === 'Purchase' ? 'bg-indigo-50 text-indigo-700' : 'bg-rose-50 text-rose-700'
                                                        }`}>
                                                            {tx.transactionType}
                                                        </span>
                                                    </td>
                                                    <td className="px-6 py-4 font-black font-mono text-slate-900">{tx.docNumber}</td>
                                                    <td className="px-6 py-4 text-slate-600 font-medium">
                                                        {tx.docDate ? new Date(tx.docDate).toLocaleDateString('en-GB') : '-'}
                                                    </td>
                                                    <td className="px-6 py-4">
                                                        <p className="font-bold text-slate-900">{tx.partyName}</p>
                                                        {tx.partyGstin && <p className="text-[10px] font-mono text-slate-400">{tx.partyGstin}</p>}
                                                    </td>
                                                    <td className="px-6 py-4 font-mono font-bold text-slate-700">
                                                        ₹{(tx.summary?.totalTaxableValue || 0).toLocaleString('en-IN')}
                                                    </td>
                                                    <td className="px-6 py-4 font-mono font-black text-slate-900 text-sm">
                                                        ₹{(tx.summary?.totalAmount || 0).toLocaleString('en-IN')}
                                                    </td>
                                                    <td className="px-6 py-4">
                                                        <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                                                            tx.status === 'Verified' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                                                            tx.status === 'Flagged' ? 'bg-rose-50 text-rose-700 border border-rose-200' :
                                                            'bg-amber-50 text-amber-700 border border-amber-200'
                                                        }`}>
                                                            {tx.status}
                                                        </span>
                                                    </td>
                                                    <td className="px-6 py-4 text-right space-x-1">
                                                        <button 
                                                            onClick={() => setSelectedInvoice(tx)}
                                                            title="View Invoice Sheet"
                                                            className="p-1.5 text-slate-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-lg transition"
                                                        >
                                                            <Eye size={15} />
                                                        </button>
                                                        {tx.status !== 'Verified' && (
                                                            <button 
                                                                onClick={() => handleVerify(tx._id, 'Verified')}
                                                                title="Mark Verified"
                                                                className="bg-emerald-50 text-emerald-700 hover:bg-emerald-600 hover:text-white px-2.5 py-1 rounded-lg transition text-xs font-bold inline-flex items-center gap-1"
                                                            >
                                                                <Check size={12} /> Verify
                                                            </button>
                                                        )}
                                                        {tx.status !== 'Flagged' && (
                                                            <button 
                                                                onClick={() => handleVerify(tx._id, 'Flagged')}
                                                                title="Flag Discrepancy"
                                                                className="bg-rose-50 text-rose-700 hover:bg-rose-600 hover:text-white px-2.5 py-1 rounded-lg transition text-xs font-bold inline-flex items-center gap-1"
                                                            >
                                                                <X size={12} /> Flag
                                                            </button>
                                                        )}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </div>
                    )}

                    {/* Tab 2: GSTR-3B Computation */}
                    {activeAdminTab === 'gst' && gstr3bData && (
                        <div className="bg-white rounded-3xl border border-slate-100 shadow-xl p-6 space-y-6">
                            <div>
                                <h4 className="font-black text-slate-900 text-base">GSTR-3B Monthly Computation Sheet</h4>
                                <p className="text-xs text-slate-500 font-medium">Computed outward supplies, ITC entitlement, and net cash liability</p>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                                <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200 space-y-2">
                                    <h5 className="font-black text-slate-800 uppercase tracking-wider text-[11px]">Table 3.1 Outward Taxable</h5>
                                    <p className="flex justify-between"><span>Taxable Value:</span> <span className="font-mono font-bold">₹{gstr3bData.table3_1?.outwardTaxableSupplies?.taxableValue?.toLocaleString('en-IN')}</span></p>
                                    <p className="flex justify-between"><span>IGST:</span> <span className="font-mono font-bold">₹{gstr3bData.table3_1?.outwardTaxableSupplies?.igst?.toLocaleString('en-IN')}</span></p>
                                    <p className="flex justify-between"><span>CGST:</span> <span className="font-mono font-bold">₹{gstr3bData.table3_1?.outwardTaxableSupplies?.cgst?.toLocaleString('en-IN')}</span></p>
                                    <p className="flex justify-between"><span>SGST:</span> <span className="font-mono font-bold">₹{gstr3bData.table3_1?.outwardTaxableSupplies?.sgst?.toLocaleString('en-IN')}</span></p>
                                </div>

                                <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200 space-y-2">
                                    <h5 className="font-black text-emerald-800 uppercase tracking-wider text-[11px]">Table 4 Eligible ITC</h5>
                                    <p className="flex justify-between"><span>Purchases Taxable:</span> <span className="font-mono font-bold">₹{gstr3bData.table4?.eligibleItc?.taxableValue?.toLocaleString('en-IN')}</span></p>
                                    <p className="flex justify-between"><span>ITC IGST:</span> <span className="font-mono font-bold">₹{gstr3bData.table4?.eligibleItc?.igst?.toLocaleString('en-IN')}</span></p>
                                    <p className="flex justify-between"><span>ITC CGST:</span> <span className="font-mono font-bold">₹{gstr3bData.table4?.eligibleItc?.cgst?.toLocaleString('en-IN')}</span></p>
                                    <p className="flex justify-between"><span>ITC SGST:</span> <span className="font-mono font-bold">₹{gstr3bData.table4?.eligibleItc?.sgst?.toLocaleString('en-IN')}</span></p>
                                </div>

                                <div className="bg-slate-900 text-white p-4 rounded-2xl space-y-2">
                                    <h5 className="font-black text-indigo-300 uppercase tracking-wider text-[11px]">Net GST Payable (Cash)</h5>
                                    <p className="flex justify-between"><span>Net IGST:</span> <span className="font-mono font-bold text-emerald-400">₹{gstr3bData.netPayable?.igst?.toLocaleString('en-IN')}</span></p>
                                    <p className="flex justify-between"><span>Net CGST:</span> <span className="font-mono font-bold text-emerald-400">₹{gstr3bData.netPayable?.cgst?.toLocaleString('en-IN')}</span></p>
                                    <p className="flex justify-between"><span>Net SGST:</span> <span className="font-mono font-bold text-emerald-400">₹{gstr3bData.netPayable?.sgst?.toLocaleString('en-IN')}</span></p>
                                    <div className="border-t border-slate-700 pt-2 flex justify-between font-black text-sm">
                                        <span>Total Cash Liability:</span>
                                        <span className="font-mono text-emerald-300">
                                            ₹{(gstr3bData.netPayable?.igst + gstr3bData.netPayable?.cgst + gstr3bData.netPayable?.sgst).toLocaleString('en-IN')}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Tab 3: Payroll & Form 16 */}
                    {activeAdminTab === 'payroll' && (
                        <div className="bg-white rounded-3xl border border-slate-100 shadow-xl overflow-hidden p-6 space-y-4">
                            <div className="flex justify-between items-center border-b border-slate-100 pb-3">
                                <div>
                                    <h4 className="font-black text-slate-900 text-sm">Employee Salary & Form 16 / TDS Register</h4>
                                    <p className="text-xs text-slate-500 font-medium">Monthly salary registers and Sec 192 TDS deductions</p>
                                </div>
                            </div>

                            {payrollRecords.length === 0 ? (
                                <div className="text-center py-16 text-slate-400">
                                    <Users size={40} className="mx-auto mb-2 opacity-30" />
                                    <p className="font-bold">No payroll records configured for this client</p>
                                </div>
                            ) : (
                                <div className="overflow-x-auto">
                                    <table className="w-full text-left border-collapse text-xs">
                                        <thead>
                                            <tr className="bg-slate-50 text-slate-400 font-black text-[10px] uppercase tracking-wider">
                                                <th className="p-3">Month</th>
                                                <th className="p-3">Employee</th>
                                                <th className="p-3">PAN</th>
                                                <th className="p-3">Gross Salary</th>
                                                <th className="p-3">TDS (192)</th>
                                                <th className="p-3">Net Payable</th>
                                                <th className="p-3">Status</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-slate-100">
                                            {payrollRecords.map(pr => (
                                                <tr key={pr._id}>
                                                    <td className="p-3 font-bold">{pr.month}</td>
                                                    <td className="p-3 font-bold text-slate-900">{pr.employeeName}</td>
                                                    <td className="p-3 font-mono">{pr.employeePan}</td>
                                                    <td className="p-3 font-mono font-bold">₹{pr.grossSalary?.toLocaleString('en-IN')}</td>
                                                    <td className="p-3 font-mono text-rose-600 font-bold">₹{pr.tdsDeducted?.toLocaleString('en-IN')}</td>
                                                    <td className="p-3 font-mono font-black text-emerald-600">₹{pr.netPayable?.toLocaleString('en-IN')}</td>
                                                    <td className="p-3"><span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-50 text-emerald-700">{pr.status}</span></td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            ) : (
                /* Client Directory Selection */
                <div className="space-y-6">
                    <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-white p-6 rounded-3xl border border-slate-100 shadow-sm">
                        <div>
                            <h2 className="text-2xl font-black text-slate-950 tracking-tight leading-none mb-1">Bookkeeping & AaaS Audit Desk</h2>
                            <p className="text-xs text-slate-500 font-medium">Select a client below to audit invoices, generate GSTR-1/3B filings, export Tally XML, or manage payroll.</p>
                        </div>
                        <div className="relative w-full md:w-72">
                            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" size={16} />
                            <input 
                                type="text"
                                value={searchClient}
                                onChange={(e) => setSearchClient(e.target.value)}
                                placeholder="Search client name, email..."
                                className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-2xl text-xs font-medium text-slate-900 focus:outline-none focus:border-indigo-500"
                            />
                        </div>
                    </div>

                    {loading ? (
                        <div className="flex justify-center py-20">
                            <div className="w-10 h-10 border-4 border-slate-200 border-t-indigo-600 rounded-full animate-spin"></div>
                        </div>
                    ) : (
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                            {filteredClients.map(client => (
                                <div 
                                    key={client._id} 
                                    onClick={() => fetchClientData(client)}
                                    className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm hover:border-indigo-300 cursor-pointer transition-all flex items-center justify-between group hover:shadow-lg hover:shadow-indigo-50"
                                >
                                    <div className="flex items-center gap-4">
                                        <div className="w-12 h-12 bg-indigo-50 text-indigo-600 rounded-2xl flex items-center justify-center group-hover:bg-indigo-600 group-hover:text-white transition-all shadow-sm">
                                            <Building2 size={22} />
                                        </div>
                                        <div>
                                            <h4 className="font-black text-slate-800 text-sm leading-none mb-1 group-hover:text-indigo-600 transition-colors">{client.name}</h4>
                                            <p className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider font-mono">{client.email}</p>
                                        </div>
                                    </div>
                                    <span className="text-xs font-black text-slate-300 group-hover:text-indigo-600 transition-colors">Audit →</span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default AdminBookkeepingView;
