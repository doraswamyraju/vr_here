import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    Calculator, Settings, Download, FileText, CheckCircle2, 
    AlertCircle, RefreshCw, Eye, Search, User, Filter, Check, X 
} from 'lucide-react';
import BookkeepingView from '../customer/BookkeepingView';

const AdminBookkeepingView = ({ token }) => {
    const [clients, setClients] = useState([]);
    const [selectedClient, setSelectedClient] = useState(null);
    const [loading, setLoading] = useState(true);
    const [transactions, setTransactions] = useState([]);
    const [selectedInvoice, setSelectedInvoice] = useState(null);

    const config = { headers: { Authorization: `Bearer ${token}` } };

    const fetchClients = async () => {
        setLoading(true);
        try {
            // Fetch users/clients
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

    const fetchClientTransactions = async (client) => {
        setSelectedClient(client);
        setTransactions([]);
        try {
            // We need a route to fetch transactions of a specific client for admin/employee.
            // Wait, does the API support fetching another user's transactions?
            // In accountingController, getTransactions fetches: query = { clientUser: req.user._id }
            // Let's modify the backend controller/route so that admins and employees can pass a client ID query parameter!
            // E.g., GET /api/accounting/transactions?clientId=XYZ
            const { data } = await axios.get(`/api/accounting/transactions?clientId=${client._id}`, config);
            setTransactions(data);
        } catch (error) {
            console.error('Failed to fetch client transactions:', error);
        }
    };

    const handleVerify = async (id, status) => {
        try {
            await axios.put(`/api/accounting/transactions/${id}`, { status }, config);
            if (selectedClient) fetchClientTransactions(selectedClient);
        } catch (error) {
            alert('Failed to update status');
        }
    };

    const handleDownloadTally = () => {
        if (!selectedClient) return;
        window.open(`/api/accounting/export/tally?clientId=${selectedClient._id}&token=${token}`, '_blank');
    };

    const handleDownloadGstr = async () => {
        if (!selectedClient) return;
        try {
            const { data } = await axios.get(`/api/accounting/export/gstr1?clientId=${selectedClient._id}`, config);
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
            const downloadAnchor = document.createElement('a');
            downloadAnchor.setAttribute("href",     dataStr);
            downloadAnchor.setAttribute("download", `GSTR1_Offline_${selectedClient.name}_${new Date().toISOString().slice(0,10)}.json`);
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
        } catch (error) {
            alert('Failed to generate GSTR1 offline file');
        }
    };

    return (
        <div className="space-y-6 pb-20">
            {/* If a client is selected, show their full bookkeeping screen but with admin controls */}
            {selectedClient ? (
                <div className="space-y-4">
                    <div className="flex items-center gap-4 bg-white p-4 rounded-3xl border border-slate-100 sticky top-0 z-10 shadow-sm">
                        <button 
                            onClick={() => { setSelectedClient(null); setTransactions([]); }} 
                            className="text-slate-600 font-bold text-sm hover:text-slate-900 transition flex items-center gap-1"
                        >
                            ← Back to Clients List
                        </button>
                        <div className="h-6 w-px bg-slate-200" />
                        <div className="flex-1">
                            <span className="text-[10px] font-black text-indigo-600 uppercase tracking-widest">Auditing Client:</span>
                            <h3 className="text-lg font-black text-slate-800 leading-none">{selectedClient.name} ({selectedClient.email})</h3>
                        </div>
                        <div className="flex gap-2">
                            <button 
                                onClick={handleDownloadTally}
                                className="bg-slate-900 text-white px-4 py-2 rounded-xl text-xs font-bold hover:bg-slate-800 transition"
                            >
                                Tally XML
                            </button>
                            <button 
                                onClick={handleDownloadGstr}
                                className="bg-emerald-600 text-white px-4 py-2 rounded-xl text-xs font-bold hover:bg-emerald-500 transition"
                            >
                                GSTR-1 JSON
                            </button>
                        </div>
                    </div>

                    {/* Transaction list for this client */}
                    <div className="bg-white rounded-[2.5rem] border border-slate-100 overflow-hidden shadow-xl shadow-slate-200/50">
                        <div className="p-6 border-b border-slate-50 flex justify-between items-center">
                            <h3 className="font-black text-slate-800">Ledger & Audit Vouchers</h3>
                            <button onClick={() => fetchClientTransactions(selectedClient)} className="text-slate-400 hover:text-slate-600">
                                <RefreshCw size={16} />
                            </button>
                        </div>

                        {transactions.length === 0 ? (
                            <div className="text-center py-20 text-slate-300">
                                <FileText size={48} className="mx-auto mb-4 opacity-30" />
                                <p className="font-bold">No bookkeeping records found for this client</p>
                            </div>
                        ) : (
                            <div className="overflow-x-auto">
                                <table className="w-full text-left border-collapse">
                                    <thead>
                                        <tr className="bg-slate-50/50 text-slate-400">
                                            <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest">Type</th>
                                            <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest">Doc No</th>
                                            <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest font-bold">Party Name</th>
                                            <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest">Total Amount</th>
                                            <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest">Status</th>
                                            <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest text-right">Audit Action</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-50">
                                        {transactions.map((tx) => (
                                            <tr key={tx._id} className="hover:bg-slate-50/80 transition group">
                                                <td className="px-8 py-5">
                                                    <span className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wide ${
                                                        tx.transactionType === 'Sales' ? 'bg-emerald-50 text-emerald-600' : 'bg-indigo-50 text-indigo-600'
                                                    }`}>
                                                        {tx.transactionType}
                                                    </span>
                                                </td>
                                                <td className="px-8 py-5 font-bold text-slate-700">{tx.docNumber}</td>
                                                <td className="px-8 py-5 font-bold text-slate-700">{tx.partyName}</td>
                                                <td className="px-8 py-5 font-black text-slate-900">₹{tx.summary.totalAmount.toLocaleString()}</td>
                                                <td className="px-8 py-5">
                                                    <span className={`px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wide ${
                                                        tx.status === 'Verified' ? 'bg-green-50 text-green-600' :
                                                        tx.status === 'Flagged' ? 'bg-red-50 text-red-600' : 'bg-amber-50 text-amber-600'
                                                    }`}>
                                                        {tx.status}
                                                    </span>
                                                </td>
                                                <td className="px-8 py-5 text-right space-x-1">
                                                    {tx.status !== 'Verified' && (
                                                        <button 
                                                            onClick={() => handleVerify(tx._id, 'Verified')}
                                                            title="Verify / Signoff"
                                                            className="bg-green-50 text-green-600 hover:bg-green-600 hover:text-white p-2 rounded-xl transition inline-flex items-center gap-1 text-xs font-bold"
                                                        >
                                                            <Check size={14} /> Verify
                                                        </button>
                                                    )}
                                                    {tx.status !== 'Flagged' && (
                                                        <button 
                                                            onClick={() => handleVerify(tx._id, 'Flagged')}
                                                            title="Flag Dispute"
                                                            className="bg-red-50 text-red-600 hover:bg-red-600 hover:text-white p-2 rounded-xl transition inline-flex items-center gap-1 text-xs font-bold"
                                                        >
                                                            <X size={14} /> Flag
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
                </div>
            ) : (
                /* List of all client users */
                <div className="space-y-6">
                    <div>
                        <h2 className="text-3xl font-black text-slate-950 tracking-tight leading-none mb-2">Bookkeeping Audits</h2>
                        <p className="text-sm text-slate-500 font-medium">Select a client below to review their transactional ledgers, verify invoices, and run compliance downloads.</p>
                    </div>

                    {loading ? (
                        <div className="flex justify-center py-20">
                            <div className="w-10 h-10 border-4 border-slate-200 border-t-indigo-600 rounded-full animate-spin"></div>
                        </div>
                    ) : (
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                            {clients.map(client => (
                                <div 
                                    key={client._id} 
                                    onClick={() => fetchClientTransactions(client)}
                                    className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm hover:border-indigo-200 cursor-pointer transition-all flex items-center justify-between group"
                                >
                                    <div className="flex items-center gap-4">
                                        <div className="w-12 h-12 bg-indigo-50 text-indigo-600 rounded-2xl flex items-center justify-center group-hover:bg-indigo-600 group-hover:text-white transition-all">
                                            <User size={22} />
                                        </div>
                                        <div>
                                            <h4 className="font-black text-slate-800 text-sm leading-none mb-1 group-hover:text-indigo-600 transition-colors">{client.name}</h4>
                                            <p className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">{client.email}</p>
                                        </div>
                                    </div>
                                    <span className="text-[10px] font-black text-slate-300 group-hover:text-indigo-600 transition-colors">Audit →</span>
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
