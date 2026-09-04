import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    FileText, ShieldCheck, FileSpreadsheet, Users, 
    ArrowLeft, Download, RefreshCw, Eye
} from 'lucide-react';

import ClientDirectoryTab from './bookkeeping/ClientDirectoryTab';
import LedgerAuditTab from './bookkeeping/LedgerAuditTab';
import GstReturnsTab from './bookkeeping/GstReturnsTab';
import TallyExportTab from './bookkeeping/TallyExportTab';
import PayrollAuditTab from './bookkeeping/PayrollAuditTab';
import GSTInvoiceView from '../customer/bookkeeping/GSTInvoiceView';

const AdminBookkeepingView = ({ token }) => {
    const [clients, setClients] = useState([]);
    const [selectedClient, setSelectedClient] = useState(null);
    const [loading, setLoading] = useState(true);
    const [clientDataLoading, setClientDataLoading] = useState(false);
    const [transactions, setTransactions] = useState([]);
    const [payrollRecords, setPayrollRecords] = useState([]);
    const [gstr3bData, setGstr3bData] = useState(null);
    const [selectedInvoice, setSelectedInvoice] = useState(null);
    const [activeAdminTab, setActiveAdminTab] = useState('ledger'); // 'ledger' | 'gst' | 'tally' | 'payroll'

    const config = { headers: { Authorization: `Bearer ${token}` } };

    // Fetch client list
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

    // Fetch client bookkeeping data
    const fetchClientData = async (client) => {
        setSelectedClient(client);
        setClientDataLoading(true);
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
        } finally {
            setClientDataLoading(false);
        }
    };

    // Verify / Flag transaction
    const handleVerifyTransaction = async (id, status) => {
        try {
            await axios.put(`/api/accounting/transactions/${id}`, { status }, config);
            setTransactions(transactions.map(t => t._id === id ? { ...t, status } : t));
        } catch (error) {
            alert('Failed to update status');
        }
    };

    // Add Payroll record
    const handleAddPayroll = async (formData) => {
        try {
            const { data } = await axios.post('/api/accounting/payroll', formData, config);
            setPayrollRecords([data, ...payrollRecords]);
            alert('Payroll row added successfully!');
        } catch (error) {
            alert('Failed to add payroll record: ' + (error.response?.data?.message || error.message));
        }
    };

    // Tally XML Download
    const handleDownloadTally = () => {
        if (!selectedClient) return;
        window.open(`/api/accounting/export/tally?clientId=${selectedClient._id}&token=${token}`, '_blank');
    };

    // GSTR-1 JSON Download
    const handleDownloadGstr1 = async () => {
        if (!selectedClient) return;
        try {
            const { data } = await axios.get(`/api/accounting/export/gstr1?clientId=${selectedClient._id}`, config);
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
            const downloadAnchor = document.createElement('a');
            downloadAnchor.setAttribute("href", dataStr);
            downloadAnchor.setAttribute("download", `GSTR1_Offline_${selectedClient.name.replace(/\s+/g, '_')}_${new Date().toISOString().slice(0, 10)}.json`);
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
        } catch (error) {
            alert('Failed to generate GSTR1 offline file');
        }
    };

    // Sub-tab definitions
    const adminTabs = [
        { id: 'ledger', label: 'Ledger Audit & Vouchers', icon: FileText, badge: transactions.length },
        { id: 'gst', label: 'GST Returns & 3B Sheet', icon: ShieldCheck },
        { id: 'tally', label: 'Tally Prime XML Exporter', icon: FileSpreadsheet },
        { id: 'payroll', label: 'Payroll & Form 16 / TDS', icon: Users, badge: payrollRecords.length }
    ];

    // If Viewing a specific invoice
    if (selectedInvoice) {
        return (
            <GSTInvoiceView 
                selectedInvoice={selectedInvoice}
                company={null}
                onBack={() => setSelectedInvoice(null)}
                onCopyShareLink={() => alert('Link copied!')}
            />
        );
    }

    return (
        <div className="space-y-6 pb-20 max-w-7xl mx-auto animate-in fade-in duration-300">
            {selectedClient ? (
                <div className="space-y-6">
                    {/* Header with Client Info & Quick Actions */}
                    <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-4 sticky top-0 z-10">
                        <div className="flex items-center gap-3">
                            <button 
                                onClick={() => { setSelectedClient(null); setTransactions([]); }}
                                className="p-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl transition font-bold text-xs flex items-center gap-1.5"
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

                    {/* Sub-Navigation Tabs */}
                    <div className="bg-white p-2 rounded-2xl border border-slate-100 shadow-sm flex items-center gap-1.5 overflow-x-auto">
                        {adminTabs.map(tab => {
                            const Icon = tab.icon;
                            const isActive = activeAdminTab === tab.id;
                            return (
                                <button
                                    key={tab.id}
                                    onClick={() => setActiveAdminTab(tab.id)}
                                    className={`px-4 py-2.5 rounded-xl text-xs font-bold transition shrink-0 flex items-center gap-2 ${
                                        isActive 
                                            ? 'bg-indigo-600 text-white shadow-md shadow-indigo-200' 
                                            : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                                    }`}
                                >
                                    <Icon size={16} />
                                    <span>{tab.label}</span>
                                    {tab.badge !== undefined && (
                                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-black ${
                                            isActive ? 'bg-white/20 text-white' : 'bg-slate-200 text-slate-700'
                                        }`}>
                                            {tab.badge}
                                        </span>
                                    )}
                                </button>
                            );
                        })}
                    </div>

                    {/* Sub-Tab Views */}
                    {clientDataLoading ? (
                        <div className="flex justify-center py-20">
                            <div className="w-10 h-10 border-4 border-slate-200 border-t-indigo-600 rounded-full animate-spin"></div>
                        </div>
                    ) : (
                        <>
                            {activeAdminTab === 'ledger' && (
                                <LedgerAuditTab 
                                    transactions={transactions}
                                    selectedClient={selectedClient}
                                    onVerifyTransaction={handleVerifyTransaction}
                                    onViewInvoice={(tx) => setSelectedInvoice(tx)}
                                    onRefresh={() => fetchClientData(selectedClient)}
                                />
                            )}

                            {activeAdminTab === 'gst' && (
                                <GstReturnsTab 
                                    selectedClient={selectedClient}
                                    gstr3bData={gstr3bData}
                                    onDownloadGstr1={handleDownloadGstr1}
                                    onRefresh={() => fetchClientData(selectedClient)}
                                />
                            )}

                            {activeAdminTab === 'tally' && (
                                <TallyExportTab 
                                    selectedClient={selectedClient}
                                    onDownloadTally={handleDownloadTally}
                                    transactionsCount={transactions.length}
                                />
                            )}

                            {activeAdminTab === 'payroll' && (
                                <PayrollAuditTab 
                                    payrollRecords={payrollRecords}
                                    selectedClient={selectedClient}
                                    onAddRecord={handleAddPayroll}
                                    onRefresh={() => fetchClientData(selectedClient)}
                                />
                            )}
                        </>
                    )}
                </div>
            ) : (
                /* Client Directory View */
                <ClientDirectoryTab 
                    clients={clients}
                    onSelectClient={fetchClientData}
                    loading={loading}
                />
            )}
        </div>
    );
};

export default AdminBookkeepingView;
