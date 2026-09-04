import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    FileText, ShieldCheck, FileSpreadsheet, Users, 
    ArrowLeft, Download, RefreshCw, Eye, Building2
} from 'lucide-react';

import ClientDirectoryTab from './bookkeeping/ClientDirectoryTab';
import LedgerAuditTab from './bookkeeping/LedgerAuditTab';
import GstReturnsTab from './bookkeeping/GstReturnsTab';
import TallyExportTab from './bookkeeping/TallyExportTab';
import PayrollAuditTab from './bookkeeping/PayrollAuditTab';
import GSTInvoiceView from '../customer/bookkeeping/GSTInvoiceView';

const AdminBookkeepingView = ({ token, activeSubTab: propSubTab, onSubTabChange }) => {
    const [internalSubTab, setInternalSubTab] = useState('ledger');
    const activeAdminTab = propSubTab || internalSubTab;
    const setActiveAdminTab = (tab) => {
        if (onSubTabChange) onSubTabChange(tab);
        setInternalSubTab(tab);
    };

    const [clients, setClients] = useState([]);
    const [selectedClient, setSelectedClient] = useState(null);
    const [loading, setLoading] = useState(true);
    const [clientDataLoading, setClientDataLoading] = useState(false);
    const [transactions, setTransactions] = useState([]);
    const [payrollRecords, setPayrollRecords] = useState([]);
    const [gstr3bData, setGstr3bData] = useState(null);
    const [selectedInvoice, setSelectedInvoice] = useState(null);

    const config = { headers: { Authorization: `Bearer ${token}` } };

    // Fetch client list
    const fetchClients = async () => {
        setLoading(true);
        try {
            const { data } = await axios.get('/api/auth/users', config);
            const clientUsers = data.filter(u => u.role === 'client');
            setClients(clientUsers);
            // Default select the first client if available
            if (clientUsers.length > 0 && !selectedClient) {
                fetchClientData(clientUsers[0]);
            }
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

    // Sub-tab header info
    const getAdminSubTabInfo = () => {
        switch(activeAdminTab) {
            case 'clients': return { title: 'Client Accounting Directory', subtitle: 'Browse and switch between client portfolios.' };
            case 'gst': return { title: 'GST Statutory Returns & GSTR-3B Computation', subtitle: 'Export GSTR-1 portal JSON and compute 3B cash liabilities.' };
            case 'tally': return { title: 'Tally Prime XML & ERP Exporter', subtitle: 'Export multi-voucher XML payloads for 1-click Tally Prime import.' };
            case 'payroll': return { title: 'Payroll & Form 16 / TDS Register', subtitle: 'Manage employee salary registers and Section 192/194 TDS records.' };
            default: return { title: 'Ledger Audit & Transaction Verification', subtitle: 'Audit client vouchers, verify proofs, and flag discrepancies.' };
        }
    };

    const tabInfo = getAdminSubTabInfo();

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

    // If Directory tab selected explicitly
    if (activeAdminTab === 'clients') {
        return (
            <div className="space-y-6 pb-20 max-w-7xl mx-auto animate-in fade-in duration-300">
                <ClientDirectoryTab 
                    clients={clients}
                    onSelectClient={(client) => {
                        fetchClientData(client);
                        setActiveAdminTab('ledger');
                    }}
                    loading={loading}
                />
            </div>
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
                                onClick={() => setActiveAdminTab('clients')}
                                className="p-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl transition font-bold text-xs flex items-center gap-1.5"
                            >
                                <Building2 size={16} /> Switch Client
                            </button>
                            <div className="h-6 w-px bg-slate-200" />
                            <div>
                                <div className="flex items-center gap-2">
                                    <h3 className="text-lg font-black text-slate-900 leading-none">
                                        {selectedClient.name}
                                    </h3>
                                    <span className="text-[10px] font-bold text-slate-400 font-mono bg-slate-50 px-2 py-0.5 rounded border border-slate-200">
                                        {selectedClient.email}
                                    </span>
                                </div>
                                <p className="text-xs text-indigo-600 font-bold mt-1">
                                    {tabInfo.title}
                                </p>
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
                                <Download size={14} /> GSTR-1 JSON
                            </button>
                            <button
                                onClick={() => fetchClientData(selectedClient)}
                                className="p-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl transition"
                                title="Refresh"
                            >
                                <RefreshCw size={15} />
                            </button>
                        </div>
                    </div>

                    {/* Sub-Tab Views directly rendered based on Sidebar Selection */}
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
                    onSelectClient={(client) => {
                        fetchClientData(client);
                        setActiveAdminTab('ledger');
                    }}
                    loading={loading}
                />
            )}
        </div>
    );
};

export default AdminBookkeepingView;
