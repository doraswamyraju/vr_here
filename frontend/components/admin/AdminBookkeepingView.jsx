import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import { 
    FileText, ShieldCheck, FileSpreadsheet, Users, 
    ArrowLeft, Download, RefreshCw, Eye, Building2,
    Calendar, ChevronLeft, ChevronRight, Sparkles, Landmark,
    Layers, CheckCircle2
} from 'lucide-react';

import AdminFilingsMatrixTab from './bookkeeping/AdminFilingsMatrixTab';
import LedgerAuditTab from './bookkeeping/LedgerAuditTab';
import AdminBankReconTab from './bookkeeping/AdminBankReconTab';
import GstReturnsTab from './bookkeeping/GstReturnsTab';
import TallyExportTab from './bookkeeping/TallyExportTab';
import PayrollAuditTab from './bookkeeping/PayrollAuditTab';
import GSTInvoiceView from '../customer/bookkeeping/GSTInvoiceView';

const MONTHS_LIST = [
    { id: 'April 2026', label: 'Apr 2026' },
    { id: 'May 2026', label: 'May 2026' },
    { id: 'June 2026', label: 'Jun 2026' },
    { id: 'July 2026', label: 'Jul 2026' },
    { id: 'August 2026', label: 'Aug 2026' },
    { id: 'September 2026', label: 'Sep 2026' },
    { id: 'October 2026', label: 'Oct 2026' },
    { id: 'November 2026', label: 'Nov 2026' },
    { id: 'December 2026', label: 'Dec 2026' },
    { id: 'January 2027', label: 'Jan 2027' },
    { id: 'February 2027', label: 'Feb 2027' },
    { id: 'March 2027', label: 'Mar 2027' },
    { id: 'ALL', label: 'All Months (FY 26-27)' }
];

const AdminBookkeepingView = ({ token, activeSubTab: propSubTab, onSubTabChange }) => {
    const [internalSubTab, setInternalSubTab] = useState('matrix');
    const activeAdminTab = propSubTab || internalSubTab;
    const setActiveAdminTab = (tab) => {
        if (onSubTabChange) onSubTabChange(tab);
        setInternalSubTab(tab);
    };

    const currentMonthName = useMemo(() => {
        return new Date().toLocaleDateString('en-GB', { month: 'long', year: 'numeric' });
    }, []);

    // Default to active current month
    const [selectedMonth, setSelectedMonth] = useState(() => {
        const cur = new Date().toLocaleDateString('en-GB', { month: 'long', year: 'numeric' });
        const match = MONTHS_LIST.find(m => m.id.toLowerCase() === cur.toLowerCase());
        return match ? match.id : 'September 2026';
    });

    const [matrixData, setMatrixData] = useState(null);
    const [matrixLoading, setMatrixLoading] = useState(true);

    const [selectedClient, setSelectedClient] = useState(null);
    const [clientDataLoading, setClientDataLoading] = useState(false);
    const [transactions, setTransactions] = useState([]);
    const [payrollRecords, setPayrollRecords] = useState([]);
    const [gstr3bData, setGstr3bData] = useState(null);
    const [selectedInvoice, setSelectedInvoice] = useState(null);

    const config = { headers: { Authorization: `Bearer ${token}` } };

    // Fetch All-Clients Compliance Matrix for selected month
    const fetchMatrixData = async () => {
        setMatrixLoading(true);
        try {
            const { data } = await axios.get(`/api/accounting/filings/matrix?month=${encodeURIComponent(selectedMonth)}`, config);
            setMatrixData(data);
        } catch (error) {
            console.error('Failed to fetch filings matrix:', error);
        } finally {
            setMatrixLoading(false);
        }
    };

    useEffect(() => {
        fetchMatrixData();
    }, [selectedMonth]);

    // Fetch individual client bookkeeping data
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

    // Filter client transactions for selected month
    const filteredTransactions = useMemo(() => {
        if (selectedMonth === 'ALL') return transactions;
        return transactions.filter(t => {
            if (!t.docDate) return false;
            const d = new Date(t.docDate);
            const mStr = d.toLocaleDateString('en-GB', { month: 'long', year: 'numeric' });
            return mStr.toLowerCase() === selectedMonth.toLowerCase();
        });
    }, [transactions, selectedMonth]);

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
            alert('Payroll record added successfully!');
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
            downloadAnchor.setAttribute("download", `GSTR1_${(selectedClient.companyName || selectedClient.name).replace(/\s+/g, '_')}_${selectedMonth.replace(/\s+/g, '_')}.json`);
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
        } catch (error) {
            alert('Failed to generate GSTR1 offline file');
        }
    };

    // Sub-tab info
    const getAdminSubTabInfo = () => {
        switch(activeAdminTab) {
            case 'matrix': return { title: 'Monthly Filings & Bookkeeping Matrix', subtitle: 'Compliance tracker, return sign-offs, and bank health across all client portfolios.' };
            case 'bank': return { title: 'Bank Reconciliation Audit', subtitle: 'Audit and tag bank statement credits and debits to invoices and ledgers.' };
            case 'ledger': return { title: 'Sales & Purchases Voucher Audit', subtitle: 'Verify tax invoices, vendor bills, and line item tax calculations.' };
            case 'gst': return { title: 'GST Statutory Returns & GSTR-3B Computation', subtitle: 'Export GSTR-1 portal JSON, reconcile 2B ITC, and record PMT-06 sign-off.' };
            case 'tally': return { title: 'Tally Prime XML & ERP Exporter', subtitle: 'Export multi-voucher XML payloads for 1-click Tally Prime import.' };
            case 'payroll': return { title: 'Staff Payroll, TDS & Form 16 Register', subtitle: 'Manage salary registers, TDS deduction certificates, and Form 16.' };
            default: return { title: 'Monthly Accounting & Compliance Desk', subtitle: 'Complete monthly audit, GST return sign-off, and Tally ERP sync.' };
        }
    };

    const tabInfo = getAdminSubTabInfo();

    // If Viewing a specific invoice in full page mode
    if (selectedInvoice) {
        return (
            <GSTInvoiceView 
                selectedInvoice={selectedInvoice}
                company={null}
                onBack={() => setSelectedInvoice(null)}
                onCopyShareLink={() => alert('Invoice link copied!')}
            />
        );
    }

    const workflowSteps = [
        { id: 'bank', label: '1. Bank Recon', icon: Landmark },
        { id: 'ledger', label: '2. Vouchers Audit', icon: FileText },
        { id: 'gst', label: '3. GST Returns & 2B', icon: ShieldCheck },
        { id: 'tally', label: '4. Tally ERP Export', icon: FileSpreadsheet },
        { id: 'payroll', label: '5. Payroll & TDS', icon: Users }
    ];

    return (
        <div className="space-y-6 pb-20 max-w-7xl mx-auto animate-in fade-in duration-300">
            {/* Top Period & Month Switcher Bar */}
            <div className="bg-white p-3 rounded-2xl border border-slate-100 shadow-sm flex flex-col sm:flex-row items-center justify-between gap-3">
                <div className="flex items-center gap-2.5 w-full sm:w-auto">
                    <div className="flex items-center gap-1.5 px-3 py-2 bg-slate-100 rounded-xl text-xs font-black text-slate-800 shrink-0">
                        <Calendar size={14} className="text-indigo-600" />
                        <span>FY 2026-27</span>
                    </div>

                    {/* Month Stepper & Dropdown */}
                    <div className="flex items-center bg-slate-50 border border-slate-200 rounded-xl p-0.5">
                        <button
                            onClick={() => {
                                const idx = MONTHS_LIST.findIndex(m => m.id === selectedMonth);
                                if (idx > 0) setSelectedMonth(MONTHS_LIST[idx - 1].id);
                                else if (selectedMonth === 'ALL') setSelectedMonth(MONTHS_LIST[0].id);
                            }}
                            disabled={selectedMonth === MONTHS_LIST[0].id}
                            title="Previous Month"
                            className="p-1.5 text-slate-500 hover:text-slate-900 hover:bg-white rounded-lg transition disabled:opacity-30 disabled:pointer-events-none"
                        >
                            <ChevronLeft size={15} />
                        </button>

                        <select
                            value={selectedMonth}
                            onChange={(e) => setSelectedMonth(e.target.value)}
                            className="bg-transparent text-xs font-black text-slate-900 px-3 py-1.5 focus:outline-none cursor-pointer"
                        >
                            {MONTHS_LIST.map(m => (
                                <option key={m.id} value={m.id}>
                                    {m.id.toLowerCase() === currentMonthName.toLowerCase() ? `⭐ ${m.label} (Current)` : m.label}
                                </option>
                            ))}
                        </select>

                        <button
                            onClick={() => {
                                const idx = MONTHS_LIST.findIndex(m => m.id === selectedMonth);
                                if (idx >= 0 && idx < MONTHS_LIST.length - 2) setSelectedMonth(MONTHS_LIST[idx + 1].id);
                            }}
                            disabled={selectedMonth === MONTHS_LIST[MONTHS_LIST.length - 2]?.id}
                            title="Next Month"
                            className="p-1.5 text-slate-500 hover:text-slate-900 hover:bg-white rounded-lg transition disabled:opacity-30 disabled:pointer-events-none"
                        >
                            <ChevronRight size={15} />
                        </button>
                    </div>
                </div>

                {/* Quick Switcher Shortcuts */}
                <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
                    <button
                        onClick={() => {
                            const match = MONTHS_LIST.find(m => m.id.toLowerCase() === currentMonthName.toLowerCase());
                            setSelectedMonth(match ? match.id : 'September 2026');
                        }}
                        className={`px-3.5 py-2 rounded-xl text-xs font-bold transition flex items-center gap-1.5 ${
                            selectedMonth.toLowerCase() === currentMonthName.toLowerCase()
                                ? 'bg-indigo-600 text-white shadow-xs font-black'
                                : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                        }`}
                    >
                        <Sparkles size={13} />
                        <span>Current Month</span>
                    </button>

                    <button
                        onClick={() => setSelectedMonth('ALL')}
                        className={`px-3.5 py-2 rounded-xl text-xs font-bold transition ${
                            selectedMonth === 'ALL'
                                ? 'bg-slate-900 text-white shadow-xs font-black'
                                : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                        }`}
                    >
                        All Months (FY 26-27)
                    </button>
                </div>
            </div>

            {/* If Client is Selected -> Dedicated Audit Desk */}
            {selectedClient ? (
                <div className="space-y-5">
                    {/* Top Client Header & Breadcrumbs */}
                    <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                        <div className="flex items-center gap-3">
                            <button 
                                onClick={() => {
                                    setSelectedClient(null);
                                    setActiveAdminTab('matrix');
                                }}
                                className="px-3 py-2 bg-slate-100 hover:bg-slate-200 text-slate-800 rounded-xl transition font-black text-xs flex items-center gap-1.5"
                            >
                                <ArrowLeft size={14} /> Back to All Clients
                            </button>

                            <div className="h-6 w-px bg-slate-200" />

                            <div>
                                <div className="flex items-center gap-2">
                                    <h3 className="text-lg font-black text-slate-900 leading-none">
                                        {selectedClient.companyName || selectedClient.name}
                                    </h3>
                                    {selectedClient.gstin && (
                                        <span className="text-[10px] font-bold text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded-full border border-indigo-200 font-mono">
                                            {selectedClient.gstin}
                                        </span>
                                    )}
                                </div>
                                <p className="text-xs text-slate-500 font-medium mt-0.5">
                                    {tabInfo.subtitle}
                                </p>
                            </div>
                        </div>

                        <div className="flex items-center gap-2 flex-wrap">
                            <button 
                                onClick={handleDownloadTally}
                                className="bg-slate-900 hover:bg-slate-800 text-white px-3.5 py-2 rounded-xl text-xs font-bold transition flex items-center gap-1.5 shadow-sm"
                            >
                                <FileSpreadsheet size={14} /> Tally XML
                            </button>
                            <button 
                                onClick={handleDownloadGstr1}
                                className="bg-emerald-600 hover:bg-emerald-700 text-white px-3.5 py-2 rounded-xl text-xs font-bold transition flex items-center gap-1.5 shadow-sm"
                            >
                                <Download size={14} /> GSTR-1 JSON
                            </button>
                            <button
                                onClick={() => fetchClientData(selectedClient)}
                                className="p-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl transition"
                                title="Refresh Client Data"
                            >
                                <RefreshCw size={15} />
                            </button>
                        </div>
                    </div>

                    {/* Monthly Filing Workflow Stepper Bar */}
                    <div className="bg-white p-2 rounded-2xl border border-slate-100 shadow-sm flex items-center gap-1.5 overflow-x-auto">
                        {workflowSteps.map(step => {
                            const Icon = step.icon;
                            const isActive = activeAdminTab === step.id;
                            return (
                                <button
                                    key={step.id}
                                    onClick={() => setActiveAdminTab(step.id)}
                                    className={`px-4 py-2.5 rounded-xl text-xs font-bold transition flex items-center gap-2 shrink-0 ${
                                        isActive
                                            ? 'bg-indigo-600 text-white shadow-md shadow-indigo-200 font-black'
                                            : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                                    }`}
                                >
                                    <Icon size={14} className={isActive ? 'text-white' : 'text-slate-400'} />
                                    <span>{step.label}</span>
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
                            {activeAdminTab === 'bank' && (
                                <AdminBankReconTab 
                                    token={token}
                                    selectedClient={selectedClient}
                                    transactions={transactions}
                                    selectedMonth={selectedMonth}
                                    onRefreshLedger={() => fetchClientData(selectedClient)}
                                />
                            )}

                            {activeAdminTab === 'ledger' && (
                                <LedgerAuditTab 
                                    transactions={filteredTransactions}
                                    selectedClient={selectedClient}
                                    onVerifyTransaction={handleVerifyTransaction}
                                    onViewInvoice={(tx) => setSelectedInvoice(tx)}
                                    onRefresh={() => fetchClientData(selectedClient)}
                                />
                            )}

                            {activeAdminTab === 'gst' && (
                                <GstReturnsTab 
                                    token={token}
                                    selectedClient={selectedClient}
                                    selectedMonth={selectedMonth}
                                    transactions={filteredTransactions}
                                    gstr3bData={gstr3bData}
                                    onDownloadGstr1={handleDownloadGstr1}
                                    onRefresh={() => fetchClientData(selectedClient)}
                                />
                            )}

                            {activeAdminTab === 'tally' && (
                                <TallyExportTab 
                                    selectedClient={selectedClient}
                                    onDownloadTally={handleDownloadTally}
                                    transactionsCount={filteredTransactions.length}
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
                /* Mode 1: All Clients Monthly Filings Matrix */
                <AdminFilingsMatrixTab 
                    matrixData={matrixData}
                    selectedMonth={selectedMonth}
                    onSelectClient={(client) => {
                        fetchClientData(client);
                        setActiveAdminTab('bank');
                    }}
                    onRefresh={fetchMatrixData}
                    loading={matrixLoading}
                />
            )}
        </div>
    );
};

export default AdminBookkeepingView;
