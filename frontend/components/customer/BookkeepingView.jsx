import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    FileText, ShoppingCart, ArrowDownRight, Building2, 
    Landmark, BarChart3, Settings, Plus, RefreshCw, Eye
} from 'lucide-react';

import GSTInvoiceView from './bookkeeping/GSTInvoiceView';
import CompanySettingsModal from './bookkeeping/CompanySettingsModal';
import SalesInvoicesTab from './bookkeeping/SalesInvoicesTab';
import PurchaseBillsTab from './bookkeeping/PurchaseBillsTab';
import IncomeExpensesTab from './bookkeeping/IncomeExpensesTab';
import BankStatementsTab from './bookkeeping/BankStatementsTab';
import PartiesTab from './bookkeeping/PartiesTab';
import ReportsTab from './bookkeeping/ReportsTab';
import TransactionFormModal from './bookkeeping/TransactionFormModal';

const BookkeepingView = ({ token, activeSubTab: propSubTab, onSubTabChange }) => {
    const [internalSubTab, setInternalSubTab] = useState('sales');
    const activeSubTab = propSubTab || internalSubTab;
    const setActiveSubTab = (tab) => {
        if (onSubTabChange) onSubTabChange(tab);
        setInternalSubTab(tab);
    };

    const [transactions, setTransactions] = useState([]);
    const [company, setCompany] = useState(null);
    const [parties, setParties] = useState([]);
    const [loading, setLoading] = useState(true);

    // Modal triggers
    const [showFormModal, setShowFormModal] = useState(false);
    const [formTxType, setFormTxType] = useState('Sales');
    const [showSettingsModal, setShowSettingsModal] = useState(false);
    const [selectedInvoice, setSelectedInvoice] = useState(null);

    const config = { headers: { Authorization: `Bearer ${token}` } };

    // Fetch all core bookkeeping data
    const fetchData = async () => {
        setLoading(true);
        try {
            const [txRes, compRes, partyRes] = await Promise.allSettled([
                axios.get('/api/accounting/transactions', config),
                axios.get('/api/accounting/company', config),
                axios.get('/api/accounting/parties', config)
            ]);

            if (txRes.status === 'fulfilled') setTransactions(txRes.value.data);
            if (compRes.status === 'fulfilled') setCompany(compRes.value.data);
            if (partyRes.status === 'fulfilled' && Array.isArray(partyRes.value.data)) {
                setParties(partyRes.value.data);
            } else {
                // LocalStorage fallback
                const saved = localStorage.getItem('bookkeeping_parties');
                if (saved) setParties(JSON.parse(saved));
            }
        } catch (error) {
            console.error('Error fetching bookkeeping data:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, []);

    // Create Transaction
    const handleCreateTransaction = async (formData) => {
        try {
            const { data } = await axios.post('/api/accounting/transactions', formData, config);
            setTransactions([data, ...transactions]);
            setShowFormModal(false);
            // If new party not in directory, add it
            if (formData.partyName && !parties.some(p => p.name.toLowerCase() === formData.partyName.toLowerCase())) {
                const newParty = {
                    name: formData.partyName,
                    partyType: formData.transactionType === 'Sales' ? 'Customer' : 'Vendor',
                    gstin: formData.partyGstin || '',
                    pan: formData.partyPan || '',
                    billingAddress: formData.partyAddress || '',
                    state: formData.placeOfSupply || 'Andhra Pradesh',
                    phone: formData.partyPhone || '',
                    email: formData.partyEmail || ''
                };
                try {
                    const partyRes = await axios.post('/api/accounting/parties', newParty, config);
                    setParties([...parties, partyRes.data]);
                } catch(e) {}
            }
            alert(`${formData.transactionType} recorded successfully!`);
        } catch (error) {
            alert('Failed to save voucher: ' + (error.response?.data?.message || error.message));
        }
    };

    // Delete Transaction
    const handleDeleteTransaction = async (id) => {
        if (!window.confirm('Are you sure you want to delete this transaction voucher?')) return;
        try {
            await axios.delete(`/api/accounting/transactions/${id}`, config);
            setTransactions(transactions.filter(t => t._id !== id));
        } catch (error) {
            alert('Failed to delete voucher');
        }
    };

    // Party CRUD
    const handleAddParty = async (partyData) => {
        try {
            const { data } = await axios.post('/api/accounting/parties', partyData, config);
            setParties([...parties, data]);
        } catch (error) {
            // Local fallback
            setParties([...parties, partyData]);
            localStorage.setItem('bookkeeping_parties', JSON.stringify([...parties, partyData]));
        }
    };

    const handleEditParty = async (idOrName, updated) => {
        try {
            const { data } = await axios.put(`/api/accounting/parties/${idOrName}`, updated, config);
            setParties(parties.map(p => (p._id === idOrName ? data : p)));
        } catch (error) {
            const updatedList = parties.map(p => ((p._id === idOrName || p.name === idOrName) ? { ...p, ...updated } : p));
            setParties(updatedList);
            localStorage.setItem('bookkeeping_parties', JSON.stringify(updatedList));
        }
    };

    const handleDeleteParty = async (idOrName) => {
        if (!window.confirm('Are you sure you want to remove this party?')) return;
        try {
            await axios.delete(`/api/accounting/parties/${idOrName}`, config);
            setParties(parties.filter(p => p._id !== idOrName));
        } catch (error) {
            const updated = parties.filter(p => p._id !== idOrName && p.name !== idOrName);
            setParties(updated);
            localStorage.setItem('bookkeeping_parties', JSON.stringify(updated));
        }
    };

    // WhatsApp Share
    const handleWhatsAppShare = (inv) => {
        const text = `*Tax Invoice from ${company?.companyName || 'VR Here Customer'}*%0AInvoice No: ${inv.docNumber}%0ADate: ${inv.docDate ? new Date(inv.docDate).toLocaleDateString('en-GB') : ''}%0ATotal Amount: ₹${(inv.summary?.totalAmount || 0).toLocaleString('en-IN')}`;
        const phone = inv.partyPhone ? inv.partyPhone.replace(/[^0-9]/g, '') : '';
        const url = phone ? `https://wa.me/91${phone}?text=${text}` : `https://wa.me/?text=${text}`;
        window.open(url, '_blank');
    };

    // Current Active Tab Title
    const getSubTabInfo = () => {
        switch(activeSubTab) {
            case 'purchases': return { title: 'Purchase Bills & Inward Supplies', subtitle: 'Manage supplier bills, scanned proof attachments, and ITC entitlement.' };
            case 'expenses': return { title: 'Income & Expense Ledgers', subtitle: 'Track operational overheads, salaries, rent, and non-trading income receipts.' };
            case 'bank': return { title: 'Bank Statements & Payment Tagging', subtitle: 'Upload statements and manually tag credits/debits to invoices and ledgers.' };
            case 'parties': return { title: 'Customers & Vendors Master Directory', subtitle: 'Maintain party billing details, GSTIN, PAN, and ledger statements.' };
            case 'reports': return { title: 'Financial Reports & Profit & Loss (P&L)', subtitle: 'Real-time profit summary, turnover metrics, and net GST cash liability.' };
            default: return { title: 'Sales Invoices & Billing Hub', subtitle: 'Generate GST-compliant tax invoices, track receivables, and share via WhatsApp.' };
        }
    };

    const tabInfo = getSubTabInfo();

    // If Viewing a specific invoice in full page mode
    if (selectedInvoice) {
        return (
            <GSTInvoiceView 
                selectedInvoice={selectedInvoice}
                company={company}
                onBack={() => setSelectedInvoice(null)}
                onCopyShareLink={() => {
                    navigator.clipboard.writeText(window.location.href);
                    alert('Invoice link copied to clipboard!');
                }}
            />
        );
    }

    return (
        <div className="space-y-6 pb-20 max-w-7xl mx-auto animate-in fade-in duration-300">
            {/* Top Workspace Header */}
            <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div>
                    <div className="flex items-center gap-2">
                        <h2 className="text-2xl font-black text-slate-900 tracking-tight">{tabInfo.title}</h2>
                        <span className="bg-indigo-50 text-indigo-700 text-[10px] font-black uppercase px-2.5 py-0.5 rounded-full border border-indigo-200">
                            Bookkeeping & AaaS
                        </span>
                    </div>
                    <p className="text-xs text-slate-500 font-medium mt-1">
                        {tabInfo.subtitle}
                    </p>
                </div>

                <div className="flex items-center gap-2.5 flex-wrap">
                    <button
                        onClick={fetchData}
                        title="Refresh All Ledgers"
                        className="p-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-2xl transition"
                    >
                        <RefreshCw size={16} />
                    </button>
                    <button
                        onClick={() => setShowSettingsModal(true)}
                        className="bg-slate-100 hover:bg-slate-200 text-slate-800 px-4 py-2.5 rounded-2xl text-xs font-bold transition flex items-center gap-1.5"
                    >
                        <Settings size={15} /> Company Settings
                    </button>
                    <button
                        onClick={() => {
                            setFormTxType(activeSubTab === 'purchases' ? 'Purchase' : activeSubTab === 'expenses' ? 'Expense' : 'Sales');
                            setShowFormModal(true);
                        }}
                        className="bg-emerald-600 hover:bg-emerald-700 text-white px-5 py-2.5 rounded-2xl text-xs font-black uppercase tracking-wider transition flex items-center gap-1.5 shadow-md shadow-emerald-200"
                    >
                        <Plus size={16} /> {activeSubTab === 'purchases' ? 'Add Purchase Bill' : activeSubTab === 'expenses' ? 'Add Expense' : 'Create Invoice'}
                    </button>
                </div>
            </div>

            {/* Sub-Tab Views directly rendered based on Sidebar Selection */}
            {loading ? (
                <div className="flex justify-center py-20">
                    <div className="w-10 h-10 border-4 border-slate-200 border-t-indigo-600 rounded-full animate-spin"></div>
                </div>
            ) : (
                <>
                    {activeSubTab === 'sales' && (
                        <SalesInvoicesTab 
                            transactions={transactions}
                            onAddNew={() => {
                                setFormTxType('Sales');
                                setShowFormModal(true);
                            }}
                            onViewInvoice={(inv) => setSelectedInvoice(inv)}
                            onDeleteInvoice={handleDeleteTransaction}
                            onWhatsAppShare={handleWhatsAppShare}
                            company={company}
                        />
                    )}

                    {activeSubTab === 'purchases' && (
                        <PurchaseBillsTab 
                            transactions={transactions}
                            onAddNew={() => {
                                setFormTxType('Purchase');
                                setShowFormModal(true);
                            }}
                            onViewInvoice={(inv) => setSelectedInvoice(inv)}
                            onDeleteInvoice={handleDeleteTransaction}
                        />
                    )}

                    {activeSubTab === 'expenses' && (
                        <IncomeExpensesTab 
                            transactions={transactions}
                            onAddNewIncome={() => {
                                setFormTxType('Income');
                                setShowFormModal(true);
                            }}
                            onAddNewExpense={() => {
                                setFormTxType('Expense');
                                setShowFormModal(true);
                            }}
                            onViewInvoice={(inv) => setSelectedInvoice(inv)}
                            onDeleteInvoice={handleDeleteTransaction}
                        />
                    )}

                    {activeSubTab === 'bank' && (
                        <BankStatementsTab 
                            token={token}
                            transactions={transactions}
                            company={company}
                            onRefreshLedger={fetchData}
                        />
                    )}

                    {activeSubTab === 'parties' && (
                        <PartiesTab 
                            parties={parties}
                            onAddParty={handleAddParty}
                            onEditParty={handleEditParty}
                            onDeleteParty={handleDeleteParty}
                        />
                    )}

                    {activeSubTab === 'reports' && (
                        <ReportsTab 
                            transactions={transactions}
                            company={company}
                        />
                    )}
                </>
            )}

            {/* Modal: Add/Edit Transaction */}
            <TransactionFormModal 
                show={showFormModal}
                onClose={() => setShowFormModal(false)}
                txType={formTxType}
                onSubmit={handleCreateTransaction}
                parties={parties}
                companyState={company?.state || 'Andhra Pradesh'}
                invoiceCount={transactions.filter(t => t.transactionType === formTxType).length + 1}
            />

            {/* Modal: Company Settings */}
            <CompanySettingsModal 
                show={showSettingsModal}
                onClose={() => setShowSettingsModal(false)}
                company={company}
                onSave={async (compData) => {
                    try {
                        const { data } = await axios.post('/api/accounting/company', compData, config);
                        setCompany(data);
                        setShowSettingsModal(false);
                        alert('Company profile & tax settings saved successfully!');
                    } catch (error) {
                        alert('Failed to save settings: ' + (error.response?.data?.message || error.message));
                    }
                }}
            />
        </div>
    );
};

export default BookkeepingView;
