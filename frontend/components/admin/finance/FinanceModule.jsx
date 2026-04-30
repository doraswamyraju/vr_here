import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import { 
    FileText, Plus, Search, Filter, 
    Download, Trash2, Edit3, Eye, 
    ArrowLeft, Printer, Send, CreditCard,
    ChevronRight, CheckCircle2, AlertCircle, Clock
} from 'lucide-react';
import FinanceForm from './FinanceForm';
import FinanceList from './FinanceList';
import GSTInvoiceTemplate from './GSTInvoiceTemplate';

const Card = ({ children, className = '' }) => (
    <div className={`bg-white rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 overflow-hidden ${className}`}>
        {children}
    </div>
);

const FinanceModule = ({ token }) => {
    const [view, setView] = useState('list'); // 'list' | 'create' | 'edit' | 'view'
    const [type, setType] = useState('Invoice'); // 'Estimate' | 'Invoice' | 'Payment' | 'CreditNote' | 'Proforma'
    const [records, setRecords] = useState([]);
    const [selectedRecord, setSelectedRecord] = useState(null);
    const [loading, setLoading] = useState(false);
    const [searchQuery, setSearchQuery] = useState('');

    const config = useMemo(() => ({
        headers: { Authorization: `Bearer ${token}` }
    }), [token]);

    const fetchRecords = async () => {
        setLoading(true);
        try {
            const { data } = await axios.get(`/api/finance?type=${type}`, config);
            setRecords(data);
        } catch (error) {
            console.error('Failed to fetch finance records:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchRecords();
    }, [type, config]);

    const handleCreate = (selectedType) => {
        setType(selectedType);
        setSelectedRecord(null);
        setView('create');
    };

    const handleEdit = (record) => {
        setSelectedRecord(record);
        setView('edit');
    };

    const handleView = (record) => {
        setSelectedRecord(record);
        setView('view');
    };

    const handleDelete = async (id) => {
        if (!window.confirm('Are you sure you want to delete this record?')) return;
        try {
            await axios.delete(`/api/finance/${id}`, config);
            fetchRecords();
        } catch (error) {
            alert('Failed to delete record');
        }
    };

    const FinanceSubNav = () => {
        const items = [
            { id: 'Estimate', label: 'Estimate/ Quotation' },
            { id: 'Invoice', label: 'Sale Invoices' },
            { id: 'Proforma', label: 'Proforma Invoice' },
            { id: 'Payment', label: 'Payment-In' },
            { id: 'CreditNote', label: 'Credit Notes' }
        ];

        return (
            <div className="w-72 space-y-2 pr-6 border-r border-slate-100 shrink-0 hidden lg:block">
                <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest px-4 mb-4">Finance Categories</p>
                {items.map(item => (
                    <div key={item.id} className="group relative flex items-center">
                        <button
                            onClick={() => { setType(item.id); setView('list'); }}
                            className={`flex-grow flex items-center justify-between px-4 py-3.5 rounded-2xl transition-all font-bold text-sm ${type === item.id ? 'bg-slate-900 text-white shadow-xl shadow-slate-300' : 'text-slate-600 hover:bg-slate-50'}`}
                        >
                            <span className="truncate">{item.label}</span>
                            {type === item.id && <ChevronRight size={14} className="text-red-500" />}
                        </button>
                        <button 
                            onClick={(e) => { e.stopPropagation(); handleCreate(item.id); }}
                            className={`absolute right-2 p-1.5 rounded-lg transition-all opacity-0 group-hover:opacity-100 ${type === item.id ? 'text-white hover:bg-white/10' : 'text-slate-400 hover:bg-slate-100'}`}
                        >
                            <Plus size={16} />
                        </button>
                    </div>
                ))}
            </div>
        );
    };

    const filteredRecords = records.filter(r => 
        r.number.toLowerCase().includes(searchQuery.toLowerCase()) ||
        r.client.name.toLowerCase().includes(searchQuery.toLowerCase())
    );

    return (
        <div className="flex h-full min-h-[600px]">
            {view === 'list' && <FinanceSubNav />}

            <div className="flex-1 min-w-0 pl-0 lg:pl-6">
                {view === 'list' ? (
                    <div className="space-y-6 animate-in fade-in slide-in-from-right-4 duration-500">
                        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                            <div>
                                <h2 className="text-2xl font-black text-slate-900 tracking-tight">{type}s</h2>
                                <p className="text-xs text-slate-500 font-medium">Manage your {type.toLowerCase()} records and documentation.</p>
                            </div>
                            <button 
                                onClick={() => handleCreate(type)}
                                className="bg-red-600 text-white px-6 py-3 rounded-2xl font-black text-sm shadow-xl shadow-red-100 hover:bg-red-700 transition flex items-center gap-2 transform active:scale-95"
                            >
                                <Plus size={18} /> New {type}
                            </button>
                        </div>

                        <Card className="p-4 flex flex-col sm:flex-row gap-4">
                            <div className="flex-1 relative">
                                <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
                                <input 
                                    type="text" 
                                    placeholder={`Search by ${type.toLowerCase()} # or client name...`}
                                    className="w-full pl-12 pr-4 py-3 bg-slate-50 border-none rounded-xl text-sm font-bold focus:ring-2 focus:ring-red-500/20 transition-all"
                                    value={searchQuery}
                                    onChange={(e) => setSearchQuery(e.target.value)}
                                />
                            </div>
                            <button className="px-6 py-3 bg-white border border-slate-200 rounded-xl text-slate-600 font-bold text-sm hover:bg-slate-50 transition flex items-center gap-2">
                                <Filter size={18} /> Filter
                            </button>
                        </Card>

                        <FinanceList 
                            records={filteredRecords} 
                            loading={loading} 
                            onView={handleView} 
                            onEdit={handleEdit} 
                            onDelete={handleDelete}
                            type={type}
                        />
                    </div>
                ) : view === 'view' && selectedRecord ? (
                    <div className="space-y-6 animate-in fade-in zoom-in-95 duration-500">
                        <div className="flex justify-between items-center bg-white p-4 rounded-2xl border border-slate-100 sticky top-0 z-10 shadow-sm">
                            <button onClick={() => setView('list')} className="flex items-center gap-2 text-slate-600 font-bold text-sm hover:text-slate-900 transition">
                                <ArrowLeft size={18} /> Back to List
                            </button>
                            <div className="flex gap-2">
                                <button onClick={() => window.print()} className="p-2.5 bg-slate-100 text-slate-600 rounded-xl hover:bg-slate-200 transition shadow-sm" title="Print Invoice">
                                    <Printer size={18} />
                                </button>
                                <button className="p-2.5 bg-slate-100 text-slate-600 rounded-xl hover:bg-slate-200 transition shadow-sm" title="Send Email">
                                    <Send size={18} />
                                </button>
                                <button onClick={() => handleEdit(selectedRecord)} className="bg-slate-900 text-white px-6 py-2.5 rounded-xl font-bold text-sm hover:bg-slate-800 transition flex items-center gap-2 shadow-lg shadow-slate-200">
                                    <Edit3 size={18} /> Edit {type}
                                </button>
                            </div>
                        </div>
                        <GSTInvoiceTemplate data={selectedRecord} />
                    </div>
                ) : (
                    <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
                        <div className="mb-6 flex items-center justify-between">
                            <button onClick={() => setView('list')} className="flex items-center gap-2 text-slate-600 font-bold text-sm hover:text-slate-900 transition">
                                <ArrowLeft size={18} /> Cancel & Go Back
                            </button>
                            <h2 className="text-xl font-black text-slate-900 uppercase tracking-tighter">{view === 'edit' ? 'Edit' : 'Create New'} {type}</h2>
                        </div>
                        <FinanceForm 
                            type={type} 
                            initialData={selectedRecord} 
                            token={token} 
                            onSuccess={() => { setView('list'); fetchRecords(); }} 
                        />
                    </div>
                )}
            </div>
        </div>
    );
};

export default FinanceModule;
