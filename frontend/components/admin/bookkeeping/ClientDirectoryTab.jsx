import React, { useState } from 'react';
import { Search, Building2, User, FileText, ArrowRight, ShieldCheck } from 'lucide-react';

const ClientDirectoryTab = ({
    clients = [],
    onSelectClient,
    loading = false
}) => {
    const [search, setSearch] = useState('');

    const filtered = clients.filter(c => 
        (c.name || '').toLowerCase().includes(search.toLowerCase()) ||
        (c.email || '').toLowerCase().includes(search.toLowerCase()) ||
        (c.phone || '').includes(search)
    );

    return (
        <div className="space-y-6">
            {/* Top Search and Metrics Header */}
            <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div>
                    <h3 className="text-xl font-black text-slate-900 leading-none">Client Accounting Directory</h3>
                    <p className="text-xs text-slate-500 font-medium mt-1">Select a business client to audit transactional ledgers, GST returns, Tally XML, or payroll.</p>
                </div>
                
                <div className="relative w-full md:w-80">
                    <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" size={16} />
                    <input 
                        type="text"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Search by client name, email, phone..."
                        className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-2xl text-xs font-medium text-slate-900 focus:outline-none focus:border-indigo-500"
                    />
                </div>
            </div>

            {/* Client Cards Grid */}
            {loading ? (
                <div className="flex justify-center py-20">
                    <div className="w-10 h-10 border-4 border-slate-200 border-t-indigo-600 rounded-full animate-spin"></div>
                </div>
            ) : filtered.length === 0 ? (
                <div className="bg-white rounded-3xl p-16 text-center border border-slate-100 shadow-sm text-slate-400">
                    <Building2 size={48} className="mx-auto mb-3 opacity-30" />
                    <p className="font-bold text-sm">No clients match your search criteria</p>
                </div>
            ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                    {filtered.map(client => (
                        <div 
                            key={client._id} 
                            onClick={() => onSelectClient(client)}
                            className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm hover:border-indigo-300 cursor-pointer transition-all flex items-center justify-between group hover:shadow-lg hover:shadow-indigo-50/80"
                        >
                            <div className="flex items-center gap-4 min-w-0">
                                <div className="w-12 h-12 bg-indigo-50 text-indigo-600 rounded-2xl flex items-center justify-center group-hover:bg-indigo-600 group-hover:text-white transition-all shadow-sm shrink-0">
                                    <Building2 size={22} />
                                </div>
                                <div className="min-w-0">
                                    <h4 className="font-black text-slate-800 text-sm leading-none mb-1 group-hover:text-indigo-600 transition-colors truncate">
                                        {client.name}
                                    </h4>
                                    <p className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider font-mono truncate">
                                        {client.email}
                                    </p>
                                    {client.phone && (
                                        <p className="text-[10px] text-slate-500 font-medium mt-0.5">
                                            {client.phone}
                                        </p>
                                    )}
                                </div>
                            </div>
                            <div className="flex items-center gap-1 text-xs font-black text-slate-300 group-hover:text-indigo-600 transition-colors shrink-0 ml-2">
                                <span>Audit</span>
                                <ArrowRight size={14} />
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default ClientDirectoryTab;
