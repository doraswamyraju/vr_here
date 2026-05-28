import React, { useState, useMemo } from 'react';
import { Search, User, Mail, Phone, ExternalLink, IndianRupee, Layers, CheckCircle2, AlertCircle, Copy, Check } from 'lucide-react';
import { rupees } from '../../../modules/orders/v1.1/utils/helpers';

const Card = ({ children, className = '' }) => (
  <div className={`rounded-3xl border border-white/80 bg-white/70 backdrop-blur-xl shadow-[0_15px_35px_rgba(15,23,42,0.04)] hover:shadow-[0_20px_45px_rgba(15,23,42,0.06)] transition-all duration-300 ${className}`}>
    {children}
  </div>
);

const CustomersModule = ({ users = [], orders = [], onViewOrder }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCustomerId, setSelectedCustomerId] = useState(null);
  const [copiedId, setCopiedId] = useState(null);

  // Filter users to only show clients
  const customers = useMemo(() => {
    return users.filter(u => u.role === 'client');
  }, [users]);

  // Filter customers based on search
  const filteredCustomers = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    if (!q) return customers;
    return customers.filter(c => 
      c.name?.toLowerCase().includes(q) || 
      c.email?.toLowerCase().includes(q) || 
      c.phone?.includes(q)
    );
  }, [customers, searchQuery]);

  // Aggregate project data for each customer
  const customerAnalytics = useMemo(() => {
    const analytics = {};
    customers.forEach(c => {
      const clientOrders = orders.filter(o => 
        o.user?._id === c._id || 
        o.email?.toLowerCase() === c.email?.toLowerCase() || 
        o.phone === c.phone
      );

      const totalRevenue = clientOrders.reduce((sum, o) => sum + Number(o.price || 0), 0);
      const activeCount = clientOrders.filter(o => o.status !== 'Completed').length;
      
      // Calculate outstanding sent but unpaid invoices balance
      let outstandingBalance = 0;
      clientOrders.forEach(order => {
        (order.invoices || []).forEach(inv => {
          if (inv.status === 'Sent') {
            outstandingBalance += Number(inv.amount || 0);
          }
        });
      });
      
      analytics[c._id] = {
        orders: clientOrders,
        totalRevenue,
        activeCount,
        outstandingBalance
      };
    });
    return analytics;
  }, [customers, orders]);

  const selectedCustomer = useMemo(() => {
    return customers.find(c => c._id === selectedCustomerId) || null;
  }, [customers, selectedCustomerId]);

  const selectedCustomerData = useMemo(() => {
    if (!selectedCustomerId) return null;
    return customerAnalytics[selectedCustomerId] || { orders: [], totalRevenue: 0, activeCount: 0, outstandingBalance: 0 };
  }, [selectedCustomerId, customerAnalytics]);

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const getInitialsGradient = (name) => {
    const char = name?.charAt(0).toUpperCase() || 'C';
    const charCode = char.charCodeAt(0);
    if (charCode < 70) return 'from-indigo-500 to-purple-600';
    if (charCode < 80) return 'from-teal-400 to-emerald-600';
    if (charCode < 90) return 'from-pink-500 to-rose-600';
    return 'from-orange-400 to-red-600';
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-black text-slate-900 tracking-tight leading-none">Customer Directory</h2>
          <p className="text-sm text-slate-500 mt-1.5 font-medium">Track client projects, billing statements, and outstanding balances.</p>
        </div>

        <div className="relative w-full max-w-md shadow-sm rounded-2xl overflow-hidden border border-slate-200 bg-white">
          <input 
            type="text"
            placeholder="Search by name, email, or phone..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-11 pr-4 py-3 bg-white text-sm font-semibold text-slate-800 placeholder-slate-400 outline-none focus:ring-2 focus:ring-indigo-500/20"
          />
          <Search className="absolute left-4 top-3.5 text-slate-400" size={16} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Customers List */}
        <div className="lg:col-span-1 space-y-3 max-h-[72vh] overflow-y-auto pr-1">
          {filteredCustomers.map(customer => {
            const data = customerAnalytics[customer._id] || { orders: [], totalRevenue: 0, activeCount: 0, outstandingBalance: 0 };
            const isActive = selectedCustomerId === customer._id;
            const gradient = getInitialsGradient(customer.name);

            return (
              <div 
                key={customer._id}
                onClick={() => setSelectedCustomerId(customer._id)}
                className={`p-4 rounded-2xl border cursor-pointer transition-all duration-300 transform ${
                  isActive 
                    ? 'bg-gradient-to-br from-indigo-600 to-indigo-700 text-white border-indigo-600 shadow-xl shadow-indigo-100 -translate-y-0.5' 
                    : 'bg-white border-slate-100 hover:border-indigo-400 hover:shadow-lg hover:shadow-indigo-50/50 hover:-translate-y-0.5'
                }`}
              >
                <div className="flex items-start gap-3">
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center text-xs font-black shadow-md ${
                    isActive ? 'bg-white/20 text-white' : `bg-gradient-to-br ${gradient} text-white`
                  }`}>
                    {customer.name?.charAt(0).toUpperCase() || 'C'}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-1.5">
                      <p className={`text-sm font-black truncate ${isActive ? 'text-white' : 'text-slate-800'}`}>
                        {customer.name}
                      </p>
                      {data.outstandingBalance > 0 && (
                        <span className={`px-2 py-0.5 rounded-full text-[8px] font-black uppercase flex-shrink-0 flex items-center gap-0.5 ${
                          isActive ? 'bg-rose-500 text-white' : 'bg-rose-50 text-rose-600'
                        }`}>
                          <AlertCircle size={8} /> Due
                        </span>
                      )}
                    </div>
                    <p className={`text-xs mt-0.5 truncate ${isActive ? 'text-indigo-100' : 'text-slate-400'}`}>
                      {customer.email}
                    </p>
                  </div>
                </div>

                <div className="flex items-center justify-between border-t border-white/10 mt-3 pt-3 text-[10px] uppercase font-black tracking-wider">
                  <span className={`inline-flex items-center gap-1 ${isActive ? 'text-indigo-200' : 'text-slate-400'}`}>
                    <Layers size={10} /> {data.orders.length} {data.orders.length === 1 ? 'Project' : 'Projects'}
                  </span>
                  <span className={isActive ? 'text-white' : 'text-slate-850 font-black'}>
                    {rupees(data.totalRevenue)}
                  </span>
                </div>
              </div>
            );
          })}

          {filteredCustomers.length === 0 && (
            <p className="text-center text-xs text-slate-400 italic py-8 border border-dashed border-slate-200 rounded-2xl">No customers matching query.</p>
          )}
        </div>

        {/* Right Column: Redesigned Premium Detail Pane */}
        <div className="lg:col-span-2">
          {selectedCustomer ? (
            <Card className="p-6 space-y-6">
              
              {/* Premium Profile Banner Header */}
              <div className="relative rounded-2xl bg-gradient-to-r from-slate-900 via-slate-850 to-slate-900 p-6 text-white overflow-hidden shadow-lg border border-slate-800">
                <div className="absolute right-0 top-0 w-1/3 h-full bg-[radial-gradient(circle_at_top_right,rgba(99,102,241,0.15),transparent_70%)] pointer-events-none" />
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="flex items-start gap-4">
                    <div className={`w-14 h-14 rounded-2xl flex items-center justify-center text-lg font-black shadow-lg bg-gradient-to-br ${getInitialsGradient(selectedCustomer.name)} text-white`}>
                      {selectedCustomer.name?.charAt(0).toUpperCase() || 'C'}
                    </div>
                    <div>
                      <span className="text-[9px] font-black uppercase text-indigo-400 tracking-widest bg-indigo-500/10 border border-indigo-500/25 px-2 py-0.5 rounded-full">Client Workspace</span>
                      <h3 className="text-2xl font-black mt-1 leading-tight tracking-tight">{selectedCustomer.name}</h3>
                      <p className="text-xs text-slate-400 font-medium mt-1">ID: #{selectedCustomer._id?.substring(selectedCustomer._id.length - 8).toUpperCase()}</p>
                    </div>
                  </div>
                </div>
                
                {/* Quick Action Contact Row */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-6 border-t border-slate-800 pt-5 text-xs font-bold text-slate-300">
                  <div className="flex items-center justify-between p-2.5 rounded-xl border border-slate-800/80 bg-slate-950/40 hover:bg-slate-950/60 transition group cursor-pointer" onClick={() => handleCopy(selectedCustomer.email, 'email')}>
                    <div className="flex items-center gap-2 truncate">
                      <Mail size={14} className="text-indigo-400 group-hover:scale-110 transition-transform" />
                      <span className="truncate">{selectedCustomer.email}</span>
                    </div>
                    {copiedId === 'email' ? <Check size={12} className="text-emerald-400 flex-shrink-0" /> : <Copy size={12} className="text-slate-500 group-hover:text-slate-300 flex-shrink-0 ml-1" />}
                  </div>
                  {selectedCustomer.phone && (
                    <div className="flex items-center justify-between p-2.5 rounded-xl border border-slate-800/80 bg-slate-950/40 hover:bg-slate-950/60 transition group cursor-pointer" onClick={() => handleCopy(selectedCustomer.phone, 'phone')}>
                      <div className="flex items-center gap-2 truncate">
                        <Phone size={14} className="text-indigo-400 group-hover:scale-110 transition-transform" />
                        <span>{selectedCustomer.phone}</span>
                      </div>
                      {copiedId === 'phone' ? <Check size={12} className="text-emerald-400 flex-shrink-0" /> : <Copy size={12} className="text-slate-500 group-hover:text-slate-300 flex-shrink-0 ml-1" />}
                    </div>
                  )}
                </div>
              </div>

              {/* Outstanding Balance Warning Banner */}
              {selectedCustomerData.outstandingBalance > 0 && (
                <div className="p-4 rounded-2xl bg-rose-50 border border-rose-100 flex items-center justify-between gap-4 animate-in fade-in slide-in-from-top-4 duration-300">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-xl bg-rose-100 text-rose-600 flex items-center justify-center flex-shrink-0">
                      <AlertCircle size={18} />
                    </div>
                    <div>
                      <p className="text-xs font-black text-rose-800 uppercase tracking-widest">Pending Invoices Alert</p>
                      <p className="text-xs text-rose-600 font-bold mt-0.5">This customer has unpaid milestone payment links issued.</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-rose-500 font-bold">Outstanding</p>
                    <p className="text-lg font-black text-rose-700 tracking-tight">{rupees(selectedCustomerData.outstandingBalance)}</p>
                  </div>
                </div>
              )}

              {/* CRM Key Metrics */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="p-4 rounded-2xl border border-slate-200 bg-slate-50/30 flex flex-col justify-center">
                  <p className="text-[9px] font-black uppercase text-slate-400 tracking-wider">Lifetime Value (LTV)</p>
                  <p className="text-2xl font-black text-slate-800 mt-1 tracking-tight">{rupees(selectedCustomerData.totalRevenue)}</p>
                </div>
                <div className="p-4 rounded-2xl border border-slate-200 bg-slate-50/30 flex flex-col justify-center">
                  <p className="text-[9px] font-black uppercase text-slate-400 tracking-wider">Active Pipelines</p>
                  <p className="text-2xl font-black text-indigo-600 mt-1 tracking-tight">{selectedCustomerData.activeCount} Active</p>
                </div>
                <div className="p-4 rounded-2xl border border-slate-200 bg-slate-50/30 flex flex-col justify-center">
                  <p className="text-[9px] font-black uppercase text-slate-400 tracking-wider">Conversion Ratio</p>
                  <p className="text-2xl font-black text-emerald-600 mt-1 tracking-tight">
                    {selectedCustomerData.orders.length > 0 
                      ? `${Math.round((selectedCustomerData.orders.filter(o => o.status === 'Completed').length / selectedCustomerData.orders.length) * 100)}%`
                      : 'N/A'
                    }
                  </p>
                </div>
              </div>

              {/* Linked Projects Grid */}
              <div className="space-y-4">
                <h4 className="text-xs font-black uppercase text-slate-400 tracking-widest flex items-center gap-1.5 border-b border-slate-100 pb-2">
                  <Layers size={14} className="text-indigo-500" /> Linked Projects & Subscriptions ({selectedCustomerData.orders.length})
                </h4>

                <div className="grid grid-cols-1 gap-3 max-h-[360px] overflow-y-auto pr-1">
                  {selectedCustomerData.orders.map(project => (
                    <div 
                      key={project._id}
                      className="p-4 rounded-2xl border border-slate-200 bg-white flex items-center justify-between hover:border-indigo-400 hover:shadow-lg transition-all duration-300"
                    >
                      <div>
                        <p className="text-sm font-black text-slate-800">{project.serviceName}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <span className={`px-1.5 py-0.5 rounded text-[8px] font-black uppercase tracking-wider ${
                            project.status === 'Completed' ? 'bg-emerald-50 text-emerald-700' : 'bg-indigo-50 text-indigo-700'
                          }`}>
                            {project.packageName || 'Basic'}
                          </span>
                          <span className={`px-1.5 py-0.5 rounded text-[8px] font-black uppercase tracking-wider ${
                            project.status === 'Completed' ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800'
                          }`}>
                            {project.status}
                          </span>
                        </div>
                      </div>

                      <div className="flex items-center gap-4">
                        <div className="text-right">
                          <p className="text-sm font-black text-slate-900 tracking-tight">{rupees(project.price)}</p>
                          <p className="text-[9px] text-slate-400 font-bold uppercase mt-0.5">Budget</p>
                        </div>
                        <button 
                          onClick={() => onViewOrder(project._id)}
                          className="p-2.5 rounded-xl bg-indigo-50 text-indigo-600 hover:bg-indigo-600 hover:text-white transition-all shadow-sm"
                          title="Open Project Workspace"
                        >
                          <ExternalLink size={16} />
                        </button>
                      </div>
                    </div>
                  ))}

                  {selectedCustomerData.orders.length === 0 && (
                    <p className="text-center text-xs text-slate-400 italic py-8 border border-dashed border-slate-250 rounded-2xl">No active projects linked.</p>
                  )}
                </div>
              </div>
            </Card>
          ) : (
            <Card className="p-8 text-center text-slate-400 flex flex-col items-center justify-center min-h-[50vh] border-dashed border-slate-200">
              <div className="w-16 h-16 bg-slate-50 text-slate-300 rounded-2xl flex items-center justify-center mb-4">
                <User size={32} />
              </div>
              <p className="text-slate-900 font-black text-lg">Select a Customer Profile</p>
              <p className="text-xs mt-1 text-slate-400 font-semibold max-w-xs">Click on any client in the sidebar directory to load comprehensive CRM details, balances, and pipelines.</p>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};

export default CustomersModule;
