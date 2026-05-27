import React, { useState, useMemo } from 'react';
import { Search, User, Mail, Phone, ExternalLink, IndianRupee, Layers } from 'lucide-react';
import { rupees } from '../../../modules/orders/v1.1/utils/helpers';

const Card = ({ children, className = '' }) => (
  <div className={`rounded-2xl border border-white/70 bg-white/80 backdrop-blur-md shadow-[0_10px_30px_rgba(15,23,42,0.04)] ${className}`}>
    {children}
  </div>
);

const CustomersModule = ({ users = [], orders = [], onViewOrder }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCustomerId, setSelectedCustomerId] = useState(null);

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
      
      analytics[c._id] = {
        orders: clientOrders,
        totalRevenue,
        activeCount
      };
    });
    return analytics;
  }, [customers, orders]);

  const selectedCustomer = useMemo(() => {
    return customers.find(c => c._id === selectedCustomerId) || null;
  }, [customers, selectedCustomerId]);

  const selectedCustomerData = useMemo(() => {
    if (!selectedCustomerId) return null;
    return customerAnalytics[selectedCustomerId] || { orders: [], totalRevenue: 0, activeCount: 0 };
  }, [selectedCustomerId, customerAnalytics]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-black text-slate-800">Customer Directory</h2>
          <p className="text-sm text-slate-500">Track client projects, billing statements, and outstanding balances.</p>
        </div>

        <div className="relative w-full max-w-md">
          <input 
            type="text"
            placeholder="Search by name, email, or phone..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 bg-white border border-slate-200 rounded-xl text-sm focus:ring-2 focus:ring-indigo-500/20 outline-none"
          />
          <Search className="absolute left-3.5 top-3.5 text-slate-400" size={16} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Customers List */}
        <div className="lg:col-span-1 space-y-3 max-h-[70vh] overflow-y-auto pr-1">
          {filteredCustomers.map(customer => {
            const data = customerAnalytics[customer._id] || { orders: [], totalRevenue: 0, activeCount: 0 };
            const isActive = selectedCustomerId === customer._id;

            return (
              <div 
                key={customer._id}
                onClick={() => setSelectedCustomerId(customer._id)}
                className={`p-4 rounded-2xl border cursor-pointer transition-all ${
                  isActive 
                    ? 'bg-indigo-600 text-white border-indigo-600 shadow-lg shadow-indigo-100' 
                    : 'bg-white border-slate-100 hover:border-indigo-500'
                }`}
              >
                <div className="flex items-start gap-3">
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center text-xs font-black ${
                    isActive ? 'bg-white/15 text-white' : 'bg-indigo-50 text-indigo-600'
                  }`}>
                    {customer.name?.charAt(0).toUpperCase() || 'C'}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className={`text-sm font-black truncate ${isActive ? 'text-white' : 'text-slate-800'}`}>
                      {customer.name}
                    </p>
                    <p className={`text-xs mt-0.5 truncate ${isActive ? 'text-indigo-200' : 'text-slate-400'}`}>
                      {customer.email}
                    </p>
                  </div>
                </div>

                <div className="flex items-center justify-between border-t border-white/10 mt-3 pt-3 text-[10px] uppercase font-black tracking-wider">
                  <span className={isActive ? 'text-indigo-200' : 'text-slate-400'}>
                    {data.orders.length} Projects
                  </span>
                  <span className={isActive ? 'text-white' : 'text-slate-800'}>
                    {rupees(data.totalRevenue)}
                  </span>
                </div>
              </div>
            );
          })}

          {filteredCustomers.length === 0 && (
            <p className="text-center text-xs text-slate-400 italic py-8">No customers matching query.</p>
          )}
        </div>

        {/* Right Column: Customer Details Card */}
        <div className="lg:col-span-2">
          {selectedCustomer ? (
            <Card className="p-6 space-y-6">
              <div className="border-b border-slate-100 pb-5">
                <span className="text-[10px] font-black uppercase text-indigo-600 tracking-wider">Customer Overview</span>
                <h3 className="text-2xl font-black text-slate-800 mt-1">{selectedCustomer.name}</h3>
                
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-4 text-xs font-semibold text-slate-600">
                  <div className="flex items-center gap-2">
                    <Mail size={14} className="text-indigo-500" /> {selectedCustomer.email}
                  </div>
                  {selectedCustomer.phone && (
                    <div className="flex items-center gap-2">
                      <Phone size={14} className="text-indigo-500" /> {selectedCustomer.phone}
                    </div>
                  )}
                </div>
              </div>

              {/* Stats Cards */}
              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 rounded-xl border border-slate-100 bg-slate-50/50">
                  <p className="text-[9px] font-black uppercase text-slate-400">Total Value</p>
                  <p className="text-lg font-black text-slate-800 mt-0.5">{rupees(selectedCustomerData.totalRevenue)}</p>
                </div>
                <div className="p-4 rounded-xl border border-slate-100 bg-slate-50/50">
                  <p className="text-[9px] font-black uppercase text-slate-400">Active Pipelines</p>
                  <p className="text-lg font-black text-indigo-600 mt-0.5">{selectedCustomerData.activeCount} Active</p>
                </div>
              </div>

              {/* Projects List */}
              <div className="space-y-3">
                <h4 className="text-xs font-black uppercase text-slate-400 tracking-widest flex items-center gap-1.5">
                  <Layers size={14} /> Linked Projects & Subscriptions
                </h4>

                <div className="space-y-3 max-h-[350px] overflow-y-auto pr-1">
                  {selectedCustomerData.orders.map(project => (
                    <div 
                      key={project._id}
                      className="p-4 rounded-xl border border-slate-100 bg-white flex items-center justify-between hover:border-indigo-300 transition-colors"
                    >
                      <div>
                        <p className="text-sm font-bold text-slate-800">{project.serviceName}</p>
                        <p className="text-[10px] text-slate-500 font-bold uppercase mt-0.5">{project.packageName}</p>
                      </div>

                      <div className="flex items-center gap-4">
                        <div className="text-right">
                          <p className="text-xs font-black text-slate-900">{rupees(project.price)}</p>
                          <span className={`px-1.5 py-0.5 rounded text-[8px] font-black uppercase ${
                            project.status === 'Completed' ? 'bg-emerald-50 text-emerald-700' : 'bg-amber-50 text-amber-700'
                          }`}>
                            {project.status}
                          </span>
                        </div>
                        <button 
                          onClick={() => onViewOrder(project._id)}
                          className="p-2 rounded-lg bg-indigo-50 text-indigo-600 hover:bg-indigo-600 hover:text-white transition-colors"
                          title="Open Project Workspace"
                        >
                          <ExternalLink size={14} />
                        </button>
                      </div>
                    </div>
                  ))}

                  {selectedCustomerData.orders.length === 0 && (
                    <p className="text-center text-xs text-slate-400 italic py-4">No active projects linked.</p>
                  )}
                </div>
              </div>
            </Card>
          ) : (
            <Card className="p-8 text-center text-slate-400 flex flex-col items-center justify-center min-h-[40vh]">
              <User size={48} className="text-slate-200 mb-3" />
              <p className="text-sm font-bold">Select a Customer</p>
              <p className="text-xs mt-1 text-slate-400">Click on any client in the sidebar directory to load details.</p>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};

export default CustomersModule;
