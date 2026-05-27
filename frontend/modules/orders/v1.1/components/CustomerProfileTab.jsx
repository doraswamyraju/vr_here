import React, { useMemo } from 'react';
import { Mail, Phone, Calendar, Briefcase, IndianRupee, Clock, CheckCircle } from 'lucide-react';
import { rupees } from '../utils/helpers';

const CustomerProfileTab = ({ customerEmail, customerPhone, customerName, orders = [], onSwitchOrder }) => {
  // Find all orders linked to this customer via email or phone
  const customerOrders = useMemo(() => {
    return orders.filter(o => {
      const emailMatch = customerEmail && (o.email?.toLowerCase() === customerEmail.toLowerCase() || o.user?.email?.toLowerCase() === customerEmail.toLowerCase());
      const phoneMatch = customerPhone && (o.phone === customerPhone || o.user?.phone === customerPhone);
      const nameMatch = customerName && o.clientName?.toLowerCase() === customerName.toLowerCase();
      return emailMatch || phoneMatch || nameMatch;
    });
  }, [orders, customerEmail, customerPhone, customerName]);

  const stats = useMemo(() => {
    let totalProjects = customerOrders.length;
    let completedProjects = customerOrders.filter(o => o.status === 'Completed').length;
    let pendingProjects = totalProjects - completedProjects;
    let totalRevenue = customerOrders.reduce((sum, o) => sum + Number(o.price || 0), 0);
    let totalInvoices = customerOrders.reduce((sum, o) => sum + (o.invoices?.length || 0), 0);

    return { totalProjects, completedProjects, pendingProjects, totalRevenue, totalInvoices };
  }, [customerOrders]);

  return (
    <div className="space-y-6">
      {/* Customer Header Info Card */}
      <div className="rounded-2xl border border-white/70 bg-gradient-to-r from-slate-50 to-indigo-50/50 p-6 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <span className="text-[10px] font-black uppercase text-indigo-600 tracking-wider">Customer Profile</span>
            <h3 className="text-2xl font-black text-slate-800 mt-1">{customerName || 'Community Member'}</h3>
            <div className="flex flex-wrap gap-4 mt-2.5 text-xs text-slate-600 font-medium">
              {customerEmail && (
                <a href={`mailto:${customerEmail}`} className="flex items-center gap-1 hover:text-indigo-600 transition-colors">
                  <Mail size={14} className="text-indigo-500" /> {customerEmail}
                </a>
              )}
              {customerPhone && (
                <a href={`tel:${customerPhone}`} className="flex items-center gap-1 hover:text-indigo-600 transition-colors">
                  <Phone size={14} className="text-indigo-500" /> {customerPhone}
                </a>
              )}
            </div>
          </div>
          
          <div className="flex gap-3 text-center">
            <div className="bg-white border border-slate-100 rounded-xl px-4 py-2.5 shadow-sm">
              <p className="text-[9px] font-black uppercase text-slate-400">Lifetime Revenue</p>
              <p className="text-base font-black text-slate-800 mt-0.5">{rupees(stats.totalRevenue)}</p>
            </div>
            <div className="bg-white border border-slate-100 rounded-xl px-4 py-2.5 shadow-sm">
              <p className="text-[9px] font-black uppercase text-slate-400">Total Projects</p>
              <p className="text-base font-black text-indigo-600 mt-0.5">{stats.totalProjects}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Grid of Projects */}
      <div className="space-y-3">
        <h4 className="text-xs font-black uppercase text-slate-400 tracking-widest">Active & Historic Projects</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {customerOrders.map(project => (
            <div 
              key={project._id}
              onClick={() => onSwitchOrder(project._id)}
              className="rounded-2xl border border-slate-200/60 bg-white p-5 hover:border-indigo-500 hover:shadow-md cursor-pointer transition-all flex flex-col justify-between gap-4 group"
            >
              <div>
                <div className="flex items-start justify-between gap-3">
                  <h5 className="font-bold text-slate-800 group-hover:text-indigo-600 transition-colors">{project.serviceName}</h5>
                  <span className={`px-2 py-0.5 rounded-md text-[9px] font-black uppercase flex-shrink-0 ${
                    project.status === 'Completed' ? 'bg-emerald-50 text-emerald-700 border border-emerald-100' : 'bg-amber-50 text-amber-700 border border-amber-100'
                  }`}>
                    {project.status}
                  </span>
                </div>
                <p className="text-xs text-slate-500 mt-1 uppercase tracking-wider font-bold">{project.packageName}</p>
              </div>

              <div className="flex items-center justify-between border-t border-slate-50 pt-3 text-xs text-slate-600">
                <span className="font-black text-slate-800">{rupees(project.price)}</span>
                <span className="text-[10px] font-bold text-slate-400">Created: {new Date(project.createdAt).toLocaleDateString()}</span>
              </div>
            </div>
          ))}

          {customerOrders.length === 0 && (
            <p className="col-span-full py-8 text-center text-xs text-slate-400 italic bg-slate-50 rounded-2xl">No linked projects found for this client.</p>
          )}
        </div>
      </div>
    </div>
  );
};

export default CustomerProfileTab;
