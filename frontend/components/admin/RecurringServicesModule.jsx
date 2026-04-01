import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import { 
  RefreshCcw, 
  Plus, 
  Trash2, 
  Play, 
  Pause, 
  Calendar, 
  User as UserIcon, 
  Briefcase,
  AlertCircle,
  CheckCircle2,
  Clock
} from 'lucide-react';

const Card = ({ children, className = '' }) => (
  <div className={`rounded-2xl border border-white/70 bg-white/85 backdrop-blur-sm shadow-[0_10px_30px_rgba(15,23,42,0.08)] ${className}`}>
    {children}
  </div>
);

const RecurringServicesModule = ({ token }) => {
  const [subscriptions, setSubscriptions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const config = useMemo(() => ({
    headers: { Authorization: `Bearer ${token}` }
  }), [token]);

  const fetchSubscriptions = async () => {
    try {
      setLoading(true);
      const res = await axios.get('/api/recurring', config);
      setSubscriptions(res.data);
      setError(null);
    } catch (err) {
      setError('Failed to load recurring services.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSubscriptions();
  }, [token]);

  const toggleStatus = async (sub) => {
    try {
      await axios.put(`/api/recurring/${sub._id}`, { isActive: !sub.isActive }, config);
      fetchSubscriptions();
    } catch (err) {
      alert('Error updating status');
    }
  };

  const deleteSub = async (sub) => {
    if (!window.confirm(`Stop and Delete recurring service for ${sub.clientName}?`)) return;
    try {
      await axios.delete(`/api/recurring/${sub._id}`, config);
      fetchSubscriptions();
    } catch (err) {
      alert('Error deleting service');
    }
  };

  if (loading) return <div className="p-20 text-center text-slate-500 font-bold">Synchronizing Subscription data...</div>;

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center bg-white/50 p-4 rounded-3xl border border-white/70">
        <div>
          <h2 className="text-xl font-black text-slate-900">Recurring Management</h2>
          <p className="text-xs text-slate-500">Automated service generation and scheduling</p>
        </div>
        <div className="flex gap-2">
           <button 
             onClick={fetchSubscriptions}
             className="p-3 bg-white border border-slate-200 rounded-2xl text-slate-600 hover:bg-slate-50 transition-all"
           >
             <RefreshCcw size={18} />
           </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-rose-50 text-rose-600 rounded-2xl flex items-center gap-2 font-bold text-sm">
          <AlertCircle size={18} /> {error}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        {subscriptions.length === 0 ? (
          <Card className="col-span-full py-20 text-center">
            <div className="w-16 h-16 bg-slate-100 rounded-3xl mx-auto flex items-center justify-center mb-4 text-slate-400">
               <Calendar size={32} />
            </div>
            <h3 className="font-bold text-slate-800">No recurring services active</h3>
            <p className="text-sm text-slate-500">Enable "Set as Recurring" on any order to automate it.</p>
          </Card>
        ) : (
          subscriptions.map((sub) => (
            <Card key={sub._id} className="overflow-hidden group">
               <div className="p-5 flex flex-col sm:flex-row gap-5">
                  <div className={`p-4 rounded-2xl flex flex-col items-center justify-center min-w-[100px] ${sub.isActive ? 'bg-indigo-50 text-indigo-600' : 'bg-slate-100 text-slate-400'}`}>
                     <p className="text-[10px] font-black uppercase tracking-widest mb-1">{sub.frequency}</p>
                     <p className="text-2xl font-black">{sub.dayOfMonth}</p>
                     <p className="text-[10px] font-bold">Day of Month</p>
                  </div>

                  <div className="flex-1 space-y-3">
                     <div className="flex items-start justify-between">
                        <div>
                           <h4 className="font-black text-slate-900 text-lg leading-tight">{sub.serviceName}</h4>
                           <div className="flex items-center gap-2 mt-1">
                              <span className="text-[10px] font-bold bg-slate-100 px-2 py-0.5 rounded text-slate-500 uppercase">{sub.packageName}</span>
                              <span className="text-[10px] font-bold text-emerald-600">Rs. {sub.price?.toLocaleString()}</span>
                           </div>
                        </div>
                        <div className="flex gap-1.5 opacity-0 group-hover:opacity-100 transition-opacity">
                           <button 
                             onClick={() => toggleStatus(sub)}
                             className={`p-2 rounded-xl transition-all ${sub.isActive ? 'bg-amber-100 text-amber-600 hover:bg-amber-600 hover:text-white' : 'bg-emerald-100 text-emerald-600 hover:bg-emerald-600 hover:text-white'}`}
                             title={sub.isActive ? "Pause" : "Resume"}
                           >
                              {sub.isActive ? <Pause size={16} /> : <Play size={16} />}
                           </button>
                           <button 
                             onClick={() => deleteSub(sub)}
                             className="p-2 bg-rose-100 text-rose-600 rounded-xl hover:bg-rose-600 hover:text-white transition-all outline-none"
                             title="Remove"
                           >
                              <Trash2 size={16} />
                           </button>
                        </div>
                     </div>

                     <div className="grid grid-cols-2 gap-3 pb-2">
                        <div className="flex items-center gap-2">
                           <div className="p-1.5 bg-slate-100 rounded-lg text-slate-500"><UserIcon size={12} /></div>
                           <p className="text-[11px] font-bold text-slate-600 truncate">{sub.user?.name || sub.clientName}</p>
                        </div>
                        <div className="flex items-center gap-2">
                           <div className="p-1.5 bg-slate-100 rounded-lg text-slate-500"><Clock size={12} /></div>
                           <p className="text-[11px] font-bold text-slate-600">Next: {new Date(sub.nextRunDate).toLocaleDateString()}</p>
                        </div>
                     </div>

                     <div className="pt-3 border-t border-slate-100 flex items-center justify-between">
                        <div className="flex -space-x-2">
                           {sub.assignedEmployee && (
                              <div title={sub.assignedEmployee.name} className="w-6 h-6 rounded-full bg-indigo-500 border-2 border-white flex items-center justify-center text-[8px] text-white font-bold">
                                {sub.assignedEmployee.name.charAt(0)}
                              </div>
                           )}
                           {sub.assignedMaker && (
                              <div title={`Maker: ${sub.assignedMaker.name}`} className="w-6 h-6 rounded-full bg-emerald-500 border-2 border-white flex items-center justify-center text-[8px] text-white font-bold">
                                {sub.assignedMaker.name.charAt(0)}
                              </div>
                           )}
                           {sub.assignedChecker && (
                              <div title={`Checker: ${sub.assignedChecker.name}`} className="w-6 h-6 rounded-full bg-amber-500 border-2 border-white flex items-center justify-center text-[8px] text-white font-bold">
                                {sub.assignedChecker.name.charAt(0)}
                              </div>
                           )}
                        </div>
                        <div className="flex items-center gap-1.5">
                           <div className={`w-2 h-2 rounded-full ${sub.isActive ? 'bg-emerald-500 animate-pulse' : 'bg-slate-300'}`}></div>
                           <span className="text-[10px] font-black uppercase tracking-tighter text-slate-400">
                             {sub.isActive ? 'Autopilot Active' : 'Operation Paused'}
                           </span>
                        </div>
                     </div>
                  </div>
               </div>
            </Card>
          ))
        )}
      </div>
    </div>
  );
};

export default RecurringServicesModule;
