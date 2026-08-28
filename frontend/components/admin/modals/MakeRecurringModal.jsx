import React, { useState, useEffect } from 'react';
import { X, RefreshCcw, Calendar, User as UsersIcon, Zap, CheckCircle2 } from 'lucide-react';
import axios from 'axios';

const MakeRecurringModal = ({ isOpen, onClose, order: orderProp, selectedOrder, token, onCreated, onSuccess }) => {
  const targetOrder = orderProp || selectedOrder;
  const callback = onCreated || onSuccess || (() => {});
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    frequency: 'Monthly',
    dayOfMonth: 1,
    dayOfWeek: 1,
    startDate: new Date().toISOString().split('T')[0],
    assignedEmployee: '',
    assignedMaker: '',
    assignedChecker: ''
  });

  useEffect(() => {
    if (targetOrder) {
      setFormData((prev) => ({
        ...prev,
        assignedEmployee: targetOrder.assignedEmployee?._id || targetOrder.assignedEmployee || '',
        assignedMaker: targetOrder.assignedMaker?._id || targetOrder.assignedMaker || '',
        assignedChecker: targetOrder.assignedChecker?._id || targetOrder.assignedChecker || ''
      }));
    }
  }, [targetOrder]);

  if (!isOpen || !targetOrder) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const config = { headers: { Authorization: `Bearer ${token}` } };
      
      const payload = {
        userId: targetOrder.user?._id || targetOrder.user,
        clientName: targetOrder.clientName,
        serviceName: targetOrder.serviceName,
        packageName: targetOrder.packageName,
        price: targetOrder.price,
        frequency: formData.frequency,
        dayOfMonth: Number(formData.dayOfMonth),
        dayOfWeek: Number(formData.dayOfWeek),
        startDate: formData.startDate,
        assignedEmployee: formData.assignedEmployee || null,
        assignedMaker: formData.assignedMaker || null,
        assignedChecker: formData.assignedChecker || null,
        // Clone current order structure as template
        tasksTemplate: targetOrder.tasks || [],
        requirementsTemplate: targetOrder.customerRequirements || [],
        checklistsTemplate: targetOrder.checklists || []
      };

      await axios.post('/api/recurring', payload, config);
      alert('Recurring service successfully scheduled!');
      callback();
      onClose();
    } catch (err) {
      alert(err.response?.data?.message || 'Error creating recurring service');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[120] flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm">
      <div className="bg-white rounded-3xl w-full max-w-xl shadow-2xl border border-slate-200 overflow-hidden flex flex-col">
        <div className="p-6 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
          <div>
            <h2 className="text-xl font-black text-slate-900 flex items-center gap-2">
              <RefreshCcw size={20} className="text-indigo-600" /> Automate Service
            </h2>
            <p className="text-slate-500 text-xs">Convert this order into a recurring monthly/yearly cycle.</p>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-slate-200 rounded-full transition-colors">
            <X size={20} className="text-slate-500" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-5">
           <div className="p-4 bg-indigo-50 rounded-2xl border border-indigo-100">
              <p className="text-[10px] font-black uppercase tracking-widest text-indigo-500 mb-1">Service to Automate</p>
              <p className="font-bold text-slate-800">{targetOrder.serviceName}</p>
              <p className="text-xs text-slate-500">{targetOrder.clientName}</p>
           </div>

           <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                 <label className="text-xs font-bold text-slate-500 uppercase flex items-center gap-1.5">
                    <Calendar size={12} /> Frequency
                 </label>
                 <select 
                   value={formData.frequency}
                   onChange={(e) => setFormData({...formData, frequency: e.target.value})}
                   className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold focus:ring-2 focus:ring-indigo-500 outline-none"
                 >
                    <option value="Weekly">Weekly</option>
                    <option value="Monthly">Monthly</option>
                    <option value="Quarterly">Quarterly</option>
                    <option value="Half-Yearly">Half-Yearly</option>
                    <option value="Yearly">Yearly</option>
                 </select>
              </div>

              {formData.frequency === 'Weekly' ? (
                <div className="space-y-1.5">
                   <label className="text-xs font-bold text-slate-500 uppercase">Day of Week</label>
                   <select 
                     value={formData.dayOfWeek}
                     onChange={(e) => setFormData({...formData, dayOfWeek: e.target.value})}
                     className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold focus:ring-2 focus:ring-indigo-500 outline-none"
                   >
                      <option value={1}>Monday</option>
                      <option value={2}>Tuesday</option>
                      <option value={3}>Wednesday</option>
                      <option value={4}>Thursday</option>
                      <option value={5}>Friday</option>
                      <option value={6}>Saturday</option>
                      <option value={0}>Sunday</option>
                   </select>
                </div>
              ) : (
                <div className="space-y-1.5">
                   <label className="text-xs font-bold text-slate-500 uppercase">Day of Month</label>
                   <input 
                     type="number"
                     min="1"
                     max="31"
                     value={formData.dayOfMonth}
                     onChange={(e) => setFormData({...formData, dayOfMonth: e.target.value})}
                     className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold focus:ring-2 focus:ring-indigo-500 outline-none"
                   />
                </div>
              )}
           </div>

           <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-500 uppercase flex items-center gap-1.5">
                 <UsersIcon size={12} /> Confirm Assignments
              </label>
              <div className="p-3 border border-slate-100 rounded-2xl space-y-2 bg-slate-50/30">
                 <div className="flex justify-between text-xs">
                    <span className="text-slate-500 font-bold">Maker:</span>
                    <span className="text-slate-800 font-black">{targetOrder.assignedMaker?.name || 'Inherited'}</span>
                 </div>
                 <div className="flex justify-between text-xs">
                    <span className="text-slate-500 font-bold">Checker:</span>
                    <span className="text-slate-800 font-black">{targetOrder.assignedChecker?.name || 'Inherited'}</span>
                 </div>
              </div>
              <p className="text-[10px] text-slate-400 italic mt-1">
                * All tasks and checklists from this order will be cloned exactly.
              </p>
           </div>

           <div className="pt-4 flex gap-3">
              <button 
                type="button"
                onClick={onClose}
                className="flex-1 px-4 py-3 rounded-2xl font-bold text-slate-500 hover:bg-slate-100 transition-colors"
              >
                Not Now
              </button>
              <button 
                type="submit"
                disabled={loading}
                className="flex-[2] px-6 py-3 bg-indigo-600 text-white rounded-2xl font-black shadow-xl shadow-indigo-100 hover:bg-slate-900 transition-all flex items-center justify-center gap-2"
              >
                {loading ? 'Scheduling...' : <><Zap size={18} fill="currentColor" /> Set as Recurring</>}
              </button>
           </div>
        </form>
      </div>
    </div>
  );
};

export default MakeRecurringModal;
