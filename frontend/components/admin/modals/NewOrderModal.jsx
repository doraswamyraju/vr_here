import React, { useState, useEffect } from 'react';
import { X, Search, ShieldCheck, Briefcase, Zap, IndianRupee } from 'lucide-react';
import axios from 'axios';

const NewOrderModal = ({ isOpen, onClose, users, employees, token, onCreated }) => {
  const [loading, setLoading] = useState(false);
  const [servicesData, setServicesData] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  
  const [formData, setFormData] = useState({
    userId: '',
    serviceName: '',
    packageName: 'Manual Entry',
    price: '',
    assignedEmployee: '',
    clientName: '',
    email: '',
    phone: ''
  });

  useEffect(() => {
    if (isOpen) {
      fetchServices();
    }
  }, [isOpen]);

  const fetchServices = async () => {
    try {
      const { data } = await axios.get('/api/services');
      setServicesData(data.services || []);
    } catch (error) {
      console.error('Error fetching services:', error);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!formData.serviceName || !formData.price || (!formData.userId && !formData.email)) {
      alert('Please fill at least Service, Price, and Customer (User or Email).');
      return;
    }

    setLoading(true);
    try {
      const config = { headers: { Authorization: `Bearer ${token}` } };
      await axios.post('/api/orders', formData, config);
      onCreated();
      onClose();
      setFormData({
        userId: '',
        serviceName: '',
        packageName: 'Manual Entry',
        price: '',
        assignedEmployee: '',
        clientName: '',
        email: '',
        phone: ''
      });
    } catch (error) {
      alert(error.response?.data?.message || 'Error creating order');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  const filteredUsers = users.filter(u => 
    u.name?.toLowerCase().includes(searchTerm.toLowerCase()) || 
    u.email?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    u.phone?.includes(searchTerm)
  );

  return (
    <div className="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm">
      <div className="bg-white rounded-3xl w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col shadow-2xl border border-slate-200">
        <div className="p-6 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
          <div>
            <h2 className="text-2xl font-black text-slate-900">Manual Order Placement</h2>
            <p className="text-slate-500 text-sm">Create a new order record directly in the system.</p>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-slate-200 rounded-full transition-colors">
            <X size={20} className="text-slate-500" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 overflow-y-auto flex-1 space-y-6">
          {/* Customer Selection */}
          <div className="space-y-3">
            <label className="text-sm font-bold text-slate-700 flex items-center gap-2">
              <Search size={14} /> Select Customer (Existing User)
            </label>
            <div className="relative">
              <input 
                type="text" 
                placeholder="Search user by name, email or phone..."
                className="w-full px-4 py-3 rounded-xl border border-slate-200 bg-slate-50 focus:bg-white focus:ring-2 focus:ring-indigo-500 transition-all outline-none"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
              {searchTerm && (
                <div className="absolute top-full left-0 right-0 mt-2 bg-white border border-slate-200 rounded-xl shadow-xl z-50 max-h-48 overflow-y-auto">
                  {filteredUsers.length > 0 ? (
                    filteredUsers.map(user => (
                      <button
                        key={user._id}
                        type="button"
                        className="w-full text-left px-4 py-3 hover:bg-indigo-50 flex flex-col border-b border-slate-50 last:border-0"
                        onClick={() => {
                          setFormData({ ...formData, userId: user._id, clientName: user.name, email: user.email, phone: user.phone });
                          setSearchTerm(user.name);
                        }}
                      >
                        <span className="font-bold text-slate-900">{user.name}</span>
                        <span className="text-xs text-slate-500">{user.email} | {user.phone}</span>
                      </button>
                    ))
                  ) : (
                    <div className="px-4 py-3 text-slate-500 text-sm italic">No users found. You can enter details manually below.</div>
                  )}
                </div>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-xs font-bold text-slate-500 uppercase tracking-wider">Client Name (Manual)</label>
              <input 
                className="w-full px-4 py-2.5 rounded-xl border border-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none"
                value={formData.clientName}
                onChange={(e) => setFormData({ ...formData, clientName: e.target.value })}
                placeholder="Enter client name"
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs font-bold text-slate-500 uppercase tracking-wider">Email Address</label>
              <input 
                type="email"
                className="w-full px-4 py-2.5 rounded-xl border border-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                placeholder="client@example.com"
              />
            </div>
          </div>

          <hr className="border-slate-100" />

          {/* Service Details */}
          <div className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-bold text-slate-700 flex items-center gap-2">
                <Briefcase size={14} /> Service Category & Service Name
              </label>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <select 
                  className="px-4 py-3 rounded-xl border border-slate-200 bg-slate-50 outline-none"
                  onChange={(e) => setFormData({ ...formData, serviceName: e.target.value })}
                  value={formData.serviceName}
                >
                  <option value="">Select a Service</option>
                  {servicesData.map(cat => (
                    <optgroup key={cat.id} label={cat.title}>
                      {cat.columns.map(col => (
                        col.items.map(item => (
                          <option key={item} value={item}>{item}</option>
                        ))
                      ))}
                    </optgroup>
                  ))}
                  <option value="Custom Service">Other / Custom Service</option>
                </select>

                <input 
                  className="px-4 py-3 rounded-xl border border-slate-200 bg-white outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="Service Name (if other)"
                  value={formData.serviceName === 'Custom Service' ? '' : formData.serviceName}
                  onChange={(e) => setFormData({ ...formData, serviceName: e.target.value })}
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-xs font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1">
                  <IndianRupee size={12} /> Total Price (Manual)
                </label>
                <input 
                  type="number"
                  className="w-full px-4 py-2.5 rounded-xl border border-slate-200 focus:ring-2 focus:ring-indigo-500 underline underline-offset-4 decoration-indigo-200"
                  value={formData.price}
                  onChange={(e) => setFormData({ ...formData, price: e.target.value })}
                  placeholder="e.g. 5000"
                />
              </div>
              <div className="space-y-2">
                <label className="text-xs font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1">
                  <ShieldCheck size={12} /> Assign To Employee
                </label>
                <select 
                  className="w-full px-4 py-2.5 rounded-xl border border-slate-200 outline-none bg-slate-50"
                  value={formData.assignedEmployee}
                  onChange={(e) => setFormData({ ...formData, assignedEmployee: e.target.value })}
                >
                  <option value="">Do not assign yet</option>
                  {employees.map(emp => (
                    <option key={emp._id} value={emp._id}>{emp.name} ({emp.role})</option>
                  ))}
                </select>
              </div>
            </div>
          </div>
        </form>

        <div className="p-6 border-t border-slate-100 bg-slate-50/50 flex justify-end gap-3">
          <button 
            type="button"
            onClick={onClose}
            className="px-6 py-3 rounded-xl font-bold text-slate-600 hover:bg-slate-200 transition-colors"
          >
            Cancel
          </button>
          <button 
            type="button"
            onClick={handleSubmit}
            disabled={loading}
            className="px-8 py-3 rounded-xl font-bold bg-indigo-600 text-white shadow-xl shadow-indigo-200 hover:bg-indigo-700 disabled:bg-indigo-400 disabled:cursor-not-allowed transition-all flex items-center gap-2"
          >
            {loading ? 'Creating...' : (
              <>
                <Zap size={18} fill="currentColor" /> Create Order
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default NewOrderModal;
