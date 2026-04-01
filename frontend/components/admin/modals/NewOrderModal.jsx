import React, { useState, useEffect, useMemo } from 'react';
import { X, Search, ShieldCheck, Briefcase, Zap, IndianRupee, UserPlus, UserCheck, Trash2 } from 'lucide-react';
import axios from 'axios';
import { MENU_DATA } from '../../SharedComponents';

const NewOrderModal = ({ isOpen, onClose, users, employees, token, onCreated }) => {
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [serviceSearchTerm, setServiceSearchTerm] = useState('');
  const [showUserResults, setShowUserResults] = useState(false);
  const [showServiceResults, setShowServiceResults] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [isRegisteringClient, setIsRegisteringClient] = useState(false);

  // Flatten all services from MENU_DATA for searching
  const allServices = useMemo(() => {
    const list = MENU_DATA.flatMap(cat => 
      cat.columns.flatMap(col => col.items)
    );
    // Add custom service option at the end
    return [...new Set(list)];
  }, []);

  const [formData, setFormData] = useState({
    userId: '',
    serviceName: '',
    packageName: 'Manual Entry',
    price: '',
    clientName: '',
    email: '',
    phone: ''
  });

  useEffect(() => {
    if (!isOpen) {
      // Reset state on close
      setSearchTerm('');
      setServiceSearchTerm('');
      setSelectedUser(null);
      setIsRegisteringClient(false);
      setFormData({
        userId: '',
        serviceName: '',
        packageName: 'Manual Entry',
        price: '',
        clientName: '',
        email: '',
        phone: ''
      });
    }
  }, [isOpen]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    const clientNameFinal = selectedUser ? selectedUser.name : formData.clientName;
    const emailFinal = selectedUser ? selectedUser.email : formData.email;
    const serviceFinal = formData.serviceName || serviceSearchTerm;

    if (!serviceFinal || !formData.price || (!selectedUser && !emailFinal)) {
      alert('Please fill at least Service, Price, and Customer details.');
      return;
    }

    setLoading(true);
    try {
      const config = { headers: { Authorization: `Bearer ${token}` } };
      let finalUserId = selectedUser?._id || '';

      // 1. If Registering as New Client, create the user first
      if (isRegisteringClient && !selectedUser) {
        try {
          const userRes = await axios.post('/api/auth/users', {
            name: formData.clientName,
            email: formData.email,
            phone: formData.phone,
            role: 'client'
          }, config);
          finalUserId = userRes.data.user._id;
        } catch (err) {
          alert('User creation failed: ' + (err.response?.data?.message || err.message));
          setLoading(false);
          return;
        }
      }

      // 2. Create the order
      const orderPayload = {
        ...formData,
        userId: finalUserId,
        serviceName: serviceFinal,
        clientName: clientNameFinal,
        email: emailFinal
      };

      await axios.post('/api/orders', orderPayload, config);
      onCreated();
      onClose();
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

  const filteredServices = allServices.filter(s => 
    s.toLowerCase().includes(serviceSearchTerm.toLowerCase())
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
              <Search size={14} /> Select Customer
            </label>
            
            {selectedUser ? (
              <div className="flex items-center justify-between p-4 bg-indigo-50 border border-indigo-100 rounded-2xl animate-fade-in">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-indigo-600 rounded-full flex items-center justify-center text-white">
                    <UserCheck size={20} />
                  </div>
                  <div>
                    <div className="font-bold text-slate-900">{selectedUser.name}</div>
                    <div className="text-xs text-slate-500">{selectedUser.email} | {selectedUser.phone}</div>
                  </div>
                </div>
                <button 
                  type="button" 
                  onClick={() => {
                    setSelectedUser(null);
                    setFormData({ ...formData, userId: '', clientName: '', email: '', phone: '' });
                  }}
                  className="p-2 text-red-500 hover:bg-red-50 rounded-lg transition-colors"
                >
                  <Trash2 size={18} />
                </button>
              </div>
            ) : (
              <div className="relative">
                <input 
                  type="text" 
                  placeholder="Search existing user by name, email or phone..."
                  className="w-full px-4 py-3 rounded-xl border border-slate-200 bg-slate-50 focus:bg-white focus:ring-2 focus:ring-indigo-500 transition-all outline-none"
                  value={searchTerm}
                  onFocus={() => setShowUserResults(true)}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
                {showUserResults && searchTerm.length > 0 && (
                  <div className="absolute top-full left-0 right-0 mt-2 bg-white border border-slate-200 rounded-xl shadow-xl z-50 max-h-48 overflow-y-auto">
                    {filteredUsers.length > 0 ? (
                      filteredUsers.map(user => (
                        <button
                          key={user._id}
                          type="button"
                          className="w-full text-left px-4 py-3 hover:bg-indigo-50 flex flex-col border-b border-slate-50 last:border-0"
                          onClick={() => {
                            setSelectedUser(user);
                            setFormData({ ...formData, userId: user._id, clientName: user.name, email: user.email, phone: user.phone });
                            setShowUserResults(false);
                            setSearchTerm('');
                          }}
                        >
                          <span className="font-bold text-slate-900">{user.name}</span>
                          <span className="text-xs text-slate-500">{user.email} | {user.phone}</span>
                        </button>
                      ))
                    ) : (
                      <div className="px-4 py-3 text-slate-500 text-sm italic">No users found. Enter details manually below.</div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>

          {!selectedUser && (
            <div className="space-y-4 pt-2 animate-fade-in">
              <div className="flex items-center justify-between">
                <label className="flex items-center gap-2 cursor-pointer group">
                  <input 
                    type="checkbox" 
                    className="w-4 h-4 rounded text-indigo-600 focus:ring-indigo-500"
                    checked={isRegisteringClient}
                    onChange={(e) => setIsRegisteringClient(e.target.checked)}
                  />
                  <span className="text-sm font-bold text-slate-700 flex items-center gap-1.5">
                    <UserPlus size={14} className="text-indigo-600" /> Register as New Client
                  </span>
                </label>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-xs font-bold text-slate-500 uppercase tracking-wider">Client Name</label>
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
                <div className="space-y-2">
                  <label className="text-xs font-bold text-slate-500 uppercase tracking-wider">Phone Number</label>
                  <input 
                    type="text"
                    className="w-full px-4 py-2.5 rounded-xl border border-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none"
                    value={formData.phone}
                    onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                    placeholder="e.g. 9876543210"
                  />
                </div>
              </div>
            </div>
          )}

          <hr className="border-slate-100" />

          {/* Service Details */}
          <div className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-bold text-slate-700 flex items-center gap-2">
                <Briefcase size={14} /> Service Name
              </label>
              <div className="relative">
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <input 
                      type="text" 
                      placeholder="Search or enter service name..."
                      className="w-full px-4 py-3 rounded-xl border border-slate-200 bg-white focus:ring-2 focus:ring-indigo-500 outline-none"
                      value={serviceSearchTerm}
                      onFocus={() => setShowServiceResults(true)}
                      onChange={(e) => {
                        setServiceSearchTerm(e.target.value);
                        setFormData({ ...formData, serviceName: e.target.value });
                      }}
                    />
                    {showServiceResults && serviceSearchTerm.length > 0 && (
                      <div className="absolute bottom-full left-0 right-0 mb-2 bg-white border border-slate-200 rounded-xl shadow-xl z-50 max-h-48 overflow-y-auto">
                        {filteredServices.length > 0 ? (
                          filteredServices.map(service => (
                            <button
                              key={service}
                              type="button"
                              className="w-full text-left px-4 py-3 hover:bg-slate-50 border-b border-slate-50 last:border-0"
                              onClick={() => {
                                setFormData({ ...formData, serviceName: service });
                                setServiceSearchTerm(service);
                                setShowServiceResults(false);
                              }}
                            >
                              <span className="text-sm font-medium text-slate-700">{service}</span>
                            </button>
                          ))
                        ) : (
                          <div className="px-4 py-3 text-slate-500 text-xs italic">Not in header list. Custom service will be used.</div>
                        )}
                      </div>
                    )}
                  </div>
                  <div className="w-1/3">
                    <input 
                      type="number"
                      className="w-full px-4 py-3 rounded-xl border border-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none font-bold"
                      value={formData.price}
                      onChange={(e) => setFormData({ ...formData, price: e.target.value })}
                      placeholder="Price (₹)"
                    />
                  </div>
                </div>
                <p className="text-[10px] text-slate-400 mt-1 font-medium italic">* You can select from suggested services or type a custom one.</p>
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
