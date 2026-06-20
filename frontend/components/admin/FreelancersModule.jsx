import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    Users, Search, RefreshCcw, CheckCircle2, 
    AlertCircle, ArrowUpRight, Briefcase, 
    ShieldCheck, Phone, Mail, X, FileText, 
    Clock, DollarSign, Landmark, Check, Trash2, Edit, Eye
} from 'lucide-react';

const FreelancersModule = ({ token, orders = [], employees = [] }) => {
    const [freelancers, setFreelancers] = useState([]);
    const [payouts, setPayouts] = useState([]);
    const [liveAttendance, setLiveAttendance] = useState([]);
    const [loading, setLoading] = useState(true);
    const [activeSubTab, setActiveSubTab] = useState('Registrations'); // Registrations | Payouts | LiveAttendance
    const [searchTerm, setSearchTerm] = useState('');
    const [error, setError] = useState('');
    const [successMsg, setSuccessMsg] = useState('');
    const [processingPayout, setProcessingPayout] = useState(null);
    const [payoutForm, setPayoutForm] = useState({
        method: 'NEFT',
        transactionRef: '',
        notes: ''
    });

    // Detail/Edit Modal States
    const [selectedFreelancer, setSelectedFreelancer] = useState(null);
    const [editMode, setEditMode] = useState(false);
    
    // Freelancer detailed workspace states
    const [selectedFreelancerForWorkspace, setSelectedFreelancerForWorkspace] = useState(null);
    const [selectedOrderId, setSelectedOrderId] = useState(null);
    const [orderDetailTab, setOrderDetailTab] = useState('Overview');
    const [orderTodos, setOrderTodos] = useState([]);
    const [orderHistory, setOrderHistory] = useState([]);
    const [orderPayments, setOrderPayments] = useState([]);
    const [isLoadingOrderData, setIsLoadingOrderData] = useState(false);

    const config = {
        headers: { Authorization: `Bearer ${token}` }
    };

    const fetchOrderData = async (orderId) => {
        if (!config || !orderId) return;
        setIsLoadingOrderData(true);
        try {
            const [todosRes, historyRes, paymentsRes] = await Promise.all([
                axios.get(`/api/todos?orderId=${orderId}`, config),
                axios.get(`/api/orders/${orderId}/history`, config),
                axios.get(`/api/payments?orderId=${orderId}`, config)
            ]);
            setOrderTodos(todosRes.data || []);
            setOrderHistory(historyRes.data || []);
            setOrderPayments(paymentsRes.data || []);
        } catch (err) {
            console.error('Error fetching order specific details:', err);
        } finally {
            setIsLoadingOrderData(false);
        }
    };

    useEffect(() => {
        if (selectedOrderId) {
            fetchOrderData(selectedOrderId);
        }
    }, [selectedOrderId]);

    const [editForm, setEditForm] = useState({
        name: '',
        email: '',
        phone: '',
        skills: '',
        yearsOfExperience: 0,
        panCard: '',
        resumeUrl: '',
        bankDetails: {
            bankName: '',
            accountNumber: '',
            ifscCode: '',
            accountName: ''
        },
        isActive: false
    });

    useEffect(() => {
        if (token) {
            fetchData();
        }
    }, [token, activeSubTab]);

    const fetchData = async () => {
        setLoading(true);
        setError('');
        try {
            if (activeSubTab === 'Registrations') {
                const { data } = await axios.get('/api/freelancer/admin/users', config);
                setFreelancers(data);
            } else if (activeSubTab === 'Payouts') {
                const { data } = await axios.get('/api/freelancer/admin/payouts', config);
                setPayouts(data);
            } else if (activeSubTab === 'LiveAttendance') {
                const { data } = await axios.get('/api/freelancer/admin/live-attendance', config);
                setLiveAttendance(data);
            }
        } catch (err) {
            setError('Failed to fetch data from server');
        } finally {
            setLoading(false);
        }
    };

    const handleApproveFreelancer = async (userId) => {
        try {
            setError('');
            await axios.put(`/api/freelancer/admin/approve-user/${userId}`, {}, config);
            setSuccessMsg('Freelancer account approved successfully!');
            fetchData();
            setTimeout(() => setSuccessMsg(''), 3000);
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to approve freelancer');
        }
    };

    const handleDeleteFreelancer = async (userId) => {
        if (!window.confirm('Are you sure you want to permanently delete this freelancer? This action cannot be undone.')) return;
        try {
            setError('');
            await axios.delete(`/api/freelancer/admin/users/${userId}`, config);
            setSuccessMsg('Freelancer deleted successfully!');
            fetchData();
            setTimeout(() => setSuccessMsg(''), 3000);
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to delete freelancer');
        }
    };

    const handleApproveProfileUpdate = async (userId) => {
        try {
            setError('');
            await axios.put(`/api/freelancer/admin/approve-profile-update/${userId}`, {}, config);
            setSuccessMsg('Freelancer profile update approved successfully!');
            setSelectedFreelancer(null);
            fetchData();
            setTimeout(() => setSuccessMsg(''), 3000);
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to approve profile update');
        }
    };

    const handleRejectProfileUpdate = async (userId) => {
        try {
            setError('');
            await axios.put(`/api/freelancer/admin/reject-profile-update/${userId}`, {}, config);
            setSuccessMsg('Freelancer profile update rejected successfully!');
            setSelectedFreelancer(null);
            fetchData();
            setTimeout(() => setSuccessMsg(''), 3000);
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to reject profile update');
        }
    };

    const handleEditSubmit = async (e) => {
        e.preventDefault();
        try {
            setError('');
            const payload = {
                ...editForm,
                skills: typeof editForm.skills === 'string' 
                    ? editForm.skills.split(',').map(s => s.trim()).filter(Boolean) 
                    : editForm.skills
            };
            await axios.put(`/api/freelancer/admin/users/${selectedFreelancer._id}`, payload, config);
            setSuccessMsg('Freelancer profile updated successfully!');
            setSelectedFreelancer(null);
            fetchData();
            setTimeout(() => setSuccessMsg(''), 3000);
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to update freelancer');
        }
    };

    const handleProcessPaymentSubmit = async (e) => {
        e.preventDefault();
        try {
            setError('');
            await axios.put(`/api/freelancer/admin/pay/${processingPayout._id}`, payoutForm, config);
            setSuccessMsg('Payout logged successfully!');
            setProcessingPayout(null);
            setPayoutForm({ method: 'NEFT', transactionRef: '', notes: '' });
            fetchData();
            setTimeout(() => setSuccessMsg(''), 3000);
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to process payout');
        }
    };

    const openEditModal = (freelancer) => {
        setSelectedFreelancer(freelancer);
        setEditMode(true);
        setEditForm({
            name: freelancer.name || '',
            email: freelancer.email || '',
            phone: freelancer.phone || '',
            skills: Array.isArray(freelancer.skills) ? freelancer.skills.join(', ') : '',
            yearsOfExperience: freelancer.yearsOfExperience || 0,
            panCard: freelancer.panCard || '',
            resumeUrl: freelancer.resumeUrl || '',
            bankDetails: {
                bankName: freelancer.bankDetails?.bankName || '',
                accountNumber: freelancer.bankDetails?.accountNumber || '',
                ifscCode: freelancer.bankDetails?.ifscCode || '',
                accountName: freelancer.bankDetails?.accountName || ''
            },
            isActive: freelancer.isActive || false
        });
    };

    const formatCurrency = (amount) => {
        return new Intl.NumberFormat('en-IN', {
            style: 'currency',
            currency: 'INR',
            maximumFractionDigits: 0
        }).format(amount);
    };

    const filteredFreelancers = freelancers.filter(f => 
        f.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.phone?.includes(searchTerm)
    );

    const renderFreelancerWorkspace = () => {
        const fl = selectedFreelancerForWorkspace;
        const flOrders = orders.filter(o => (o.assignedFreelancer?._id || o.assignedFreelancer) === fl._id);
        const selectedOrder = flOrders.find(o => o._id === selectedOrderId) || null;
        const flPayouts = payouts.filter(p => (p.freelancer?._id || p.freelancer) === fl._id);

        return (
            <div className="space-y-6 animate-in fade-in duration-300">
                {/* Header card with freelancer summary */}
                <div className="bg-slate-900 text-white rounded-[32px] p-6 md:p-8 shadow-xl border border-slate-800">
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                        <div>
                            <span className="bg-red-500/20 text-red-400 px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-widest border border-red-500/30">Freelancer Profile Workspace</span>
                            <h2 className="text-3xl font-black mt-3 text-white tracking-tight">{fl.name}</h2>
                            <p className="text-slate-400 mt-1 font-semibold text-xs">{fl.phone} | {fl.email}</p>
                            <div className="flex flex-wrap gap-1 mt-3">
                                {fl.skills?.map((s, idx) => (
                                    <span key={idx} className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded-full text-[9px] font-black uppercase tracking-wider">{s}</span>
                                ))}
                            </div>
                        </div>
                        <button 
                            onClick={() => setSelectedFreelancerForWorkspace(null)}
                            className="px-6 py-3 bg-white text-slate-900 rounded-2xl text-xs font-black shadow-lg hover:bg-slate-100 transition active:scale-[0.98]"
                        >
                            Back to Freelancers List
                        </button>
                    </div>
                    
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 pt-6 border-t border-slate-800 text-xs">
                        <div>
                            <p className="text-slate-400 uppercase font-black tracking-widest text-[9px]">Experience</p>
                            <p className="font-bold text-sm text-white mt-0.5">{fl.yearsOfExperience} Years</p>
                        </div>
                        <div>
                            <p className="text-slate-400 uppercase font-black tracking-widest text-[9px]">PAN Card</p>
                            <p className="font-bold text-sm text-white mt-0.5">{fl.panCard || 'N/A'}</p>
                        </div>
                        <div>
                            <p className="text-slate-400 uppercase font-black tracking-widest text-[9px]">Bank Account</p>
                            <p className="font-bold text-white mt-0.5 truncate">{fl.bankDetails?.bankName || 'N/A'}</p>
                            <p className="text-[10px] text-slate-500 mt-0.5 truncate">A/C: {fl.bankDetails?.accountNumber}</p>
                        </div>
                        <div>
                            <p className="text-slate-400 uppercase font-black tracking-widest text-[9px]">Total Assignments</p>
                            <p className="font-bold text-sm text-white mt-0.5">{flOrders.length} Projects</p>
                        </div>
                    </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 items-start">
                    {/* Left Column: Projects List */}
                    <div className="lg:col-span-1 space-y-4">
                        <div className="bg-white rounded-[32px] p-4 border border-slate-100 shadow-sm space-y-3">
                            <h3 className="text-xs font-black text-slate-900 uppercase tracking-widest border-b pb-2">Assigned Projects</h3>
                            <div className="space-y-2">
                                {flOrders.map((o) => (
                                    <div 
                                        key={o._id}
                                        onClick={() => {
                                            setSelectedOrderId(o._id);
                                            setOrderDetailTab('Overview');
                                        }}
                                        className={`p-3.5 rounded-2xl border cursor-pointer transition-all text-xs ${selectedOrderId === o._id ? 'bg-slate-900 border-slate-900 text-white shadow-md' : 'bg-slate-50 hover:bg-slate-100 border-slate-100 text-slate-700'}`}
                                    >
                                        <div className="flex justify-between items-center mb-1">
                                            <span className={`px-1.5 py-0.5 rounded text-[8px] font-black uppercase ${selectedOrderId === o._id ? 'bg-white/10 text-white' : 'bg-red-50 text-red-650'}`}>{o.status}</span>
                                            <span className="font-bold">₹{o.freelancerPayout || 0}</span>
                                        </div>
                                        <p className="font-black truncate">{o.packageName}</p>
                                        <p className={`text-[10px] truncate ${selectedOrderId === o._id ? 'text-slate-400' : 'text-slate-450'}`}>{o.serviceName}</p>
                                    </div>
                                ))}
                                {flOrders.length === 0 && (
                                    <p className="text-center text-xs text-slate-400 italic py-4">No projects assigned.</p>
                                )}
                            </div>
                        </div>

                        {/* Freelancer-level Transactions Summary */}
                        <div className="bg-white rounded-[32px] p-4 border border-slate-100 shadow-sm space-y-3">
                            <h3 className="text-xs font-black text-slate-900 uppercase tracking-widest border-b pb-2">Transactions Ledger</h3>
                            <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                                {flPayouts.map(p => (
                                    <div key={p._id} className="p-2.5 bg-slate-50 border border-slate-100 rounded-xl text-[10px] space-y-1">
                                        <div className="flex justify-between font-bold">
                                            <span className="text-slate-800 truncate max-w-[100px]">{p.order?.packageName || 'Payout'}</span>
                                            <span className="text-slate-950 font-black">{formatCurrency(p.amount)}</span>
                                        </div>
                                        <div className="flex justify-between text-[9px] text-slate-400">
                                            <span>{new Date(p.createdAt).toLocaleDateString()}</span>
                                            <span className={`px-1 rounded font-black uppercase ${p.status === 'Paid' ? 'bg-green-50 text-green-600' : 'bg-yellow-50 text-yellow-600'}`}>{p.status}</span>
                                        </div>
                                    </div>
                                ))}
                                {flPayouts.length === 0 && (
                                    <p className="text-center text-xs text-slate-400 italic py-4">No payouts found.</p>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Right Column: Active Project Workspace */}
                    <div className="lg:col-span-3">
                        {selectedOrder ? (
                            <div className="bg-white rounded-[32px] border border-slate-100 shadow-sm overflow-hidden">
                                <div className="p-6 md:p-8 bg-slate-50/50 border-b border-slate-100 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                                    <div>
                                        <span className="bg-indigo-50 text-indigo-700 px-2.5 py-0.5 rounded-full text-[9px] font-black uppercase tracking-wider">{selectedOrder.serviceName}</span>
                                        <h3 className="text-xl font-black text-slate-900 mt-2">{selectedOrder.packageName}</h3>
                                    </div>
                                    <div className="text-right">
                                        <p className="text-[10px] text-slate-400 uppercase font-black tracking-widest">Payout Budget</p>
                                        <p className="text-2xl font-black text-slate-900 mt-1">₹{selectedOrder.freelancerPayout || 0}</p>
                                    </div>
                                </div>

                                <div className="px-6 border-b border-slate-100 bg-white flex flex-wrap gap-2">
                                    {['Overview', 'Tasks', 'Requirements', 'ToDo', 'Activities', 'Docs', 'Transactions'].map((tab) => (
                                        <button
                                            key={tab}
                                            onClick={() => setOrderDetailTab(tab)}
                                            className={`px-4 py-3 text-xs font-black uppercase tracking-wider border-b-2 transition ${orderDetailTab === tab ? 'border-indigo-600 text-indigo-700' : 'border-transparent text-slate-500 hover:text-indigo-600'}`}
                                        >
                                            {tab}
                                        </button>
                                    ))}
                                </div>

                                <div className="p-6 md:p-8">
                                    {isLoadingOrderData ? (
                                        <div className="flex flex-col items-center justify-center p-12">
                                            <div className="w-8 h-8 border-4 border-slate-200 border-t-indigo-600 rounded-full animate-spin mb-3"></div>
                                            <p className="text-xs text-slate-400 font-bold">Syncing project parameters...</p>
                                        </div>
                                    ) : (
                                        <>
                                            {orderDetailTab === 'Overview' && (
                                                <div className="space-y-6">
                                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                                        <div className="bg-slate-50 p-4 rounded-2xl border border-slate-100">
                                                            <p className="text-[9px] text-slate-400 uppercase font-black tracking-widest">Payout Status</p>
                                                            <p className="text-slate-900 font-black mt-1 text-sm">₹{selectedOrder.freelancerPayout}</p>
                                                            <span className="bg-green-50 text-green-700 px-2 py-0.5 rounded-full text-[9px] font-black uppercase tracking-wider mt-2 inline-block border border-green-100">Claimed</span>
                                                        </div>
                                                        <div className="bg-slate-50 p-4 rounded-2xl border border-slate-100">
                                                            <p className="text-[9px] text-slate-400 uppercase font-black tracking-widest">Time Logs</p>
                                                            <p className="text-slate-900 font-black mt-1 text-sm">
                                                                {selectedOrder.freelancerTimeLogs?.reduce((sum, log) => sum + log.minutes, 0) || 0} Minutes
                                                            </p>
                                                            <span className="text-[9px] text-slate-400 mt-2 block font-semibold">Accumulated Effort</span>
                                                        </div>
                                                    </div>

                                                    <div className="space-y-3">
                                                        <h4 className="text-xs font-black text-slate-900 uppercase tracking-widest border-b pb-1.5 flex items-center gap-1.5"><CheckCircle2 className="w-4 h-4 text-indigo-600" /> To-Dos Checklist</h4>
                                                        <div className="space-y-2">
                                                            {orderTodos.map(todo => (
                                                                <div key={todo._id} className="flex items-center gap-2.5 p-3 rounded-xl border border-slate-100 bg-slate-50/40 text-xs font-semibold text-slate-700">
                                                                    <div className={`w-4 h-4 rounded border flex items-center justify-center ${todo.status === 'Completed' ? 'bg-indigo-600 border-indigo-600 text-white' : 'border-slate-300 bg-white'}`}>
                                                                        {todo.status === 'Completed' && <Check className="w-3 h-3" />}
                                                                    </div>
                                                                    <span className={todo.status === 'Completed' ? 'line-through text-slate-400' : ''}>{todo.title}</span>
                                                                </div>
                                                            ))}
                                                            {orderTodos.length === 0 && (
                                                                <p className="text-slate-400 italic text-xs py-4 text-center">No tasks listed.</p>
                                                            )}
                                                        </div>
                                                    </div>
                                                </div>
                                            )}

                                            {orderDetailTab === 'Tasks' && (
                                                <div className="space-y-4">
                                                    <h4 className="text-xs font-black text-slate-900 uppercase tracking-widest border-b pb-1.5">Project Tasks</h4>
                                                    <div className="space-y-3">
                                                        {(selectedOrder.tasks || []).map((t, idx) => (
                                                            <div key={idx} className="p-4 bg-slate-50 border border-slate-100 rounded-2xl space-y-2">
                                                                <div className="flex justify-between items-center">
                                                                    <div>
                                                                        <p className="font-bold text-slate-800 text-xs">{t.title}</p>
                                                                        {t.taskCode && <p className="text-[9px] text-slate-400 font-bold uppercase">{t.taskCode}</p>}
                                                                    </div>
                                                                    <span className={`px-2 py-0.5 rounded-full text-[9px] font-black uppercase tracking-wider ${t.status === 'Completed' ? 'bg-green-100 text-green-700' : t.status === 'In Progress' ? 'bg-indigo-100 text-indigo-700' : 'bg-yellow-100 text-yellow-700'}`}>{t.status || 'Pending'}</span>
                                                                </div>
                                                                {t.subtasks?.length > 0 && (
                                                                    <div className="border-t border-slate-200/50 pt-2 space-y-1">
                                                                        {t.subtasks.map((st, sIdx) => (
                                                                            <div key={sIdx} className="flex justify-between text-[10px] text-slate-650 pl-2">
                                                                                <span>• {st.title}</span>
                                                                                <span className="font-black uppercase tracking-tight">{st.status}</span>
                                                                            </div>
                                                                        ))}
                                                                    </div>
                                                                )}
                                                            </div>
                                                        ))}
                                                        {(selectedOrder.tasks || []).length === 0 && (
                                                            <p className="text-slate-400 italic text-xs py-4 text-center">No workflow tasks defined.</p>
                                                        )}
                                                    </div>
                                                </div>
                                            )}

                                            {orderDetailTab === 'Requirements' && (
                                                <div className="space-y-4">
                                                    <h4 className="text-xs font-black text-slate-900 uppercase tracking-widest border-b pb-1.5">Customer Requirements</h4>
                                                    <div className="space-y-3">
                                                        {(selectedOrder.customerRequirements || []).map((r, idx) => (
                                                            <div key={idx} className="p-3.5 bg-slate-50 border border-slate-100 rounded-xl flex items-center justify-between text-xs">
                                                                <div>
                                                                    <p className="font-bold text-slate-805">{r.title}</p>
                                                                    {r.description && <p className="text-[10px] text-slate-400 mt-0.5">{r.description}</p>}
                                                                </div>
                                                                <div className="flex items-center gap-2">
                                                                    {r.uploadedDocumentUrl && (
                                                                        <a href={r.uploadedDocumentUrl} target="_blank" rel="noreferrer" className="p-1.5 bg-white border border-slate-250 text-indigo-650 hover:bg-indigo-50 rounded-lg transition">
                                                                            <Eye className="w-4 h-4" />
                                                                        </a>
                                                                    )}
                                                                    <span className={`px-2 py-0.5 rounded-full text-[9px] font-black uppercase tracking-wider ${r.status === 'Verified' ? 'bg-green-150 text-green-700' : 'bg-yellow-100 text-yellow-700'}`}>{r.status}</span>
                                                                </div>
                                                            </div>
                                                        ))}
                                                        {(selectedOrder.customerRequirements || []).length === 0 && (
                                                            <p className="text-slate-400 italic text-xs py-4 text-center">No checklist requirements Raised.</p>
                                                        )}
                                                    </div>
                                                </div>
                                            )}

                                            {orderDetailTab === 'ToDo' && (
                                                <div className="space-y-4">
                                                    <h4 className="text-xs font-black text-slate-900 uppercase tracking-widest border-b pb-1.5">To-Dos Checklist</h4>
                                                    <div className="space-y-2">
                                                        {orderTodos.map(todo => (
                                                            <div key={todo._id} className="p-3.5 bg-slate-50 border border-slate-100 rounded-xl flex justify-between items-center text-xs font-semibold text-slate-700">
                                                                <span>{todo.title}</span>
                                                                <span className={`px-2 py-0.5 rounded-full text-[9px] font-black uppercase ${todo.status === 'Completed' ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'}`}>{todo.status}</span>
                                                            </div>
                                                        ))}
                                                        {orderTodos.length === 0 && (
                                                            <p className="text-slate-400 italic text-xs py-4 text-center">No checklist tasks logged.</p>
                                                        )}
                                                    </div>
                                                </div>
                                            )}

                                            {orderDetailTab === 'Activities' && (
                                                <div className="space-y-4">
                                                    <h4 className="text-xs font-black text-slate-900 uppercase tracking-widest border-b pb-1.5">Milestone Logs</h4>
                                                    <div className="relative pl-4 border-l border-slate-100 space-y-4 pr-1 text-xs">
                                                        {orderHistory.map(log => (
                                                            <div key={log._id} className="relative group">
                                                                <div className="absolute -left-[21px] top-1 w-2 h-2 rounded-full border-2 border-white bg-indigo-500" />
                                                                <p className="font-black text-indigo-600 uppercase text-[9px] tracking-wider">{log.action}</p>
                                                                <p className="text-slate-700 font-bold mt-0.5">{log.description}</p>
                                                                <p className="text-[9px] text-slate-400 mt-0.5">{new Date(log.createdAt).toLocaleString()}</p>
                                                            </div>
                                                        ))}
                                                        {orderHistory.length === 0 && (
                                                            <p className="text-slate-400 italic text-xs py-4 text-center">No milestones registered.</p>
                                                        )}
                                                    </div>
                                                </div>
                                            )}

                                            {orderDetailTab === 'Docs' && (
                                                <div className="space-y-4">
                                                    <h4 className="text-xs font-black text-slate-900 uppercase tracking-widest border-b pb-1.5">Documents Vault</h4>
                                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                                                        {selectedOrder.finalCertificateUrl && (
                                                            <div className="p-3.5 rounded-xl border border-slate-205 bg-white flex items-center justify-between">
                                                                <div>
                                                                    <p className="font-bold text-slate-800">Final Deliverable Certificate</p>
                                                                    <p className="text-[9px] text-slate-400 font-bold uppercase mt-0.5">Final Deliverable</p>
                                                                </div>
                                                                <a href={selectedOrder.finalCertificateUrl} target="_blank" rel="noreferrer" className="p-2 bg-indigo-50 hover:bg-indigo-600 hover:text-white rounded-lg text-indigo-600 transition">
                                                                    <Eye className="w-4 h-4" />
                                                                </a>
                                                            </div>
                                                        )}
                                                        {(selectedOrder.customerRequirements || []).filter(r => r.uploadedDocumentUrl).map((r, idx) => (
                                                            <div key={idx} className="p-3.5 rounded-xl border border-slate-200 bg-white flex items-center justify-between">
                                                                <div>
                                                                    <p className="font-bold text-slate-800 truncate max-w-[150px]">{r.title}</p>
                                                                    <p className="text-[9px] text-slate-400 font-bold uppercase mt-0.5">Uploaded Requirement</p>
                                                                </div>
                                                                <a href={r.uploadedDocumentUrl} target="_blank" rel="noreferrer" className="p-2 bg-indigo-50 hover:bg-indigo-600 hover:text-white rounded-lg text-indigo-600 transition">
                                                                    <Eye className="w-4 h-4" />
                                                                </a>
                                                            </div>
                                                        ))}
                                                        {(selectedOrder.clientDocuments || []).map((doc, idx) => (
                                                            <div key={idx} className="p-3.5 rounded-xl border border-slate-200 bg-white flex items-center justify-between">
                                                                <div>
                                                                    <p className="font-bold text-slate-850 truncate max-w-[150px]">{doc.name}</p>
                                                                    <p className="text-[9px] text-slate-400 font-bold uppercase mt-0.5">Client Uploaded</p>
                                                                </div>
                                                                <a href={doc.url} target="_blank" rel="noreferrer" className="p-2 bg-indigo-50 hover:bg-indigo-600 hover:text-white rounded-lg text-indigo-600 transition">
                                                                    <Eye className="w-4 h-4" />
                                                                </a>
                                                            </div>
                                                        ))}
                                                        {(selectedOrder.adminDocuments || []).map((doc, idx) => (
                                                            <div key={idx} className="p-3.5 rounded-xl border border-slate-200 bg-white flex items-center justify-between">
                                                                <div>
                                                                    <p className="font-bold text-slate-800 truncate max-w-[150px]">{doc.name}</p>
                                                                    <p className="text-[9px] text-slate-400 font-bold uppercase mt-0.5">Staff Uploaded</p>
                                                                </div>
                                                                <a href={doc.url} target="_blank" rel="noreferrer" className="p-2 bg-indigo-50 hover:bg-indigo-600 hover:text-white rounded-lg text-indigo-600 transition">
                                                                    <Eye className="w-4 h-4" />
                                                                </a>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}

                                            {orderDetailTab === 'Transactions' && (
                                                <div className="space-y-4">
                                                    <h4 className="text-xs font-black text-slate-900 uppercase tracking-widest border-b pb-1.5">Payments History for this Project</h4>
                                                    <div className="space-y-2">
                                                        {orderPayments.map(p => (
                                                            <div key={p._id} className="p-3 rounded-xl border border-slate-100 bg-white flex items-center justify-between text-xs font-semibold">
                                                                <div>
                                                                    <p className="font-black text-slate-800">{p.paymentId}</p>
                                                                    <p className="text-[9px] text-slate-400 font-bold uppercase mt-0.5">{p.method} | {new Date(p.createdAt).toLocaleDateString()}</p>
                                                                </div>
                                                                <div className="text-right">
                                                                    <p className="font-black text-slate-950">₹{p.amount}</p>
                                                                    <span className="px-1.5 py-0.5 rounded text-[8px] font-black uppercase bg-emerald-50 text-emerald-700">{p.status}</span>
                                                                </div>
                                                            </div>
                                                        ))}
                                                        {orderPayments.length === 0 && (
                                                            <p className="text-slate-400 italic text-xs py-4 text-center">No transactions registered for this project.</p>
                                                        )}
                                                    </div>
                                                </div>
                                            )}
                                        </>
                                    )}
                                </div>
                            </div>
                        ) : (
                            <div className="bg-white rounded-3xl p-12 text-center border border-slate-100 shadow-sm">
                                <Briefcase className="w-12 h-12 text-slate-300 mx-auto mb-4" />
                                <h4 className="text-lg font-bold text-slate-800">Select a Project</h4>
                                <p className="text-slate-400 mt-1 max-w-sm mx-auto font-semibold text-xs leading-relaxed">Select one of the freelancer's assigned projects from the side list to inspect tasks, log sessions, documents and payment records.</p>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        );
    };

    if (selectedFreelancerForWorkspace) {
        return renderFreelancerWorkspace();
    }

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            {/* Header section */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                <div>
                    <h2 className="text-3xl font-black text-slate-800 tracking-tight">Freelancer Hub</h2>
                    <p className="text-slate-500 font-medium mt-1">Supervise freelancer registrations, view time tracking and manage treasury payouts.</p>
                </div>
                <div className="flex items-center gap-3">
                    <button 
                        onClick={fetchData}
                        className="p-3 rounded-2xl bg-white border border-slate-200 text-slate-500 hover:text-red-500 transition-all shadow-sm"
                    >
                        <RefreshCcw className="w-5 h-5" />
                    </button>
                    <div className="flex bg-slate-100 p-1.5 rounded-2xl gap-2 font-bold text-xs">
                        {['Registrations', 'Payouts', 'LiveAttendance'].map((tab) => (
                            <button
                                key={tab}
                                onClick={() => { setActiveSubTab(tab); setSearchTerm(''); }}
                                className={`px-4 py-2.5 rounded-xl transition-all ${activeSubTab === tab ? 'bg-slate-900 text-white shadow-md' : 'text-slate-500 hover:text-slate-900'}`}
                            >
                                {tab === 'LiveAttendance' ? 'Live Clock-In' : tab}
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            {error && (
                <div className="p-4 bg-red-50 border-l-4 border-red-600 rounded-lg flex items-center text-red-700 text-sm">
                    <AlertCircle className="w-5 h-5 mr-3 shrink-0" />
                    {error}
                </div>
            )}

            {successMsg && (
                <div className="p-4 bg-green-50 border-l-4 border-green-600 rounded-lg flex items-center text-green-700 text-sm">
                    <CheckCircle2 className="w-5 h-5 mr-3 shrink-0" />
                    {successMsg}
                </div>
            )}

            {loading ? (
                <div className="flex flex-col items-center justify-center p-20">
                    <div className="w-12 h-12 border-4 border-slate-200 border-t-red-600 rounded-full animate-spin mb-4"></div>
                    <p className="text-slate-500 font-bold">Fetching latest data...</p>
                </div>
            ) : (
                <>
                    {/* Registrations List */}
                    {activeSubTab === 'Registrations' && (
                        <div className="bg-white rounded-[32px] border border-slate-100 shadow-sm overflow-hidden">
                            <div className="p-8 border-b border-slate-100 bg-slate-50/30 flex justify-between items-center">
                                <div className="relative w-80">
                                    <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                                    <input 
                                        type="text" 
                                        placeholder="Search by name, email, skills..."
                                        value={searchTerm}
                                        onChange={(e) => setSearchTerm(e.target.value)}
                                        className="w-full pl-11 pr-4 py-3 rounded-2xl bg-white border border-slate-200 text-sm font-semibold outline-none focus:border-red-500 transition shadow-sm"
                                    />
                                </div>
                            </div>
                            <div className="overflow-x-auto">
                                <table className="w-full text-left border-collapse">
                                    <thead>
                                        <tr className="bg-slate-50/50">
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Freelancer Details</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Experience & Skills</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Bank Details</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-center">Verification Status</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-right">Action</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-100 text-xs font-semibold">
                                        {filteredFreelancers.length > 0 ? filteredFreelancers.map((freelancer) => (
                                            <tr key={freelancer._id} className="hover:bg-slate-50/30 transition">
                                                <td className="px-8 py-5">
                                                    <div className="flex items-center gap-2">
                                                        <div 
                                                            onClick={() => {
                                                                setSelectedFreelancerForWorkspace(freelancer);
                                                                const freelancerOrders = orders.filter(o => (o.assignedFreelancer?._id || o.assignedFreelancer) === freelancer._id);
                                                                if (freelancerOrders.length > 0) {
                                                                    setSelectedOrderId(freelancerOrders[0]._id);
                                                                } else {
                                                                    setSelectedOrderId(null);
                                                                }
                                                                setOrderDetailTab('Overview');
                                                            }} 
                                                            className="font-black text-indigo-600 hover:text-indigo-800 hover:underline cursor-pointer text-sm"
                                                        >
                                                            {freelancer.name}
                                                        </div>
                                                        {freelancer.isClockedIn && (
                                                            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-red-50 text-red-600 rounded-md text-[8px] font-black uppercase tracking-wider animate-pulse border border-red-100">
                                                                <span className="w-1 h-1 bg-red-600 rounded-full"></span> Clocked In
                                                            </span>
                                                        )}
                                                    </div>
                                                    <div className="text-slate-400 text-[10px] mt-1 font-bold">
                                                        <span>{freelancer.phone} | {freelancer.email}</span>
                                                    </div>
                                                </td>
                                                <td className="px-8 py-5">
                                                    <div>Exp: <span className="text-slate-900 font-bold">{freelancer.yearsOfExperience} Years</span></div>
                                                    <div className="flex flex-wrap gap-1 mt-2">
                                                        {freelancer.skills.map((s, idx) => (
                                                            <span key={idx} className="bg-red-50 text-red-600 px-2 py-0.5 rounded-full text-[9px] font-black uppercase tracking-wider">{s}</span>
                                                        ))}
                                                    </div>
                                                    {freelancer.resumeUrl && (
                                                        <a href={freelancer.resumeUrl} target="_blank" rel="noopener noreferrer" className="text-red-600 hover:underline flex items-center gap-0.5 mt-2 text-[10px] font-bold">
                                                            View Resume/Portfolio <ArrowUpRight className="w-3 h-3" />
                                                        </a>
                                                    )}
                                                </td>
                                                <td className="px-8 py-5">
                                                    <div className="text-slate-900 font-bold">{freelancer.bankDetails?.bankName || 'N/A'}</div>
                                                    <div className="text-slate-400 text-[10px] mt-1 font-semibold">
                                                        A/C: {freelancer.bankDetails?.accountNumber} | IFSC: {freelancer.bankDetails?.ifscCode}
                                                    </div>
                                                </td>
                                                <td className="px-8 py-5 text-center space-y-2">
                                                    <div>
                                                        <span className={`px-2.5 py-1 rounded-full text-[9px] font-black uppercase tracking-widest ${freelancer.isActive ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'}`}>
                                                            {freelancer.isActive ? 'Active / Approved' : 'Pending Review'}
                                                        </span>
                                                    </div>
                                                    {freelancer.pendingProfileUpdate && (
                                                        <div>
                                                            <span className="inline-flex items-center gap-1 px-2.5 py-1 bg-amber-50 text-amber-705 rounded-full text-[9px] font-black uppercase tracking-wider animate-pulse border border-amber-100">
                                                                Update Pending
                                                            </span>
                                                        </div>
                                                    )}
                                                </td>
                                                <td className="px-8 py-5">
                                                    <div className="flex items-center justify-end gap-2.5">
                                                        {!freelancer.isActive && (
                                                            <button 
                                                                onClick={() => handleApproveFreelancer(freelancer._id)}
                                                                className="px-3 py-1.5 bg-green-600 hover:bg-green-700 text-white rounded-xl text-[10px] font-black uppercase tracking-wider transition"
                                                            >
                                                                Approve
                                                            </button>
                                                        )}
                                                        <button 
                                                            onClick={() => { setSelectedFreelancer(freelancer); setEditMode(false); }}
                                                            className="p-2 bg-slate-50 border border-slate-100 hover:border-slate-200 text-slate-500 rounded-xl transition"
                                                            title="View Details"
                                                        >
                                                            <Eye className="w-4 h-4" />
                                                        </button>
                                                        <button 
                                                            onClick={() => openEditModal(freelancer)}
                                                            className="p-2 bg-slate-50 border border-slate-100 hover:border-slate-200 text-slate-500 rounded-xl transition"
                                                            title="Edit Details"
                                                        >
                                                            <Edit className="w-4 h-4" />
                                                        </button>
                                                        <button 
                                                            onClick={() => handleDeleteFreelancer(freelancer._id)}
                                                            className="p-2 bg-rose-50 border border-rose-100 hover:border-rose-200 text-rose-600 rounded-xl transition"
                                                            title="Delete Freelancer"
                                                        >
                                                            <Trash2 className="w-4 h-4" />
                                                        </button>
                                                    </div>
                                                </td>
                                            </tr>
                                        )) : (
                                            <tr>
                                                <td colSpan="5" className="p-16 text-center text-slate-400 font-bold">No freelancers registered yet.</td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* Payouts Section */}
                    {activeSubTab === 'Payouts' && (
                        <div className="bg-white rounded-[32px] border border-slate-100 shadow-sm overflow-hidden">
                            <div className="p-8 border-b border-slate-100 bg-slate-50/30">
                                <h3 className="text-lg font-black text-slate-900">Earnings & Treasury Ledger</h3>
                            </div>
                            <div className="overflow-x-auto">
                                <table className="w-full text-left border-collapse">
                                    <thead>
                                        <tr className="bg-slate-50/50">
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Freelancer</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Order/Package</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Payout Amount</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-center">Settlement Status</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Action</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-100 text-xs font-semibold">
                                        {payouts.length > 0 ? payouts.map((payout) => (
                                            <tr key={payout._id} className="hover:bg-slate-50/30 transition">
                                                <td className="px-8 py-5">
                                                    <div className="font-bold text-slate-900">{payout.freelancer?.name}</div>
                                                    <div className="text-slate-400 text-[10px] mt-0.5">{payout.freelancer?.email}</div>
                                                </td>
                                                <td className="px-8 py-5">
                                                    <div className="font-bold text-slate-900">{payout.order?.packageName || 'N/A'}</div>
                                                    <div className="text-slate-400 text-[10px] mt-0.5">{payout.order?.serviceName}</div>
                                                </td>
                                                <td className="px-8 py-5 font-black text-slate-900">{formatCurrency(payout.amount)}</td>
                                                <td className="px-8 py-5 text-center">
                                                    <span className={`px-2.5 py-1 rounded-full text-[9px] font-black uppercase tracking-widest ${payout.status === 'Paid' ? 'bg-green-100 text-green-700 border border-green-150' : payout.status === 'Approved' ? 'bg-indigo-100 text-indigo-700' : 'bg-yellow-100 text-yellow-700'}`}>
                                                        {payout.status}
                                                    </span>
                                                </td>
                                                <td className="px-8 py-5">
                                                    {payout.status === 'Approved' && (
                                                        <button 
                                                            onClick={() => setProcessingPayout(payout)}
                                                            className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-xl text-xs font-black shadow-lg transition"
                                                        >
                                                            Record Payment
                                                        </button>
                                                    )}
                                                    {payout.status === 'Paid' && (
                                                        <span className="text-slate-400 font-mono text-[10px] uppercase">
                                                            {payout.method} - {payout.transactionRef}
                                                        </span>
                                                    )}
                                                </td>
                                            </tr>
                                        )) : (
                                            <tr>
                                                <td colSpan="5" className="p-16 text-center text-slate-400 font-bold">No payouts logged yet.</td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* Live Clock-In Attendance Status */}
                    {activeSubTab === 'LiveAttendance' && (
                        <div className="bg-white rounded-[32px] border border-slate-100 shadow-sm overflow-hidden">
                            <div className="p-8 border-b border-slate-100 bg-slate-50/30">
                                <h3 className="text-lg font-black text-slate-900">Live Attendance Status</h3>
                            </div>
                            <div className="overflow-x-auto">
                                <table className="w-full text-left border-collapse">
                                    <thead>
                                        <tr className="bg-slate-50/50">
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">User</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Role</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Active Order</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Clocked-In Since</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Live Badge</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-100 text-xs font-semibold">
                                        {liveAttendance.length > 0 ? liveAttendance.map((user) => (
                                            <tr key={user._id} className="hover:bg-slate-50/30 transition">
                                                <td className="px-8 py-5">
                                                    <div className="font-bold text-slate-900">{user.name}</div>
                                                    <div className="text-slate-400 text-[10px] mt-0.5">{user.email}</div>
                                                </td>
                                                <td className="px-8 py-5 uppercase font-black tracking-wider text-slate-500">{user.role}</td>
                                                <td className="px-8 py-5 font-bold text-slate-900">
                                                    {user.activeOrderId?.packageName || 'N/A'}
                                                    <p className="text-[10px] text-slate-400 mt-0.5">{user.activeOrderId?.serviceName}</p>
                                                </td>
                                                <td className="px-8 py-5 font-bold text-slate-600">
                                                    {new Date(user.lastClockInTime).toLocaleTimeString()}
                                                </td>
                                                <td className="px-8 py-5">
                                                    <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-red-50 text-red-600 rounded-full text-[9px] font-black uppercase tracking-widest animate-pulse border border-red-100">
                                                        <span className="w-1.5 h-1.5 bg-red-600 rounded-full"></span> Live
                                                    </span>
                                                </td>
                                            </tr>
                                        )) : (
                                            <tr>
                                                <td colSpan="5" className="p-16 text-center text-slate-400 font-bold">No employees or freelancers are clocked in.</td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                </>
            )}

            {/* View Details / Edit Modal */}
            {selectedFreelancer && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-slate-900/40 backdrop-blur-sm animate-fade-in">
                    <div className="bg-white rounded-[40px] shadow-2xl max-w-2xl w-full overflow-hidden border border-white/50 max-h-[85vh] flex flex-col">
                        <div className="bg-slate-950 p-6 flex items-center justify-between border-b-4 border-red-600">
                            <div>
                                <h3 className="text-white text-lg font-black tracking-tight">
                                    {editMode ? 'Edit Freelancer Profile' : 'Freelancer Details'}
                                </h3>
                                <p className="text-slate-400 text-[10px] font-bold uppercase tracking-widest mt-1">
                                    {selectedFreelancer.name}
                                </p>
                            </div>
                            <button onClick={() => setSelectedFreelancer(null)} className="p-2 text-slate-400 hover:text-white transition">
                                <X className="w-6 h-6" />
                            </button>
                        </div>
                        
                        <div className="p-6 md:p-8 overflow-y-auto flex-1 space-y-6">
                            {editMode ? (
                                <form onSubmit={handleEditSubmit} className="space-y-4">
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-1">
                                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest block">Full Name</label>
                                            <input 
                                                type="text" 
                                                required
                                                value={editForm.name}
                                                onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                                                className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 outline-none font-bold text-xs focus:border-red-500 focus:bg-white"
                                            />
                                        </div>
                                        <div className="space-y-1">
                                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest block">Email Address</label>
                                            <input 
                                                type="email" 
                                                required
                                                value={editForm.email}
                                                onChange={(e) => setEditForm({ ...editForm, email: e.target.value })}
                                                className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 outline-none font-bold text-xs focus:border-red-500 focus:bg-white"
                                            />
                                        </div>
                                        <div className="space-y-1">
                                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest block">Phone Number</label>
                                            <input 
                                                type="text" 
                                                required
                                                value={editForm.phone}
                                                onChange={(e) => setEditForm({ ...editForm, phone: e.target.value })}
                                                className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 outline-none font-bold text-xs focus:border-red-500 focus:bg-white"
                                            />
                                        </div>
                                        <div className="space-y-1">
                                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest block">Experience (Years)</label>
                                            <input 
                                                type="number" 
                                                value={editForm.yearsOfExperience}
                                                onChange={(e) => setEditForm({ ...editForm, yearsOfExperience: Number(e.target.value) })}
                                                className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 outline-none font-bold text-xs focus:border-red-500 focus:bg-white"
                                            />
                                        </div>
                                    </div>

                                    <div className="space-y-1">
                                        <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest block">Skills (comma separated)</label>
                                        <input 
                                            type="text" 
                                            value={editForm.skills}
                                            onChange={(e) => setEditForm({ ...editForm, skills: e.target.value })}
                                            placeholder="e.g. INCOME TAX, GST, COMPANY INCORPORATION"
                                            className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 outline-none font-bold text-xs focus:border-red-500 focus:bg-white"
                                        />
                                    </div>

                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-1">
                                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest block">PAN Card Number</label>
                                            <input 
                                                type="text" 
                                                value={editForm.panCard || ''}
                                                onChange={(e) => setEditForm({ ...editForm, panCard: e.target.value.toUpperCase() })}
                                                className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 outline-none font-bold text-xs focus:border-red-500 focus:bg-white uppercase"
                                            />
                                        </div>
                                        <div className="space-y-1">
                                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest block">Resume/Portfolio Link</label>
                                            <input 
                                                type="text" 
                                                value={editForm.resumeUrl}
                                                onChange={(e) => setEditForm({ ...editForm, resumeUrl: e.target.value })}
                                                className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 outline-none font-bold text-xs focus:border-red-500 focus:bg-white"
                                            />
                                        </div>
                                    </div>

                                    <div className="bg-slate-50 p-4 rounded-2xl border border-slate-100 space-y-3">
                                        <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-widest border-b pb-1.5">Bank Payout Info</h4>
                                        <div className="grid grid-cols-2 gap-3">
                                            <div className="space-y-1">
                                                <label className="text-[9px] font-black text-slate-400 uppercase block">Bank Name</label>
                                                <input 
                                                    type="text" 
                                                    value={editForm.bankDetails.bankName}
                                                    onChange={(e) => setEditForm({ 
                                                        ...editForm, 
                                                        bankDetails: { ...editForm.bankDetails, bankName: e.target.value } 
                                                    })}
                                                    className="w-full px-3 py-2 rounded-xl bg-white border border-slate-200 outline-none font-bold text-xs focus:border-red-500"
                                                />
                                            </div>
                                            <div className="space-y-1">
                                                <label className="text-[9px] font-black text-slate-400 uppercase block">Account Number</label>
                                                <input 
                                                    type="text" 
                                                    value={editForm.bankDetails.accountNumber}
                                                    onChange={(e) => setEditForm({ 
                                                        ...editForm, 
                                                        bankDetails: { ...editForm.bankDetails, accountNumber: e.target.value } 
                                                    })}
                                                    className="w-full px-3 py-2 rounded-xl bg-white border border-slate-200 outline-none font-bold text-xs focus:border-red-500"
                                                />
                                            </div>
                                            <div className="space-y-1">
                                                <label className="text-[9px] font-black text-slate-400 uppercase block">IFSC Code</label>
                                                <input 
                                                    type="text" 
                                                    value={editForm.bankDetails.ifscCode}
                                                    onChange={(e) => setEditForm({ 
                                                        ...editForm, 
                                                        bankDetails: { ...editForm.bankDetails, ifscCode: e.target.value.toUpperCase() } 
                                                    })}
                                                    className="w-full px-3 py-2 rounded-xl bg-white border border-slate-200 outline-none font-bold text-xs focus:border-red-500 uppercase"
                                                />
                                            </div>
                                            <div className="space-y-1">
                                                <label className="text-[9px] font-black text-slate-400 uppercase block">Account Beneficiary Name</label>
                                                <input 
                                                    type="text" 
                                                    value={editForm.bankDetails.accountName}
                                                    onChange={(e) => setEditForm({ 
                                                        ...editForm, 
                                                        bankDetails: { ...editForm.bankDetails, accountName: e.target.value } 
                                                    })}
                                                    className="w-full px-3 py-2 rounded-xl bg-white border border-slate-200 outline-none font-bold text-xs focus:border-red-500"
                                                />
                                            </div>
                                        </div>
                                    </div>

                                    <div className="flex items-center gap-2 px-1">
                                        <input 
                                            type="checkbox" 
                                            id="isActiveCheckbox"
                                            checked={editForm.isActive}
                                            onChange={(e) => setEditForm({ ...editForm, isActive: e.target.checked })}
                                            className="w-4 h-4 rounded text-red-600 border-slate-300 focus:ring-red-500"
                                        />
                                        <label htmlFor="isActiveCheckbox" className="text-xs font-bold text-slate-700 select-none">
                                            Freelancer Account is Active / Approved
                                        </label>
                                    </div>

                                    <div className="flex gap-4 pt-4 border-t border-slate-100">
                                        <button 
                                            type="button"
                                            onClick={() => setEditMode(false)}
                                            className="flex-1 py-3 bg-slate-100 text-slate-600 font-bold hover:bg-slate-200 rounded-xl transition"
                                        >
                                            View Details
                                        </button>
                                        <button 
                                            type="submit"
                                            className="flex-1 py-3 bg-slate-900 text-white font-bold hover:bg-slate-800 rounded-xl shadow-lg transition"
                                        >
                                            Save Profile
                                        </button>
                                    </div>
                                </form>
                            ) : (
                                <div className="space-y-6">
                                    {selectedFreelancer.pendingProfileUpdate && (
                                        <div className="bg-amber-50/70 border border-amber-200 rounded-3xl p-6 space-y-4">
                                            <div className="flex items-center gap-2 text-amber-800 font-bold text-sm">
                                                <AlertCircle className="w-5 h-5 shrink-0" />
                                                <span>Requested Profile Changes (Pending Approval)</span>
                                            </div>
                                            
                                            <div className="text-xs text-slate-700 bg-white rounded-2xl p-4 border border-slate-100 divide-y divide-slate-100">
                                                {(() => {
                                                    const pending = selectedFreelancer.pendingProfileUpdate;
                                                    const rows = [];
                                                    
                                                    const addCompare = (label, activeVal, pendingVal) => {
                                                        const activeStr = activeVal !== undefined && activeVal !== null ? String(activeVal) : 'N/A';
                                                        const pendingStr = pendingVal !== undefined && pendingVal !== null ? String(pendingVal) : 'N/A';
                                                        if (activeStr !== pendingStr) {
                                                            rows.push({ label, active: activeStr, pending: pendingStr });
                                                        }
                                                    };
                                                    
                                                    addCompare('Full Name', selectedFreelancer.name, pending.name);
                                                    addCompare('Phone', selectedFreelancer.phone, pending.phone);
                                                    addCompare('Experience', `${selectedFreelancer.yearsOfExperience} Years`, `${pending.yearsOfExperience} Years`);
                                                    addCompare('Skills', selectedFreelancer.skills?.join(', '), pending.skills?.join(', '));
                                                    addCompare('PAN Card', selectedFreelancer.panCard, pending.panCard);
                                                    addCompare('Resume Link', selectedFreelancer.resumeUrl, pending.resumeUrl);
                                                    
                                                    addCompare('Bank Name', selectedFreelancer.bankDetails?.bankName, pending.bankDetails?.bankName);
                                                    addCompare('Account Name', selectedFreelancer.bankDetails?.accountName, pending.bankDetails?.accountName);
                                                    addCompare('Account Number', selectedFreelancer.bankDetails?.accountNumber, pending.bankDetails?.accountNumber);
                                                    addCompare('IFSC Code', selectedFreelancer.bankDetails?.ifscCode, pending.bankDetails?.ifscCode);
                                                    
                                                    if (rows.length === 0) return <p className="text-slate-400 italic py-2 text-center">No differences detected.</p>;
                                                    
                                                    return rows.map((r, i) => (
                                                        <div key={i} className="py-2.5 grid grid-cols-3 gap-2">
                                                            <span className="font-bold text-slate-400 uppercase tracking-wider text-[9px] flex items-center">{r.label}</span>
                                                            <span className="text-slate-505 line-through truncate">{r.active}</span>
                                                            <span className="text-emerald-600 font-bold truncate">{r.pending}</span>
                                                        </div>
                                                    ));
                                                })()}
                                            </div>

                                            <div className="flex gap-3 pt-2">
                                                <button
                                                    onClick={() => handleRejectProfileUpdate(selectedFreelancer._id)}
                                                    className="flex-1 py-2.5 bg-rose-50 hover:bg-rose-100 text-rose-600 rounded-xl text-xs font-black uppercase tracking-wider transition border border-rose-100"
                                                >
                                                    Reject Changes
                                                </button>
                                                <button
                                                    onClick={() => handleApproveProfileUpdate(selectedFreelancer._id)}
                                                    className="flex-1 py-2.5 bg-green-600 hover:bg-green-700 text-white rounded-xl text-xs font-black uppercase tracking-wider transition shadow-lg shadow-green-100"
                                                >
                                                    Approve Changes
                                                </button>
                                            </div>
                                        </div>
                                    )}
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="bg-slate-50 p-3.5 rounded-2xl border border-slate-100">
                                            <p className="text-[9px] font-black text-slate-450 uppercase tracking-widest">Email Address</p>
                                            <p className="text-slate-800 font-bold mt-0.5 text-xs">{selectedFreelancer.email}</p>
                                        </div>
                                        <div className="bg-slate-50 p-3.5 rounded-2xl border border-slate-100">
                                            <p className="text-[9px] font-black text-slate-455 uppercase tracking-widest">Phone Number</p>
                                            <p className="text-slate-800 font-bold mt-0.5 text-xs">{selectedFreelancer.phone}</p>
                                        </div>
                                        <div className="bg-slate-50 p-3.5 rounded-2xl border border-slate-100">
                                            <p className="text-[9px] font-black text-slate-450 uppercase tracking-widest">Years of Experience</p>
                                            <p className="text-slate-800 font-black mt-0.5 text-xs">{selectedFreelancer.yearsOfExperience} Years</p>
                                        </div>
                                        <div className="bg-slate-50 p-3.5 rounded-2xl border border-slate-100">
                                            <p className="text-[9px] font-black text-slate-450 uppercase tracking-widest">PAN Card</p>
                                            <p className="text-slate-800 font-black mt-0.5 text-xs">{selectedFreelancer.panCard || 'N/A'}</p>
                                        </div>
                                    </div>

                                    <div className="bg-slate-50 p-4 rounded-2xl border border-slate-100 space-y-2">
                                        <p className="text-[9px] font-black text-slate-450 uppercase tracking-widest">Skills & Expertise</p>
                                        <div className="flex flex-wrap gap-1.5">
                                            {selectedFreelancer.skills.map((s, idx) => (
                                                <span key={idx} className="bg-red-50 text-red-600 px-2.5 py-1 rounded-full text-[9px] font-black uppercase tracking-wider">{s}</span>
                                            ))}
                                            {selectedFreelancer.skills.length === 0 && <span className="text-slate-400 italic">No skills declared</span>}
                                        </div>
                                    </div>

                                    <div className="bg-slate-50 p-4 rounded-2xl border border-slate-100 space-y-3">
                                        <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-widest border-b pb-1">Bank Payment Parameters</h4>
                                        <div className="grid grid-cols-2 gap-4 text-xs font-semibold">
                                            <div>
                                                <p className="text-[9px] text-slate-400 uppercase">Beneficiary Name</p>
                                                <p className="text-slate-700 mt-0.5">{selectedFreelancer.bankDetails?.accountName || 'N/A'}</p>
                                            </div>
                                            <div>
                                                <p className="text-[9px] text-slate-400 uppercase">Bank Name</p>
                                                <p className="text-slate-700 mt-0.5">{selectedFreelancer.bankDetails?.bankName || 'N/A'}</p>
                                            </div>
                                            <div>
                                                <p className="text-[9px] text-slate-400 uppercase">Account Number</p>
                                                <p className="text-slate-700 font-mono mt-0.5">{selectedFreelancer.bankDetails?.accountNumber || 'N/A'}</p>
                                            </div>
                                            <div>
                                                <p className="text-[9px] text-slate-400 uppercase">IFSC Code</p>
                                                <p className="text-slate-700 font-mono mt-0.5">{selectedFreelancer.bankDetails?.ifscCode || 'N/A'}</p>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="flex gap-4 pt-4 border-t border-slate-100">
                                        <button 
                                            onClick={() => openEditModal(selectedFreelancer)}
                                            className="flex-1 py-3 bg-slate-900 text-white font-bold hover:bg-slate-800 rounded-xl shadow-lg transition"
                                        >
                                            Edit Details
                                        </button>
                                        <button 
                                            onClick={() => setSelectedFreelancer(null)}
                                            className="flex-1 py-3 bg-slate-100 text-slate-600 font-bold hover:bg-slate-200 rounded-xl transition"
                                        >
                                            Close
                                        </button>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* Payout Processing Modal */}
            {processingPayout && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-slate-900/40 backdrop-blur-sm animate-fade-in">
                    <div className="bg-white rounded-[40px] shadow-2xl max-w-lg w-full overflow-hidden border border-white/50">
                        <div className="bg-slate-955 p-8 flex items-center justify-between border-b-4 border-red-600">
                            <div>
                                <h3 className="text-white text-xl font-black tracking-tight">Record Freelancer Payment</h3>
                                <p className="text-slate-400 text-xs font-bold uppercase tracking-widest mt-1">Log bank transfer settlements</p>
                            </div>
                            <button onClick={() => setProcessingPayout(null)} className="p-2 text-slate-400 hover:text-white transition">
                                <X className="w-6 h-6" />
                            </button>
                        </div>
                        <div className="p-8 space-y-6">
                            <form onSubmit={handleProcessPaymentSubmit} className="space-y-6">
                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Transfer Method</label>
                                    <select 
                                        value={payoutForm.method}
                                        onChange={(e) => setPayoutForm({ ...payoutForm, method: e.target.value })}
                                        className="w-full px-5 py-3 rounded-2xl bg-slate-50 border border-slate-200 outline-none font-bold text-sm transition focus:border-red-500 focus:bg-white"
                                    >
                                        <option value="NEFT">NEFT Transfer</option>
                                        <option value="IMPS">IMPS Immediate Pay</option>
                                        <option value="UPI">UPI Payment</option>
                                        <option value="Cash">Cash Settlement</option>
                                        <option value="Other">Other Mode</option>
                                    </select>
                                </div>

                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Transaction Reference / UTR Number</label>
                                    <input 
                                        type="text" 
                                        required
                                        placeholder="e.g. TXN1234567890"
                                        value={payoutForm.transactionRef}
                                        onChange={(e) => setPayoutForm({ ...payoutForm, transactionRef: e.target.value })}
                                        className="w-full px-5 py-3 rounded-2xl bg-slate-50 border border-slate-200 outline-none font-bold text-sm transition focus:border-red-500 focus:bg-white"
                                    />
                                </div>

                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Internal Notes</label>
                                    <textarea 
                                        placeholder="Add payment notes..."
                                        value={payoutForm.notes}
                                        onChange={(e) => setPayoutForm({ ...payoutForm, notes: e.target.value })}
                                        className="w-full px-5 py-3 rounded-2xl bg-slate-50 border border-slate-200 outline-none font-semibold text-sm transition focus:border-red-500 focus:bg-white h-24"
                                    />
                                </div>

                                <div className="flex gap-4 pt-4 border-t border-slate-100">
                                    <button 
                                        type="button"
                                        onClick={() => setProcessingPayout(null)}
                                        className="flex-1 py-3.5 rounded-2xl bg-slate-100 text-slate-600 font-bold hover:bg-slate-200 transition"
                                    >
                                        Cancel
                                    </button>
                                    <button 
                                        type="submit"
                                        className="flex-1 py-3.5 rounded-2xl bg-slate-900 text-white font-bold hover:bg-slate-800 shadow-xl shadow-slate-200 transition"
                                    >
                                        Log Settlement
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default FreelancersModule;
