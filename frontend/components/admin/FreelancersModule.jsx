import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    Users, Search, RefreshCcw, CheckCircle2, 
    AlertCircle, Loader2, ArrowUpRight, Briefcase, 
    ShieldCheck, Phone, Mail, X, FileText, 
    Clock, DollarSign, Landmark, Check
} from 'lucide-react';

const FreelancersModule = ({ token }) => {
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

    const config = {
        headers: { Authorization: `Bearer ${token}` }
    };

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
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Action</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-100 text-xs font-semibold">
                                        {filteredFreelancers.length > 0 ? filteredFreelancers.map((freelancer) => (
                                            <tr key={freelancer._id} className="hover:bg-slate-50/30 transition">
                                                <td className="px-8 py-5">
                                                    <div className="font-black text-slate-900 text-sm">{freelancer.name}</div>
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
                                                <td className="px-8 py-5 text-center">
                                                    <span className={`px-2.5 py-1 rounded-full text-[9px] font-black uppercase tracking-widest ${freelancer.isActive ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'}`}>
                                                        {freelancer.isActive ? 'Active / Approved' : 'Pending Review'}
                                                    </span>
                                                </td>
                                                <td className="px-8 py-5">
                                                    {!freelancer.isActive && (
                                                        <button 
                                                            onClick={() => handleApproveFreelancer(freelancer._id)}
                                                            className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-xl text-xs font-black shadow-lg transition"
                                                        >
                                                            Approve Account
                                                        </button>
                                                    )}
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

            {/* Payout Processing Modal */}
            {processingPayout && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-slate-900/40 backdrop-blur-md animate-fade-in">
                    <div className="bg-white rounded-[40px] shadow-2xl max-w-lg w-full overflow-hidden border border-white/50">
                        <div className="bg-slate-950 p-8 flex items-center justify-between border-b-4 border-red-600">
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
