import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    LayoutDashboard, Users, LogOut, Menu, X, 
    Bell, User as UserIcon, Settings, ChevronRight, 
    DollarSign, Play, Square, Award, CheckCircle2,
    Clock, Briefcase, FileText, Check, AlertCircle, ArrowUpRight
} from 'lucide-react';

const FreelancerDashboard = ({ userInfo, onLogout }) => {
    const [activeTab, setActiveTab] = useState('Overview');
    const [isSidebarOpen, setIsSidebarOpen] = useState(false);
    const [broadcasts, setBroadcasts] = useState([]);
    const [orders, setOrders] = useState([]);
    const [ledger, setLedger] = useState([]);
    const [liveClockedIn, setLiveClockedIn] = useState(userInfo?.isClockedIn || false);
    const [activeOrderId, setActiveOrderId] = useState(userInfo?.activeOrderId || null);
    const [selectedOrder, setSelectedOrder] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [successMsg, setSuccessMsg] = useState('');

    const token = localStorage.getItem('token');
    const config = {
        headers: { Authorization: `Bearer ${token}` }
    };

    // Poll live status and fetch data
    useEffect(() => {
        fetchOverviewData();
        const interval = setInterval(() => {
            fetchBroadcasts();
        }, 10000); // Poll broadcasts every 10 seconds
        return () => clearInterval(interval);
    }, []);

    const fetchOverviewData = async () => {
        setLoading(true);
        try {
            await fetchBroadcasts();
            await fetchOrders();
            await fetchLedger();
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const fetchBroadcasts = async () => {
        try {
            const { data } = await axios.get('/api/freelancer/broadcasts', config);
            setBroadcasts(data);
        } catch (err) {
            console.error('Failed to fetch broadcasts', err);
        }
    };

    const fetchOrders = async () => {
        try {
            const { data } = await axios.get('/api/freelancer/orders', config);
            setOrders(data);
            
            // Sync local clocked in status from user/orders
            const activeUser = JSON.parse(localStorage.getItem('userInfo'));
            if (activeUser) {
                setLiveClockedIn(activeUser.isClockedIn);
                setActiveOrderId(activeUser.activeOrderId);
            }
        } catch (err) {
            console.error('Failed to fetch orders', err);
        }
    };

    const fetchLedger = async () => {
        try {
            const { data } = await axios.get('/api/freelancer/ledger', config);
            setLedger(data);
        } catch (err) {
            console.error('Failed to fetch ledger', err);
        }
    };

    const handleClaimJob = async (orderId) => {
        try {
            setError('');
            const { data } = await axios.post(`/api/freelancer/claim/${orderId}`, {}, config);
            setSuccessMsg('Job claimed successfully!');
            fetchOverviewData();
            setTimeout(() => setSuccessMsg(''), 3000);
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to claim job');
        }
    };

    const handleClockIn = async (orderId) => {
        try {
            setError('');
            const { data } = await axios.post(`/api/freelancer/clock-in/${orderId}`, {}, config);
            setLiveClockedIn(true);
            setActiveOrderId(orderId);
            
            // Update local storage user info
            const localUser = JSON.parse(localStorage.getItem('userInfo'));
            localUser.isClockedIn = true;
            localUser.activeOrderId = orderId;
            localStorage.setItem('userInfo', JSON.stringify(localUser));

            setSuccessMsg('Clocked in successfully! Work status is live.');
            fetchOrders();
            setTimeout(() => setSuccessMsg(''), 3000);
        } catch (err) {
            setError(err.response?.data?.message || 'Clock in failed');
        }
    };

    const handleClockOut = async (orderId) => {
        try {
            setError('');
            const { data } = await axios.post(`/api/freelancer/clock-out/${orderId}`, {}, config);
            setLiveClockedIn(false);
            setActiveOrderId(null);

            // Update local storage user info
            const localUser = JSON.parse(localStorage.getItem('userInfo'));
            localUser.isClockedIn = false;
            localUser.activeOrderId = null;
            localStorage.setItem('userInfo', JSON.stringify(localUser));

            setSuccessMsg(`Clocked out successfully! Logged ${data.minutesLogged} minutes.`);
            fetchOrders();
            setTimeout(() => setSuccessMsg(''), 3000);
        } catch (err) {
            setError(err.response?.data?.message || 'Clock out failed');
        }
    };

    // Calculate total earnings
    const totalEarned = ledger
        .filter(item => item.status === 'Paid')
        .reduce((sum, item) => sum + item.amount, 0);

    const pendingPayout = ledger
        .filter(item => item.status !== 'Paid')
        .reduce((sum, item) => sum + item.amount, 0);

    const sidebarItems = [
        { name: 'Overview', icon: LayoutDashboard },
        { name: 'Available Jobs', icon: Bell, badge: broadcasts.length },
        { name: 'My Orders', icon: Briefcase, badge: orders.length },
        { name: 'Earnings Ledger', icon: DollarSign }
    ];

    return (
        <div className="flex h-screen bg-slate-50 font-sans overflow-hidden">
            {/* Mobile Sidebar Overlay */}
            {isSidebarOpen && (
                <div 
                    className="fixed inset-0 bg-slate-900/60 backdrop-blur-sm z-[60] lg:hidden animate-fade-in"
                    onClick={() => setIsSidebarOpen(false)}
                ></div>
            )}

            {/* Sidebar */}
            <aside className={`
                fixed lg:relative inset-y-0 left-0 w-[280px] bg-white border-r border-slate-100 z-[70] 
                transform transition-transform duration-500 ease-out flex flex-col
                ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
            `}>
                {/* Logo Section */}
                <div className="p-8 flex items-center justify-between">
                    <div className="flex items-center space-x-3 group cursor-pointer">
                        <div className="w-10 h-10 bg-slate-900 rounded-xl flex items-center justify-center transform group-hover:rotate-12 transition-transform duration-300">
                            <span className="text-white font-black text-xl">VR</span>
                        </div>
                        <div>
                            <h2 className="text-xl font-black text-slate-900 leading-none">VR HERE</h2>
                            <p className="text-[10px] text-red-600 font-black uppercase tracking-widest mt-1">Freelancer Portal</p>
                        </div>
                    </div>
                    <button className="lg:hidden p-2 text-slate-400 hover:text-slate-900" onClick={() => setIsSidebarOpen(false)}>
                        <X className="w-6 h-6" />
                    </button>
                </div>

                {/* Navigation */}
                <nav className="flex-grow px-6 space-y-2 mt-4">
                    {sidebarItems.map((item) => (
                        <button
                            key={item.name}
                            onClick={() => {
                                setActiveTab(item.name);
                                setIsSidebarOpen(false);
                            }}
                            className={`
                                w-full flex items-center justify-between px-4 py-4 rounded-2xl transition-all duration-300 group
                                ${activeTab === item.name 
                                    ? 'bg-slate-900 text-white shadow-xl shadow-slate-200' 
                                    : 'text-slate-500 hover:bg-slate-50 hover:text-slate-900'}
                            `}
                        >
                            <div className="flex items-center gap-3">
                                <item.icon className={`w-5 h-5 transition-transform duration-300 group-hover:scale-110 ${activeTab === item.name ? 'text-red-500' : ''}`} />
                                <span className="font-bold text-sm tracking-wide">{item.name}</span>
                            </div>
                            <div className="flex items-center gap-1">
                                {item.badge > 0 && (
                                    <span className="bg-red-500 text-white text-[10px] px-2 py-0.5 rounded-full font-black">
                                        {item.badge}
                                    </span>
                                )}
                                {activeTab === item.name && <ChevronRight className="w-4 h-4 text-red-500" />}
                            </div>
                        </button>
                    ))}
                </nav>

                {/* Bottom Section */}
                <div className="p-6 mt-auto">
                    <div className="bg-slate-50 rounded-3xl p-5 mb-4 border border-slate-100">
                        <div className="flex items-center gap-3 mb-3">
                            <div className="w-10 h-10 bg-white rounded-full border-2 border-white shadow-sm flex items-center justify-center overflow-hidden">
                                <UserIcon className="w-6 h-6 text-slate-300" />
                            </div>
                            <div className="flex-grow min-w-0">
                                <h4 className="text-sm font-black text-slate-900 truncate">{userInfo.name}</h4>
                                <p className="text-[10px] text-slate-400 font-bold uppercase truncate tracking-tight">{userInfo.email}</p>
                            </div>
                        </div>
                        <button 
                            onClick={onLogout}
                            className="w-full h-11 bg-white border border-slate-200 rounded-xl flex items-center justify-center gap-2 text-sm font-bold text-red-600 hover:bg-red-50 hover:border-red-100 transition-all shadow-sm"
                        >
                            <LogOut className="w-4 h-4" /> Sign Out
                        </button>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <main className="flex-grow flex flex-col min-w-0 overflow-hidden">
                {/* Top Header */}
                <header className="h-20 bg-white border-b border-slate-100 flex items-center justify-between px-6 lg:px-10 shrink-0 relative z-50">
                    <div className="flex items-center gap-4">
                        <button 
                            className="lg:hidden p-2.5 bg-slate-50 rounded-xl text-slate-600 hover:text-slate-900 transition-colors shadow-sm"
                            onClick={() => setIsSidebarOpen(true)}
                        >
                            <Menu className="w-6 h-6" />
                        </button>
                        <div className="hidden sm:block">
                            <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">Welcome Back</span>
                            <h2 className="text-lg font-black text-slate-900 tracking-tight leading-none mt-0.5">{userInfo.name.split(' ')[0]}</h2>
                        </div>
                    </div>

                    <div className="flex items-center gap-3 md:gap-5">
                        {liveClockedIn && (
                            <div className="flex items-center gap-2 px-4 py-2 bg-red-50 text-red-600 rounded-xl border border-red-100 text-[10px] font-black uppercase tracking-widest animate-pulse">
                                <span className="w-2.5 h-2.5 bg-red-600 rounded-full"></span> Live Clocked-In
                            </div>
                        )}
                        <div className="hidden md:flex items-center px-4 py-2 bg-green-50 text-green-600 rounded-xl border border-green-100 text-[10px] font-black uppercase tracking-widest">
                             Freelancer Verified
                        </div>
                    </div>
                </header>

                {/* Content Area */}
                <div className="flex-grow overflow-y-auto custom-scrollbar bg-slate-50/50">
                    <div className="max-w-[1400px] mx-auto p-6 lg:p-10">
                        {error && (
                            <div className="mb-6 p-4 bg-red-50 border-l-4 border-red-600 rounded-xl flex items-center text-red-700 text-sm font-semibold">
                                <AlertCircle className="w-5 h-5 mr-3 shrink-0" />
                                {error}
                            </div>
                        )}
                        {successMsg && (
                            <div className="mb-6 p-4 bg-green-50 border-l-4 border-green-600 rounded-xl flex items-center text-green-700 text-sm font-semibold">
                                <CheckCircle2 className="w-5 h-5 mr-3 shrink-0" />
                                {successMsg}
                            </div>
                        )}

                        {/* TAB 1: OVERVIEW */}
                        {activeTab === 'Overview' && (
                            <div className="space-y-8">
                                {/* Stats row */}
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                    <div className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm flex items-center gap-5">
                                        <div className="w-14 h-14 rounded-2xl bg-indigo-50 flex items-center justify-center text-indigo-600">
                                            <Briefcase className="w-7 h-7" />
                                        </div>
                                        <div>
                                            <p className="text-xs font-bold text-slate-400 uppercase tracking-wider">Assigned Orders</p>
                                            <h3 className="text-3xl font-black text-slate-900 mt-1">{orders.length}</h3>
                                        </div>
                                    </div>
                                    <div className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm flex items-center gap-5">
                                        <div className="w-14 h-14 rounded-2xl bg-green-50 flex items-center justify-center text-green-600">
                                            <DollarSign className="w-7 h-7" />
                                        </div>
                                        <div>
                                            <p className="text-xs font-bold text-slate-400 uppercase tracking-wider">Earned Payouts</p>
                                            <h3 className="text-3xl font-black text-slate-900 mt-1">₹{totalEarned}</h3>
                                        </div>
                                    </div>
                                    <div className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm flex items-center gap-5">
                                        <div className="w-14 h-14 rounded-2xl bg-yellow-50 flex items-center justify-center text-yellow-600">
                                            <Clock className="w-7 h-7" />
                                        </div>
                                        <div>
                                            <p className="text-xs font-bold text-slate-400 uppercase tracking-wider">Pending Payouts</p>
                                            <h3 className="text-3xl font-black text-slate-900 mt-1">₹{pendingPayout}</h3>
                                        </div>
                                    </div>
                                </div>

                                {/* Active Clock Status */}
                                {liveClockedIn && (
                                    <div className="bg-gradient-to-r from-red-500 to-rose-600 text-white rounded-3xl p-8 shadow-xl flex flex-col md:flex-row justify-between items-center gap-6">
                                        <div>
                                            <span className="bg-white/20 px-3 py-1 rounded-full text-xs font-black uppercase tracking-widest">Active Time Clock</span>
                                            <h3 className="text-2xl font-black mt-3">You are currently clocked-in</h3>
                                            <p className="text-white/80 mt-1 font-medium">Your work status is displayed as live on the Checker panel.</p>
                                        </div>
                                        <button 
                                            onClick={() => handleClockOut(activeOrderId)}
                                            className="px-8 py-4 bg-white text-red-600 rounded-2xl font-black shadow-lg hover:bg-slate-50 transition flex items-center gap-3 shrink-0"
                                        >
                                            <Square className="w-5 h-5 fill-red-600" /> Clock Out & Log Hours
                                        </button>
                                    </div>
                                )}

                                {/* Profile info */}
                                <div className="bg-white rounded-3xl p-8 border border-slate-100 shadow-sm grid md:grid-cols-2 gap-8">
                                    <div>
                                        <h3 className="text-lg font-black text-slate-900 mb-4">Qualifications & Experience</h3>
                                        <div className="space-y-4 font-semibold text-slate-600">
                                            <div className="flex justify-between border-b border-slate-50 pb-2">
                                                <span>Years of Experience:</span>
                                                <span className="text-slate-900 font-bold">{userInfo.yearsOfExperience} years</span>
                                            </div>
                                            <div className="flex justify-between border-b border-slate-50 pb-2">
                                                <span>Specializations:</span>
                                                <span className="text-slate-900 font-bold">{userInfo.skills?.join(', ') || 'N/A'}</span>
                                            </div>
                                            <div className="flex justify-between pb-2">
                                                <span>Resume Link:</span>
                                                <a href={userInfo.resumeUrl} target="_blank" rel="noopener noreferrer" className="text-red-600 hover:underline flex items-center gap-1 font-bold">
                                                    View Resume <ArrowUpRight className="w-4 h-4" />
                                                </a>
                                            </div>
                                        </div>
                                    </div>

                                    <div>
                                        <h3 className="text-lg font-black text-slate-900 mb-4">Settlement Account</h3>
                                        <div className="space-y-4 font-semibold text-slate-600">
                                            <div className="flex justify-between border-b border-slate-50 pb-2">
                                                <span>Bank Name:</span>
                                                <span className="text-slate-900 font-bold">{userInfo.bankDetails?.bankName}</span>
                                            </div>
                                            <div className="flex justify-between border-b border-slate-50 pb-2">
                                                <span>Account Name:</span>
                                                <span className="text-slate-900 font-bold">{userInfo.bankDetails?.accountName}</span>
                                            </div>
                                            <div className="flex justify-between border-b border-slate-50 pb-2">
                                                <span>Account Number:</span>
                                                <span className="text-slate-900 font-bold">{userInfo.bankDetails?.accountNumber}</span>
                                            </div>
                                            <div className="flex justify-between pb-2">
                                                <span>IFSC Code:</span>
                                                <span className="text-slate-900 font-bold">{userInfo.bankDetails?.ifscCode}</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* TAB 2: AVAILABLE BROADCASTS */}
                        {activeTab === 'Available Jobs' && (
                            <div className="space-y-6">
                                <div className="flex justify-between items-center mb-4">
                                    <h3 className="text-xl font-black text-slate-900">Open Broadcast Pools</h3>
                                    <button onClick={fetchBroadcasts} className="text-xs font-bold text-red-600 hover:underline">Refresh Feed</button>
                                </div>

                                {broadcasts.length === 0 ? (
                                    <div className="bg-white rounded-3xl p-12 text-center border border-slate-100 shadow-sm">
                                        <Bell className="w-12 h-12 text-slate-300 mx-auto mb-4" />
                                        <h4 className="text-lg font-bold text-slate-800">No active job broadcasts</h4>
                                        <p className="text-slate-400 mt-1 max-w-sm mx-auto font-medium">New requests matching your specializations will appear here in real-time.</p>
                                    </div>
                                ) : (
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                        {broadcasts.map((job) => (
                                            <div key={job._id} className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm relative overflow-hidden flex flex-col justify-between">
                                                <div>
                                                    <div className="flex justify-between items-start gap-4">
                                                        <span className="bg-indigo-50 text-indigo-600 px-3 py-1 rounded-full text-xs font-black uppercase tracking-wider">
                                                            {job.serviceName}
                                                        </span>
                                                        <span className="text-2xl font-black text-slate-900">₹{job.freelancerPayout}</span>
                                                    </div>
                                                    <h4 className="text-lg font-black text-slate-900 mt-4">{job.packageName}</h4>
                                                    <p className="text-xs text-slate-400 font-bold uppercase tracking-tight mt-1">Broadcasted: {new Date(job.createdAt).toLocaleDateString()}</p>
                                                </div>

                                                <button 
                                                    onClick={() => handleClaimJob(job._id)}
                                                    className="w-full h-12 bg-slate-900 hover:bg-slate-800 text-white font-black rounded-xl mt-6 transition flex items-center justify-center gap-2"
                                                >
                                                    Accept Job Request <ArrowUpRight className="w-4 h-4 text-red-500" />
                                                </button>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}

                        {/* TAB 3: MY ORDERS */}
                        {activeTab === 'My Orders' && (
                            <div className="space-y-6">
                                <h3 className="text-xl font-black text-slate-900">Active Order Workspace</h3>
                                {orders.length === 0 ? (
                                    <div className="bg-white rounded-3xl p-12 text-center border border-slate-100 shadow-sm">
                                        <Briefcase className="w-12 h-12 text-slate-300 mx-auto mb-4" />
                                        <h4 className="text-lg font-bold text-slate-800">No claimed orders yet</h4>
                                        <p className="text-slate-400 mt-1 max-w-sm mx-auto font-medium">Accept active broadcasts from the "Available Jobs" panel to start earning.</p>
                                    </div>
                                ) : (
                                    <div className="grid md:grid-cols-3 gap-8 items-start">
                                        {/* Left col: list of orders */}
                                        <div className="md:col-span-1 space-y-4">
                                            {orders.map((o) => (
                                                <div 
                                                    key={o._id} 
                                                    onClick={() => setSelectedOrder(o)}
                                                    className={`p-5 rounded-2xl border cursor-pointer transition-all ${selectedOrder?._id === o._id ? 'bg-slate-900 border-slate-900 text-white shadow-xl' : 'bg-white border-slate-100 text-slate-900 hover:bg-slate-50'}`}
                                                >
                                                    <div className="flex justify-between items-start">
                                                        <span className={`text-[10px] px-2 py-0.5 rounded-full font-black uppercase tracking-wider ${selectedOrder?._id === o._id ? 'bg-white/10 text-white' : 'bg-red-50 text-red-600'}`}>
                                                            {o.status}
                                                        </span>
                                                        <span className="font-bold text-sm">₹{o.freelancerPayout}</span>
                                                    </div>
                                                    <h4 className="font-black text-base mt-3 truncate">{o.packageName}</h4>
                                                    <p className={`text-xs mt-1 ${selectedOrder?._id === o._id ? 'text-white/60' : 'text-slate-400'} font-bold`}>{o.serviceName}</p>
                                                </div>
                                            ))}
                                        </div>

                                        {/* Right col: details of selected order */}
                                        <div className="md:col-span-2">
                                            {selectedOrder ? (
                                                <div className="bg-white rounded-3xl p-8 border border-slate-100 shadow-sm space-y-6">
                                                    <div className="flex justify-between items-start border-b border-slate-100 pb-4">
                                                        <div>
                                                            <h3 className="text-xl font-black text-slate-900">{selectedOrder.packageName}</h3>
                                                            <p className="text-sm text-slate-400 font-bold mt-1">{selectedOrder.serviceName}</p>
                                                        </div>
                                                        <div className="text-right">
                                                            <p className="text-xs text-slate-400 font-black uppercase tracking-widest">Payout</p>
                                                            <p className="text-2xl font-black text-slate-900">₹{selectedOrder.freelancerPayout}</p>
                                                        </div>
                                                    </div>

                                                    {/* Work Timer section */}
                                                    <div className="bg-slate-50 p-6 rounded-2xl border border-slate-100 flex flex-col sm:flex-row justify-between items-center gap-4">
                                                        <div className="flex items-center gap-3">
                                                            <Clock className="w-6 h-6 text-slate-400" />
                                                            <div>
                                                                <h4 className="font-bold text-slate-800 text-sm">Task Time Clocking</h4>
                                                                <p className="text-xs text-slate-400 font-medium">Record hours spent working on this order.</p>
                                                            </div>
                                                        </div>
                                                        <div>
                                                            {liveClockedIn && activeOrderId === selectedOrder._id ? (
                                                                <button 
                                                                    onClick={() => handleClockOut(selectedOrder._id)}
                                                                    className="px-6 py-2.5 bg-red-600 text-white font-bold rounded-xl text-xs hover:bg-red-700 transition flex items-center gap-2 shadow-sm shadow-red-100"
                                                                >
                                                                    <Square className="w-4 h-4 fill-white" /> Stop Clock
                                                                </button>
                                                            ) : (
                                                                <button 
                                                                    onClick={() => handleClockIn(selectedOrder._id)}
                                                                    disabled={liveClockedIn}
                                                                    className={`px-6 py-2.5 bg-slate-900 text-white font-bold rounded-xl text-xs hover:bg-slate-800 transition flex items-center gap-2 shadow-sm ${liveClockedIn ? 'opacity-40 cursor-not-allowed' : ''}`}
                                                                >
                                                                    <Play className="w-4 h-4 fill-white" /> Start Clock
                                                                </button>
                                                            )}
                                                        </div>
                                                    </div>

                                                    {/* Client requirements list */}
                                                    <div>
                                                        <h4 className="font-black text-slate-900 mb-3 text-sm">Customer Requirements</h4>
                                                        {selectedOrder.customerRequirements?.length === 0 ? (
                                                            <p className="text-xs text-slate-400 font-bold">No documentation checklist imported yet.</p>
                                                        ) : (
                                                            <div className="space-y-3">
                                                                {selectedOrder.customerRequirements.map((req, idx) => (
                                                                    <div key={idx} className="flex justify-between items-center p-3.5 bg-slate-50 rounded-xl border border-slate-100 text-xs">
                                                                        <div>
                                                                            <p className="font-bold text-slate-800">{req.title}</p>
                                                                            <p className="text-[10px] text-slate-400 mt-0.5">{req.description || 'No notes'}</p>
                                                                        </div>
                                                                        <span className={`px-2.5 py-1 rounded-full font-black uppercase tracking-wider text-[9px] ${req.status === 'Verified' ? 'bg-green-100 text-green-700' : req.status === 'Received' ? 'bg-indigo-100 text-indigo-700' : 'bg-yellow-100 text-yellow-700'}`}>
                                                                            {req.status}
                                                                        </span>
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        )}
                                                    </div>

                                                    {/* Final Deliverables Submission */}
                                                    <div className="pt-4 border-t border-slate-100">
                                                        <h4 className="font-black text-slate-900 mb-3 text-sm">Submit Deliverables</h4>
                                                        <p className="text-xs text-slate-400 leading-relaxed font-medium">Use the chat panel or upload deliverables for validation. Once finished, checker/admin will verify, lock total billing logs, and approve payment.</p>
                                                    </div>
                                                </div>
                                            ) : (
                                                <div className="bg-white rounded-3xl p-12 text-center border border-slate-100 shadow-sm">
                                                    <FileText className="w-12 h-12 text-slate-300 mx-auto mb-4" />
                                                    <h4 className="text-lg font-bold text-slate-800">Select an order</h4>
                                                    <p className="text-slate-400 mt-1 max-w-sm mx-auto font-medium">Select one of your claimed active orders from the sidebar to view requirements, log hours, and submit deliverables.</p>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* TAB 4: EARNINGS LEDGER */}
                        {activeTab === 'Earnings Ledger' && (
                            <div className="space-y-6">
                                <div className="bg-white rounded-3xl p-8 border border-slate-100 shadow-sm">
                                    <h3 className="text-xl font-black text-slate-900 mb-6">Payment Ledger History</h3>
                                    
                                    {ledger.length === 0 ? (
                                        <div className="text-center py-12">
                                            <DollarSign className="w-12 h-12 text-slate-300 mx-auto mb-4" />
                                            <h4 className="text-lg font-bold text-slate-800">No transactions recorded</h4>
                                            <p className="text-slate-400 mt-1 font-medium">Approved earnings and payout checks will appear here in chronological order.</p>
                                        </div>
                                    ) : (
                                        <div className="overflow-x-auto">
                                            <table className="w-full text-left border-collapse text-xs font-semibold text-slate-600">
                                                <thead>
                                                    <tr className="border-b border-slate-100 text-[10px] uppercase text-slate-400 tracking-wider">
                                                        <th className="py-4 px-4 font-black">Order ID</th>
                                                        <th className="py-4 px-4 font-black">Service Category</th>
                                                        <th className="py-4 px-4 font-black">Amount</th>
                                                        <th className="py-4 px-4 font-black">Status</th>
                                                        <th className="py-4 px-4 font-black">Date</th>
                                                        <th className="py-4 px-4 font-black">Reference ID</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {ledger.map((payout) => (
                                                        <tr key={payout._id} className="border-b border-slate-50 hover:bg-slate-50/50 transition">
                                                            <td className="py-4 px-4 font-bold text-slate-950">{payout.order?.packageName || 'N/A'}</td>
                                                            <td className="py-4 px-4">{payout.order?.serviceName || 'N/A'}</td>
                                                            <td className="py-4 px-4 font-bold text-slate-950">₹{payout.amount}</td>
                                                            <td className="py-4 px-4">
                                                                <span className={`px-2.5 py-1 rounded-full font-black uppercase tracking-wider text-[9px] ${payout.status === 'Paid' ? 'bg-green-50 text-green-700 border border-green-100' : payout.status === 'Approved' ? 'bg-indigo-50 text-indigo-700 border border-indigo-100' : 'bg-yellow-50 text-yellow-700 border border-yellow-100'}`}>
                                                                    {payout.status}
                                                                </span>
                                                            </td>
                                                            <td className="py-4 px-4">{new Date(payout.createdAt).toLocaleDateString()}</td>
                                                            <td className="py-4 px-4">
                                                                {payout.status === 'Paid' ? (
                                                                    <div className="font-mono text-[10px] text-slate-500 uppercase">
                                                                        {payout.method} - {payout.transactionRef || 'N/A'}
                                                                    </div>
                                                                ) : (
                                                                    <span className="text-slate-400">Processing...</span>
                                                                )}
                                                            </td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </main>
        </div>
    );
};

export default FreelancerDashboard;
