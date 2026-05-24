import React, { useState, useEffect } from 'react';
import axios from 'axios';

const LiveStatusDashboard = () => {
    const [liveData, setLiveData] = useState({ clockedIn: [], onLeave: [], offline: [] });
    const [loading, setLoading] = useState(true);
    const [message, setMessage] = useState('');

    const fetchLiveStatus = async () => {
        try {
            const token = localStorage.getItem('token');
            const { data } = await axios.get('/api/hrms/admin/live-status', {
                headers: { Authorization: `Bearer ${token}` }
            });
            setLiveData(data);
        } catch (error) {
            console.error('Error fetching live hrms status:', error);
            setMessage('Failed to load operational grid');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchLiveStatus();
        
        // Auto refresh every 30 seconds for live updates
        const interval = setInterval(fetchLiveStatus, 30000);
        return () => clearInterval(interval);
    }, []);

    if (loading) {
        return <div className="py-20 text-center text-slate-400 bg-white rounded-2xl border border-slate-100 shadow-sm">Loading live hrms grid...</div>;
    }

    return (
        <div className="space-y-8 animate-fade-in">
            {/* Header Control */}
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center bg-white rounded-2xl p-5 border border-slate-100 shadow-md gap-4">
                <div>
                    <h4 className="text-lg font-bold text-slate-800">Live Operational Status</h4>
                    <p className="text-xs text-slate-400">Real-time tracker of who is currently working, offline, or on leave today</p>
                </div>

                <button 
                    onClick={fetchLiveStatus}
                    className="flex items-center gap-2 bg-slate-50 border border-slate-200 hover:bg-slate-100 text-slate-700 text-xs px-4 py-2.5 rounded-xl font-bold transition active:scale-[0.98]"
                >
                    🔄 Force Sync
                </button>
            </div>

            {message && (
                <div className="p-4 rounded-xl text-sm bg-rose-50 text-rose-800 border border-rose-100">
                    {message}
                </div>
            )}

            {/* Quick Metrics */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
                <div className="bg-emerald-50 border border-emerald-100 rounded-2xl p-5 shadow-sm">
                    <span className="text-xs font-bold text-emerald-500 uppercase tracking-wider block">Active Working</span>
                    <h3 className="text-3xl font-black text-emerald-700 mt-1">{liveData.clockedIn.length}</h3>
                </div>
                <div className="bg-indigo-50 border border-indigo-100 rounded-2xl p-5 shadow-sm">
                    <span className="text-xs font-bold text-indigo-500 uppercase tracking-wider block">Approved Off/Leave</span>
                    <h3 className="text-3xl font-black text-indigo-700 mt-1">{liveData.onLeave.length}</h3>
                </div>
                <div className="bg-slate-50 border border-slate-200 rounded-2xl p-5 shadow-sm">
                    <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block">Offline / Clocked Out</span>
                    <h3 className="text-3xl font-black text-slate-700 mt-1">{liveData.offline.length}</h3>
                </div>
            </div>

            {/* Live Sections */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                
                {/* 1. CLOCKED IN SECTION */}
                <div className="bg-white rounded-2xl border border-slate-100 p-6 shadow-md shadow-slate-100/50 space-y-6">
                    <h5 className="font-bold text-slate-800 text-base flex items-center justify-between">
                        <span className="flex items-center gap-2">
                            <span className="w-3 h-3 bg-emerald-500 rounded-full animate-pulse inline-block"></span>
                            Clocked In ({liveData.clockedIn.length})
                        </span>
                    </h5>

                    {liveData.clockedIn.length === 0 ? (
                        <div className="py-12 text-center text-xs text-slate-400 border border-dashed border-slate-100 rounded-xl">
                            No active working sessions today
                        </div>
                    ) : (
                        <div className="space-y-4 max-h-[500px] overflow-y-auto pr-1">
                            {liveData.clockedIn.map(emp => (
                                <div key={emp._id} className="bg-emerald-50/20 border border-emerald-50/50 rounded-xl p-4 flex gap-4 items-center">
                                    <div className="w-10 h-10 rounded-full bg-emerald-100 text-emerald-800 font-black flex items-center justify-center text-sm">
                                        {emp.name.charAt(0).toUpperCase()}
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <h6 className="font-bold text-slate-800 text-sm truncate">{emp.name}</h6>
                                        <p className="text-[10px] text-slate-400 mt-0.5 truncate">{emp.email}</p>
                                        <div className="flex items-center gap-2 mt-2">
                                            <span className="text-[10px] bg-emerald-50 text-emerald-700 border border-emerald-100/50 px-2 py-0.5 rounded font-semibold">
                                                In: {new Date(emp.clockInAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                            </span>
                                            <span className="text-[10px] bg-slate-100 text-slate-500 px-2 py-0.5 rounded">
                                                {emp.source === 'employee-dashboard' ? '🖥️ Web' : '📱 App'}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* 2. ON LEAVE SECTION */}
                <div className="bg-white rounded-2xl border border-slate-100 p-6 shadow-md shadow-slate-100/50 space-y-6">
                    <h5 className="font-bold text-slate-800 text-base flex items-center gap-2">
                        <span className="w-3 h-3 bg-indigo-500 rounded-full inline-block"></span>
                        On Approved Leave ({liveData.onLeave.length})
                    </h5>

                    {liveData.onLeave.length === 0 ? (
                        <div className="py-12 text-center text-xs text-slate-400 border border-dashed border-slate-100 rounded-xl">
                            No approved leaves scheduled today
                        </div>
                    ) : (
                        <div className="space-y-4 max-h-[500px] overflow-y-auto pr-1">
                            {liveData.onLeave.map(emp => (
                                <div key={emp._id} className="bg-indigo-50/20 border border-indigo-50/50 rounded-xl p-4 flex gap-4 items-center">
                                    <div className="w-10 h-10 rounded-full bg-indigo-100 text-indigo-800 font-black flex items-center justify-center text-sm">
                                        {emp.name.charAt(0).toUpperCase()}
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <h6 className="font-bold text-slate-800 text-sm truncate">{emp.name}</h6>
                                        <p className="text-[10px] text-slate-400 mt-0.5 truncate">{emp.email}</p>
                                        <div className="mt-2">
                                            <span className="text-[10px] bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded font-bold">
                                                {emp.leaveType} Leave
                                            </span>
                                            <p className="text-[10px] text-slate-500 italic mt-1.5 truncate">
                                                "{emp.reason}"
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* 3. OFFLINE / CLOCKED OUT SECTION */}
                <div className="bg-white rounded-2xl border border-slate-100 p-6 shadow-md shadow-slate-100/50 space-y-6">
                    <h5 className="font-bold text-slate-800 text-base flex items-center gap-2">
                        <span className="w-3 h-3 bg-slate-400 rounded-full inline-block"></span>
                        Clocked Out / Offline ({liveData.offline.length})
                    </h5>

                    {liveData.offline.length === 0 ? (
                        <div className="py-12 text-center text-xs text-slate-400 border border-dashed border-slate-100 rounded-xl">
                            All staff are working or on leave!
                        </div>
                    ) : (
                        <div className="space-y-4 max-h-[500px] overflow-y-auto pr-1">
                            {liveData.offline.map(emp => (
                                <div key={emp._id} className="bg-slate-50 rounded-xl p-4 flex gap-4 items-center">
                                    <div className="w-10 h-10 rounded-full bg-slate-200 text-slate-600 font-black flex items-center justify-center text-sm">
                                        {emp.name.charAt(0).toUpperCase()}
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <h6 className="font-bold text-slate-700 text-sm truncate">{emp.name}</h6>
                                        <p className="text-[10px] text-slate-400 mt-0.5 truncate">{emp.email}</p>
                                        <div className="mt-2 text-[10px] text-slate-400 font-semibold flex items-center gap-1">
                                            ⚪ Offline (Not clocked-in)
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default LiveStatusDashboard;
