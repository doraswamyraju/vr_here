import React, { useState, useEffect } from 'react';
import axios from 'axios';

const LeaveApprovals = () => {
    const [leaves, setLeaves] = useState([]);
    const [loading, setLoading] = useState(true);
    const [actionLoading, setActionLoading] = useState(null); // stores active leave ID being processed
    const [remarks, setRemarks] = useState({}); // stores remarks input per leave ID
    const [filter, setFilter] = useState('Pending'); // Pending, Approved, Rejected, All
    const [message, setMessage] = useState('');

    const fetchLeaves = async () => {
        try {
            const token = localStorage.getItem('token');
            const { data } = await axios.get('/api/hrms/leaves/admin', {
                headers: { Authorization: `Bearer ${token}` }
            });
            setLeaves(data);
        } catch (error) {
            console.error('Error fetching admin leaves:', error);
            setMessage('Failed to fetch leaves list');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchLeaves();
    }, []);

    const handleAction = async (id, status) => {
        setActionLoading(id);
        setMessage('');
        try {
            const token = localStorage.getItem('token');
            await axios.put(`/api/hrms/leaves/${id}/approve`, {
                status,
                adminNotes: remarks[id] || ''
            }, {
                headers: { Authorization: `Bearer ${token}` }
            });
            
            // Re-fetch leaves list to refresh UI
            await fetchLeaves();
            setRemarks(prev => ({ ...prev, [id]: '' }));
        } catch (error) {
            console.error('Error updating leave status:', error);
            setMessage(error.response?.data?.message || 'Action failed');
        } finally {
            setActionLoading(null);
        }
    };

    const handleRemarkChange = (id, val) => {
        setRemarks(prev => ({ ...prev, [id]: val }));
    };

    // Filter leaves
    const filteredLeaves = leaves.filter(leave => {
        if (filter === 'All') return true;
        return leave.status === filter;
    });

    return (
        <div className="space-y-6 animate-fade-in">
            {/* Header / Filter Toolbar */}
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center bg-white rounded-2xl p-5 border border-slate-100 shadow-md gap-4">
                <div>
                    <h4 className="text-lg font-bold text-slate-800">Leave Applications</h4>
                    <p className="text-xs text-slate-400">Review, approve, and validate employee leave requests</p>
                </div>

                <div className="flex bg-slate-50 border border-slate-200 rounded-xl p-1 text-sm font-semibold">
                    {['Pending', 'Approved', 'Rejected', 'All'].map((tab) => (
                        <button
                            key={tab}
                            onClick={() => setFilter(tab)}
                            className={`px-4 py-2 rounded-lg transition duration-200 ${
                                filter === tab 
                                    ? 'bg-white text-indigo-600 shadow-sm' 
                                    : 'text-slate-500 hover:text-slate-800'
                            }`}
                        >
                            {tab}
                        </button>
                    ))}
                </div>
            </div>

            {message && (
                <div className="p-4 rounded-xl text-sm bg-rose-50 text-rose-800 border border-rose-100">
                    {message}
                </div>
            )}

            {/* List / Cards */}
            {loading ? (
                <div className="py-20 text-center text-slate-400 bg-white rounded-2xl shadow-sm">Loading leave applications...</div>
            ) : filteredLeaves.length === 0 ? (
                <div className="py-20 text-center text-slate-400 bg-white border-2 border-dashed border-slate-100 rounded-2xl">
                    No leave requests found matching filter: <strong className="text-slate-600">{filter}</strong>.
                </div>
            ) : (
                <div className="grid grid-cols-1 gap-6">
                    {filteredLeaves.map((leave) => (
                        <div 
                            key={leave._id}
                            className={`bg-white rounded-2xl border p-6 shadow-md transition-all duration-300 hover:shadow-lg ${
                                leave.status === 'Pending' ? 'border-l-4 border-l-amber-500 border-slate-100' :
                                leave.status === 'Approved' ? 'border-l-4 border-l-emerald-500 border-slate-100' :
                                'border-l-4 border-l-rose-500 border-slate-100'
                            }`}
                        >
                            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-100 pb-4 mb-4">
                                <div className="flex items-center gap-4">
                                    <div className="w-12 h-12 rounded-full bg-slate-100 text-slate-800 font-extrabold flex items-center justify-center text-base">
                                        {leave.employee?.name?.charAt(0).toUpperCase()}
                                    </div>
                                    <div>
                                        <h5 className="font-bold text-slate-800 text-base">{leave.employee?.name || 'Unknown Staff'}</h5>
                                        <p className="text-xs text-slate-400">{leave.employee?.email} | Role: {leave.employee?.role}</p>
                                    </div>
                                </div>

                                <div className="flex flex-col items-start md:items-end">
                                    <span className="text-xs font-semibold text-slate-400">LEAVE INTERVAL</span>
                                    <div className="font-bold text-slate-700 text-sm mt-0.5">
                                        {new Date(leave.startDate).toLocaleDateString()} to {new Date(leave.endDate).toLocaleDateString()}
                                    </div>
                                </div>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                <div className="md:col-span-2 space-y-4">
                                    <div>
                                        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">Reason & Context</span>
                                        <p className="text-slate-600 text-sm mt-1 bg-slate-50/50 rounded-xl p-3 border border-slate-100">
                                            {leave.reason}
                                        </p>
                                    </div>

                                    {leave.status !== 'Pending' && (
                                        <div className="bg-slate-50 rounded-xl p-4 border border-slate-100 text-sm">
                                            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">Admin Remarks</span>
                                            <p className="text-slate-700 mt-1 italic">
                                                "{leave.adminNotes || 'No notes provided'}"
                                            </p>
                                        </div>
                                    )}
                                </div>

                                <div className="md:col-span-1 flex flex-col justify-end gap-3">
                                    {leave.status === 'Pending' ? (
                                        <div className="space-y-4">
                                            <div>
                                                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Remarks / Notes</label>
                                                <input
                                                    type="text"
                                                    placeholder="E.g., Approved based on replacement available"
                                                    value={remarks[leave._id] || ''}
                                                    onChange={(e) => handleRemarkChange(leave._id, e.target.value)}
                                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-2.5 text-slate-800 placeholder-slate-400 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                                />
                                            </div>

                                            <div className="grid grid-cols-2 gap-3">
                                                <button
                                                    onClick={() => handleAction(leave._id, 'Approved')}
                                                    disabled={actionLoading === leave._id}
                                                    className="bg-emerald-500 hover:bg-emerald-600 text-white rounded-xl py-2.5 text-sm font-bold shadow-md shadow-emerald-500/10 transition active:scale-[0.98] disabled:opacity-50"
                                                >
                                                    {actionLoading === leave._id ? 'Please wait...' : 'Approve'}
                                                </button>
                                                <button
                                                    onClick={() => handleAction(leave._id, 'Rejected')}
                                                    disabled={actionLoading === leave._id}
                                                    className="bg-rose-500 hover:bg-rose-600 text-white rounded-xl py-2.5 text-sm font-bold shadow-md shadow-rose-500/10 transition active:scale-[0.98] disabled:opacity-50"
                                                >
                                                    {actionLoading === leave._id ? 'Please wait...' : 'Reject'}
                                                </button>
                                            </div>
                                        </div>
                                    ) : (
                                        <div className="text-right">
                                            <span className={`inline-flex items-center px-4 py-1.5 rounded-full text-xs font-extrabold ${
                                                leave.status === 'Approved' ? 'bg-emerald-50 text-emerald-700 border border-emerald-100' :
                                                'bg-rose-50 text-rose-700 border border-rose-100'
                                            }`}>
                                                {leave.status}
                                            </span>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default LeaveApprovals;
