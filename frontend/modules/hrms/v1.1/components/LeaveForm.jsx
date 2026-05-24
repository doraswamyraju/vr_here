import React, { useState, useEffect } from 'react';
import axios from 'axios';

const LeaveForm = () => {
    const [startDate, setStartDate] = useState('');
    const [endDate, setEndDate] = useState('');
    const [type, setType] = useState('Casual');
    const [reason, setReason] = useState('');
    const [myLeaves, setMyLeaves] = useState([]);
    const [loading, setLoading] = useState(false);
    const [fetchLoading, setFetchLoading] = useState(true);
    const [message, setMessage] = useState({ text: '', type: '' });

    const fetchMyLeaves = async () => {
        try {
            const token = localStorage.getItem('token');
            const { data } = await axios.get('/api/hrms/leaves/my', {
                headers: { Authorization: `Bearer ${token}` }
            });
            setMyLeaves(data);
        } catch (error) {
            console.error('Error fetching leaves:', error);
        } finally {
            setFetchLoading(false);
        }
    };

    useEffect(() => {
        fetchMyLeaves();
    }, []);

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!startDate || !endDate || !reason) {
            setMessage({ text: 'Please fill in all fields', type: 'error' });
            return;
        }

        setLoading(true);
        setMessage({ text: '', type: '' });

        try {
            const token = localStorage.getItem('token');
            await axios.post('/api/hrms/leaves', {
                startDate,
                endDate,
                type,
                reason
            }, {
                headers: { Authorization: `Bearer ${token}` }
            });

            setMessage({ text: 'Leave application submitted successfully! Admins have been notified.', type: 'success' });
            setStartDate('');
            setEndDate('');
            setReason('');
            fetchMyLeaves();
        } catch (error) {
            const errMsg = error.response?.data?.message || 'Failed to submit leave request';
            setMessage({ text: errMsg, type: 'error' });
        } finally {
            setLoading(false);
        }
    };

    // Quick stats
    const approvedCount = myLeaves.filter(l => l.status === 'Approved').length;
    const pendingCount = myLeaves.filter(l => l.status === 'Pending').length;

    return (
        <div className="space-y-8 animate-fade-in">
            {/* Top Cards Section */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-gradient-to-br from-indigo-500 to-purple-600 rounded-2xl p-6 text-white shadow-xl transform transition hover:scale-[1.02] duration-300">
                    <span className="text-indigo-100 text-sm font-semibold uppercase tracking-wider">Total Applied</span>
                    <h3 className="text-4xl font-extrabold mt-2">{myLeaves.length}</h3>
                    <div className="mt-4 text-indigo-200 text-xs">Total leave requests requested</div>
                </div>

                <div className="bg-white rounded-2xl p-6 border border-slate-100 shadow-lg shadow-slate-100/50 transform transition hover:scale-[1.02] duration-300">
                    <span className="text-slate-400 text-sm font-semibold uppercase tracking-wider">Approved Leaves</span>
                    <h3 className="text-4xl font-extrabold text-emerald-500 mt-2">{approvedCount}</h3>
                    <div className="mt-4 text-slate-500 text-xs">Successfully verified by administration</div>
                </div>

                <div className="bg-white rounded-2xl p-6 border border-slate-100 shadow-lg shadow-slate-100/50 transform transition hover:scale-[1.02] duration-300">
                    <span className="text-slate-400 text-sm font-semibold uppercase tracking-wider">Pending Approvals</span>
                    <h3 className="text-4xl font-extrabold text-amber-500 mt-2">{pendingCount}</h3>
                    <div className="mt-4 text-slate-500 text-xs">Awaiting maker/checker validation</div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Form Section */}
                <div className="lg:col-span-1 bg-white rounded-2xl border border-slate-100 shadow-xl shadow-slate-100/30 p-6">
                    <h4 className="text-lg font-bold text-slate-800 mb-6 flex items-center gap-2">
                        <span className="w-2.5 h-6 bg-indigo-500 rounded-full inline-block"></span>
                        Request Leave
                    </h4>

                    {message.text && (
                        <div className={`p-4 rounded-xl text-sm mb-6 ${
                            message.type === 'success' 
                                ? 'bg-emerald-50 text-emerald-800 border border-emerald-100' 
                                : 'bg-rose-50 text-rose-800 border border-rose-100'
                        }`}>
                            {message.text}
                        </div>
                    )}

                    <form onSubmit={handleSubmit} className="space-y-5">
                        <div>
                            <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Leave Type</label>
                            <select
                                value={type}
                                onChange={(e) => setType(e.target.value)}
                                className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition duration-200"
                            >
                                <option value="Casual">Casual Leave</option>
                                <option value="Sick">Sick Leave</option>
                                <option value="Paid">Paid / Earned Leave</option>
                                <option value="Unpaid">Unpaid Leave</option>
                            </select>
                        </div>

                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Start Date</label>
                                <input
                                    type="date"
                                    value={startDate}
                                    onChange={(e) => setStartDate(e.target.value)}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition duration-200"
                                />
                            </div>
                            <div>
                                <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">End Date</label>
                                <input
                                    type="date"
                                    value={endDate}
                                    onChange={(e) => setEndDate(e.target.value)}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition duration-200"
                                />
                            </div>
                        </div>

                        <div>
                            <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Reason for Leave</label>
                            <textarea
                                value={reason}
                                onChange={(e) => setReason(e.target.value)}
                                rows="4"
                                placeholder="Explain reason briefly..."
                                className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition duration-200"
                            ></textarea>
                        </div>

                        <button
                            type="submit"
                            disabled={loading}
                            className="w-full bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl py-3.5 font-bold shadow-lg shadow-indigo-600/20 active:scale-[0.99] transition duration-150 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            {loading ? 'Submitting request...' : 'Submit Leave Request'}
                        </button>
                    </form>
                </div>

                {/* History Section */}
                <div className="lg:col-span-2 bg-white rounded-2xl border border-slate-100 shadow-xl shadow-slate-100/30 p-6 overflow-hidden">
                    <h4 className="text-lg font-bold text-slate-800 mb-6 flex items-center gap-2">
                        <span className="w-2.5 h-6 bg-purple-500 rounded-full inline-block"></span>
                        Leave History
                    </h4>

                    {fetchLoading ? (
                        <div className="py-20 text-center text-slate-400">Loading leave history...</div>
                    ) : myLeaves.length === 0 ? (
                        <div className="py-20 text-center text-slate-400 border-2 border-dashed border-slate-100 rounded-2xl">
                            No leave applications submitted yet.
                        </div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="w-full text-left border-collapse">
                                <thead>
                                    <tr className="border-b border-slate-100 text-xs font-bold text-slate-400 uppercase tracking-wider">
                                        <th className="pb-4">Type</th>
                                        <th className="pb-4">Dates</th>
                                        <th className="pb-4">Reason</th>
                                        <th className="pb-4">Status</th>
                                        <th className="pb-4">Admin Remarks</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-50 text-sm text-slate-600">
                                    {myLeaves.map((leave) => (
                                        <tr key={leave._id} className="hover:bg-slate-50/50 transition-colors duration-150">
                                            <td className="py-4 font-semibold text-slate-800">{leave.type}</td>
                                            <td className="py-4">
                                                <div className="font-semibold text-slate-700">
                                                    {new Date(leave.startDate).toLocaleDateString()}
                                                </div>
                                                <div className="text-xs text-slate-400">
                                                    to {new Date(leave.endDate).toLocaleDateString()}
                                                </div>
                                            </td>
                                            <td className="py-4 max-w-xs truncate" title={leave.reason}>{leave.reason}</td>
                                            <td className="py-4">
                                                <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-bold ${
                                                    leave.status === 'Approved' ? 'bg-emerald-50 text-emerald-700' :
                                                    leave.status === 'Rejected' ? 'bg-rose-50 text-rose-700' :
                                                    'bg-amber-50 text-amber-700'
                                                }`}>
                                                    {leave.status}
                                                </span>
                                            </td>
                                            <td className="py-4 text-xs italic text-slate-400 max-w-xs truncate" title={leave.adminNotes}>
                                                {leave.adminNotes || '—'}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default LeaveForm;
