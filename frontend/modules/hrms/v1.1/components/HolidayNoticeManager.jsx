import React, { useState, useEffect } from 'react';
import axios from 'axios';

const HolidayNoticeManager = () => {
    const [subTab, setSubTab] = useState('notices'); // notices | holidays
    
    // Notice states
    const [noticeTitle, setNoticeTitle] = useState('');
    const [noticeMsg, setNoticeMsg] = useState('');
    const [noticePriority, setNoticePriority] = useState('Medium');
    const [notices, setNotices] = useState([]);
    
    // Holiday states
    const [holidayTitle, setHolidayTitle] = useState('');
    const [holidayDate, setHolidayDate] = useState('');
    const [holidayDesc, setHolidayDesc] = useState('');
    const [holidays, setHolidays] = useState([]);

    const [loading, setLoading] = useState(false);
    const [fetchLoading, setFetchLoading] = useState(true);
    const [feedback, setFeedback] = useState({ text: '', type: '' });

    const fetchAll = async () => {
        setFetchLoading(true);
        try {
            const token = localStorage.getItem('token');
            const hRes = await axios.get('/api/hrms/holidays', {
                headers: { Authorization: `Bearer ${token}` }
            });
            const nRes = await axios.get('/api/hrms/notices', {
                headers: { Authorization: `Bearer ${token}` }
            });
            setHolidays(hRes.data);
            setNotices(nRes.data);
        } catch (error) {
            console.error('Error fetching bulletins:', error);
        } finally {
            setFetchLoading(false);
        }
    };

    useEffect(() => {
        fetchAll();
    }, []);

    const showFeedback = (text, type) => {
        setFeedback({ text, type });
        setTimeout(() => setFeedback({ text: '', type: '' }), 5000);
    };

    const handleCreateNotice = async (e) => {
        e.preventDefault();
        if (!noticeTitle || !noticeMsg) {
            showFeedback('Notice Title and Message are required', 'error');
            return;
        }
        setLoading(true);
        try {
            const token = localStorage.getItem('token');
            await axios.post('/api/hrms/notices', {
                title: noticeTitle,
                message: noticeMsg,
                priority: noticePriority
            }, {
                headers: { Authorization: `Bearer ${token}` }
            });
            showFeedback('Notice board post published! All staff have been alerted via push notification.', 'success');
            setNoticeTitle('');
            setNoticeMsg('');
            setNoticePriority('Medium');
            fetchAll();
        } catch (error) {
            showFeedback(error.response?.data?.message || 'Failed to create notice', 'error');
        } finally {
            setLoading(false);
        }
    };

    const handleCreateHoliday = async (e) => {
        e.preventDefault();
        if (!holidayTitle || !holidayDate) {
            showFeedback('Holiday Title and Date are required', 'error');
            return;
        }
        setLoading(true);
        try {
            const token = localStorage.getItem('token');
            await axios.post('/api/hrms/holidays', {
                title: holidayTitle,
                date: holidayDate,
                description: holidayDesc
            }, {
                headers: { Authorization: `Bearer ${token}` }
            });
            showFeedback('Company holiday registered successfully and broadcasted!', 'success');
            setHolidayTitle('');
            setHolidayDate('');
            setHolidayDesc('');
            fetchAll();
        } catch (error) {
            showFeedback(error.response?.data?.message || 'Failed to create holiday', 'error');
        } finally {
            setLoading(false);
        }
    };

    const handleDeleteNotice = async (id) => {
        if (!window.confirm('Delete this notice?')) return;
        try {
            const token = localStorage.getItem('token');
            await axios.delete(`/api/hrms/notices/${id}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            showFeedback('Notice deleted successfully', 'success');
            fetchAll();
        } catch (error) {
            showFeedback('Failed to delete notice', 'error');
        }
    };

    const handleDeleteHoliday = async (id) => {
        if (!window.confirm('Delete this holiday?')) return;
        try {
            const token = localStorage.getItem('token');
            await axios.delete(`/api/hrms/holidays/${id}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            showFeedback('Holiday removed successfully', 'success');
            fetchAll();
        } catch (error) {
            showFeedback('Failed to delete holiday', 'error');
        }
    };

    return (
        <div className="space-y-6 animate-fade-in">
            {/* Header Control */}
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center bg-white rounded-2xl p-5 border border-slate-100 shadow-md gap-4">
                <div>
                    <h4 className="text-lg font-bold text-slate-800">Company Announcements</h4>
                    <p className="text-xs text-slate-400">Issue notices, internal memos, and register company holidays</p>
                </div>

                <div className="flex bg-slate-50 border border-slate-200 rounded-xl p-1 text-sm font-semibold">
                    <button
                        onClick={() => setSubTab('notices')}
                        className={`px-4 py-2 rounded-lg transition duration-200 ${
                            subTab === 'notices' ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-500 hover:text-slate-800'
                        }`}
                    >
                        Notice Board
                    </button>
                    <button
                        onClick={() => setSubTab('holidays')}
                        className={`px-4 py-2 rounded-lg transition duration-200 ${
                            subTab === 'holidays' ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-500 hover:text-slate-800'
                        }`}
                    >
                        Holidays Registry
                    </button>
                </div>
            </div>

            {feedback.text && (
                <div className={`p-4 rounded-xl text-sm border ${
                    feedback.type === 'success' ? 'bg-emerald-50 text-emerald-800 border-emerald-100' : 'bg-rose-50 text-rose-800 border-rose-100'
                }`}>
                    {feedback.text}
                </div>
            )}

            {/* Split Creator View */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div className="lg:col-span-1 bg-white rounded-2xl border border-slate-100 shadow-xl shadow-slate-100/30 p-6 h-fit">
                    {subTab === 'notices' ? (
                        <form onSubmit={handleCreateNotice} className="space-y-5">
                            <h5 className="text-base font-bold text-slate-800 flex items-center gap-2 mb-4">
                                <span className="w-2.5 h-6 bg-indigo-500 rounded-full inline-block"></span>
                                Publish Notice
                            </h5>
                            
                            <div>
                                <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Notice Title</label>
                                <input
                                    type="text"
                                    placeholder="Enter headline..."
                                    value={noticeTitle}
                                    onChange={(e) => setNoticeTitle(e.target.value)}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-800 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Priority Level</label>
                                <select
                                    value={noticePriority}
                                    onChange={(e) => setNoticePriority(e.target.value)}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-800 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                >
                                    <option value="Low">Low Alert</option>
                                    <option value="Medium">Medium Bulletin</option>
                                    <option value="High">🚨 High Priority Alert</option>
                                </select>
                            </div>

                            <div>
                                <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Announcement Message</label>
                                <textarea
                                    rows="5"
                                    placeholder="Write memo content..."
                                    value={noticeMsg}
                                    onChange={(e) => setNoticeMsg(e.target.value)}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-800 text-sm placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                ></textarea>
                            </div>

                            <button
                                type="submit"
                                disabled={loading}
                                className="w-full bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl py-3 text-sm font-bold shadow-lg shadow-indigo-600/10 active:scale-[0.98] transition"
                            >
                                {loading ? 'Publishing...' : 'Publish Announcement'}
                            </button>
                        </form>
                    ) : (
                        <form onSubmit={handleCreateHoliday} className="space-y-5">
                            <h5 className="text-base font-bold text-slate-800 flex items-center gap-2 mb-4">
                                <span className="w-2.5 h-6 bg-purple-500 rounded-full inline-block"></span>
                                Declare Holiday
                            </h5>

                            <div>
                                <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Holiday Title</label>
                                <input
                                    type="text"
                                    placeholder="E.g., Diwali, Independence Day"
                                    value={holidayTitle}
                                    onChange={(e) => setHolidayTitle(e.target.value)}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-800 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Holiday Date</label>
                                <input
                                    type="date"
                                    value={holidayDate}
                                    onChange={(e) => setHolidayDate(e.target.value)}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-800 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Brief Description</label>
                                <textarea
                                    rows="4"
                                    placeholder="Holiday note..."
                                    value={holidayDesc}
                                    onChange={(e) => setHolidayDesc(e.target.value)}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-800 text-sm placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                ></textarea>
                            </div>

                            <button
                                type="submit"
                                disabled={loading}
                                className="w-full bg-purple-600 hover:bg-purple-700 text-white rounded-xl py-3 text-sm font-bold shadow-lg shadow-purple-600/10 active:scale-[0.98] transition"
                            >
                                {loading ? 'Registering...' : 'Register Holiday'}
                            </button>
                        </form>
                    )}
                </div>

                <div className="lg:col-span-2 bg-white rounded-2xl border border-slate-100 shadow-xl shadow-slate-100/30 p-6 overflow-hidden">
                    <h5 className="text-base font-bold text-slate-800 flex items-center gap-2 mb-6">
                        <span className="w-2.5 h-6 bg-slate-300 rounded-full inline-block"></span>
                        Active List
                    </h5>

                    {fetchLoading ? (
                        <div className="py-20 text-center text-slate-400">Loading details...</div>
                    ) : subTab === 'notices' ? (
                        notices.length === 0 ? (
                            <div className="py-20 text-center text-slate-400 border-2 border-dashed border-slate-100 rounded-2xl">
                                No active announcements on the Notice Board.
                            </div>
                        ) : (
                            <div className="space-y-4">
                                {notices.map((n) => (
                                    <div key={n._id} className="border border-slate-100 rounded-2xl p-5 hover:bg-slate-50/50 transition duration-150 relative">
                                        <div className="flex justify-between items-start pr-8">
                                            <div>
                                                <div className="flex items-center gap-2">
                                                    <h6 className="font-bold text-slate-800 text-sm">{n.title}</h6>
                                                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold ${
                                                        n.priority === 'High' ? 'bg-rose-50 text-rose-600 border border-rose-100' :
                                                        n.priority === 'Medium' ? 'bg-amber-50 text-amber-600' : 'bg-slate-50 text-slate-600'
                                                    }`}>
                                                        {n.priority}
                                                    </span>
                                                </div>
                                                <p className="text-xs text-slate-400 mt-1">
                                                    Published by {n.issuedBy?.name || 'Admin'} on {new Date(n.createdAt).toLocaleDateString()}
                                                </p>
                                            </div>

                                            <button 
                                                onClick={() => handleDeleteNotice(n._id)}
                                                className="text-slate-300 hover:text-rose-500 absolute top-5 right-5 p-1 rounded-lg transition"
                                                title="Delete notice"
                                            >
                                                ✕
                                            </button>
                                        </div>
                                        <p className="text-slate-600 text-sm mt-3 border-t border-slate-50 pt-3 leading-relaxed whitespace-pre-line">{n.message}</p>
                                    </div>
                                ))}
                            </div>
                        )
                    ) : (
                        holidays.length === 0 ? (
                            <div className="py-20 text-center text-slate-400 border-2 border-dashed border-slate-100 rounded-2xl">
                                No holidays registered in system calendar.
                            </div>
                        ) : (
                            <div className="overflow-x-auto">
                                <table className="w-full text-left border-collapse">
                                    <thead>
                                        <tr className="border-b border-slate-100 text-xs font-bold text-slate-400 uppercase tracking-wider">
                                            <th className="pb-4">Date</th>
                                            <th className="pb-4">Occasion</th>
                                            <th className="pb-4">Description</th>
                                            <th className="pb-4 text-right">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-50 text-sm text-slate-600">
                                        {holidays.map((h) => (
                                            <tr key={h._id} className="hover:bg-slate-50/50 transition-colors duration-150">
                                                <td className="py-4 font-bold text-slate-800">
                                                    {new Date(h.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
                                                </td>
                                                <td className="py-4 font-semibold text-indigo-600">{h.title}</td>
                                                <td className="py-4 max-w-xs truncate" title={h.description}>{h.description || '—'}</td>
                                                <td className="py-4 text-right">
                                                    <button
                                                        onClick={() => handleDeleteHoliday(h._id)}
                                                        className="text-slate-300 hover:text-rose-500 font-bold px-2 py-1 rounded transition"
                                                        title="Delete Holiday"
                                                    >
                                                        ✕
                                                    </button>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )
                    )}
                </div>
            </div>
        </div>
    );
};

export default HolidayNoticeManager;
