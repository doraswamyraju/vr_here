import React, { useState, useEffect } from 'react';
import axios from 'axios';

const NoticeBoard = () => {
    const [notices, setNotices] = useState([]);
    const [holidays, setHolidays] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchBulletins = async () => {
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
                console.error('Error fetching notices & holidays:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchBulletins();
    }, []);

    if (loading) {
        return <div className="py-20 text-center text-slate-400">Loading notices & holidays...</div>;
    }

    return (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 animate-fade-in">
            {/* Notice Board Feed (2 columns) */}
            <div className="lg:col-span-2 space-y-6">
                <h4 className="text-lg font-bold text-slate-800 flex items-center gap-2">
                    <span className="w-2.5 h-6 bg-indigo-500 rounded-full inline-block"></span>
                    Announcements & Notices
                </h4>

                {notices.length === 0 ? (
                    <div className="py-20 text-center text-slate-400 bg-white border border-slate-100 rounded-2xl shadow-sm">
                        No notices published.
                    </div>
                ) : (
                    <div className="space-y-4">
                        {notices.map((n) => (
                            <div 
                                key={n._id} 
                                className={`bg-white rounded-2xl border p-5 shadow-sm hover:shadow-md transition duration-200 ${
                                    n.priority === 'High' ? 'border-l-4 border-l-rose-500 border-slate-100' :
                                    n.priority === 'Medium' ? 'border-l-4 border-l-amber-500 border-slate-100' :
                                    'border-l-4 border-l-slate-400 border-slate-100'
                                }`}
                            >
                                <div className="flex justify-between items-start gap-3">
                                    <div>
                                        <div className="flex items-center gap-2">
                                            <h5 className="font-bold text-slate-800 text-sm">{n.title}</h5>
                                            <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold ${
                                                n.priority === 'High' ? 'bg-rose-50 text-rose-600' :
                                                n.priority === 'Medium' ? 'bg-amber-50 text-amber-600' : 'bg-slate-50 text-slate-600'
                                            }`}>
                                                {n.priority}
                                            </span>
                                        </div>
                                        <p className="text-[10px] text-slate-400 mt-1">
                                            By {n.issuedBy?.name} on {new Date(n.createdAt).toLocaleDateString()}
                                        </p>
                                    </div>
                                </div>
                                <p className="text-slate-600 text-sm mt-3 border-t border-slate-50 pt-3 leading-relaxed whitespace-pre-line">
                                    {n.message}
                                </p>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Holiday Calendar Sidebar (1 column) */}
            <div className="lg:col-span-1 space-y-6">
                <h4 className="text-lg font-bold text-slate-800 flex items-center gap-2">
                    <span className="w-2.5 h-6 bg-purple-500 rounded-full inline-block"></span>
                    Holiday Calendar
                </h4>

                {holidays.length === 0 ? (
                    <div className="py-20 text-center text-slate-400 bg-white border border-slate-100 rounded-2xl shadow-sm">
                        No upcoming holidays.
                    </div>
                ) : (
                    <div className="bg-white rounded-2xl border border-slate-100 shadow-md p-5 space-y-4">
                        {holidays.map((h) => (
                            <div key={h._id} className="flex gap-4 items-start pb-4 last:pb-0 border-b border-slate-50 last:border-b-0">
                                <div className="bg-indigo-50 border border-indigo-100 rounded-xl p-3 flex flex-col items-center justify-center min-w-[3.5rem]">
                                    <span className="text-[10px] font-bold uppercase tracking-wider text-indigo-400">
                                        {new Date(h.date).toLocaleDateString('en-US', { month: 'short' })}
                                    </span>
                                    <span className="text-xl font-black text-indigo-600 mt-0.5">
                                        {new Date(h.date).toLocaleDateString('en-US', { day: 'numeric' })}
                                    </span>
                                </div>
                                <div>
                                    <h5 className="font-bold text-slate-800 text-sm">{h.title}</h5>
                                    <p className="text-xs text-slate-500 mt-1 leading-normal">{h.description || 'Company holiday'}</p>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
};

export default NoticeBoard;
