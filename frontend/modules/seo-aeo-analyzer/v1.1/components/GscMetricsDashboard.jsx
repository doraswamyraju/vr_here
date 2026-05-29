import React, { useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Globe, TrendingUp, BarChart2, CheckCircle2, RotateCw, AlertTriangle, Link } from 'lucide-react';
import axios from 'axios';

const GscMetricsDashboard = ({ pageId, config, onAuthRequest }) => {
    const [loading, setLoading] = useState(false);
    const [data, setData] = useState(null);
    const [error, setError] = useState('');

    const fetchGscPerformance = async () => {
        setLoading(true);
        setError('');
        try {
            const token = localStorage.getItem('token') || (JSON.parse(localStorage.getItem('userInfo'))?.token);
            const res = await axios.get(`/api/service-pages/${pageId}/gsc/performance`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setData(res.data);
        } catch (err) {
            console.error('Error fetching GSC data:', err);
            setError(err.response?.data?.message || 'Failed to pull Google Search Console statistics.');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (config && config.gscTokens && config.gscTokens.refreshToken) {
            fetchGscPerformance();
        }
    }, [pageId, config]);

    const isConnected = config?.gscTokens?.refreshToken;

    if (!isConnected) {
        return (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 text-center flex flex-col items-center justify-center space-y-6">
                <div className="w-16 h-16 bg-indigo-500/10 text-indigo-400 rounded-2xl flex items-center justify-center shadow-inner">
                    <Globe className="w-8 h-8" />
                </div>
                <div className="max-w-md">
                    <h3 className="text-lg font-black text-white leading-tight">Live Search Console Analytics</h3>
                    <p className="text-slate-400 text-xs mt-2 leading-relaxed font-semibold">
                        Pull organic traffic directly from Google. See live impressions, average Google keyword ranking position, and click-through rates for this specific service page.
                    </p>
                </div>
                <button
                    onClick={onAuthRequest}
                    className="bg-indigo-600 hover:bg-indigo-700 text-white font-bold text-xs uppercase tracking-wider py-3.5 px-6 rounded-xl shadow-lg shadow-indigo-600/25 active:scale-95 transform transition-all flex items-center justify-center gap-2"
                >
                    <Link className="w-4 h-4" />
                    <span>Connect Google Search Console</span>
                </button>
                <div className="text-[10px] text-slate-500 font-bold leading-normal">
                    Secure authorization. We only read data matching your own connected domains.
                </div>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center space-x-2 text-indigo-400">
                    <BarChart2 className="w-5 h-5" />
                    <h3 className="font-bold text-sm tracking-wide uppercase text-white font-black">Live Search Analytics</h3>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={fetchGscPerformance}
                        disabled={loading}
                        className="p-2 text-slate-400 hover:text-white bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg transition-all"
                        title="Reload live GSC metrics"
                    >
                        <RotateCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
                    </button>
                    <button
                        onClick={onAuthRequest}
                        className="text-[10px] uppercase font-black tracking-widest text-slate-400 hover:text-indigo-400 transition"
                    >
                        Reconnect Account
                    </button>
                </div>
            </div>

            {error && (
                <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-xl flex items-start gap-3 text-xs font-semibold">
                    <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                    <div>
                        <div className="font-bold">Google GSC Connection Alert</div>
                        <div className="text-[11px] font-medium leading-relaxed mt-1">{error}</div>
                    </div>
                </div>
            )}

            {loading && !data && (
                <div className="py-20 flex flex-col items-center justify-center space-y-4">
                    <RotateCw className="w-8 h-8 text-indigo-500 animate-spin" />
                    <span className="text-xs text-slate-400 font-bold tracking-widest uppercase">Fetching Google Search Metrics...</span>
                </div>
            )}

            {data && data.summary && (
                <div className="space-y-6 animate-fade-in">
                    {/* Performance Cards */}
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800/80">
                            <div className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Total Clicks</div>
                            <div className="text-2xl font-black text-white mt-1.5">{data.summary.totalClicks}</div>
                            <div className="text-[9px] text-slate-500 font-bold mt-1 uppercase">Past 30 Days</div>
                        </div>

                        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800/80">
                            <div className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Impressions</div>
                            <div className="text-2xl font-black text-white mt-1.5">{data.summary.totalImpressions}</div>
                            <div className="text-[9px] text-slate-500 font-bold mt-1 uppercase">SERP Views</div>
                        </div>

                        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800/80">
                            <div className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Average CTR</div>
                            <div className="text-2xl font-black text-emerald-400 mt-1.5">{(data.summary.avgCtr * 100).toFixed(2)}%</div>
                            <div className="text-[9px] text-slate-500 font-bold mt-1 uppercase">Click-through</div>
                        </div>

                        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800/80">
                            <div className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Avg Position</div>
                            <div className="text-2xl font-black text-indigo-400 mt-1.5">{data.summary.avgPosition.toFixed(1)}</div>
                            <div className="text-[9px] text-slate-500 font-bold mt-1 uppercase">Keyword rank</div>
                        </div>
                    </div>

                    {/* Chart trend */}
                    <div className="bg-slate-900/40 p-4 rounded-2xl border border-slate-800/80">
                        <div className="flex items-center justify-between mb-4 px-2">
                            <h4 className="text-xs font-black text-slate-300 uppercase tracking-widest">Daily Performance Timeline</h4>
                            <span className="text-[9px] uppercase tracking-wider font-bold bg-indigo-500/10 text-indigo-400 px-2 py-0.5 rounded">Organic Trends</span>
                        </div>
                        <div className="w-full h-56">
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={data.history} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                                    <defs>
                                        <linearGradient id="clicksGrad" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#818cf8" stopOpacity={0.4}/>
                                            <stop offset="95%" stopColor="#818cf8" stopOpacity={0}/>
                                        </linearGradient>
                                        <linearGradient id="impressionsGrad" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#34d399" stopOpacity={0.15}/>
                                            <stop offset="95%" stopColor="#34d399" stopOpacity={0}/>
                                        </linearGradient>
                                    </defs>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                                    <XAxis dataKey="date" stroke="#64748b" fontSize={9} tickLine={false} />
                                    <YAxis stroke="#64748b" fontSize={9} tickLine={false} />
                                    <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#f8fafc', fontSize: 11 }} />
                                    <Area type="monotone" dataKey="clicks" name="Clicks" stroke="#818cf8" strokeWidth={2} fillOpacity={1} fill="url(#clicksGrad)" />
                                    <Area type="monotone" dataKey="impressions" name="Impressions" stroke="#34d399" strokeWidth={1.5} fillOpacity={1} fill="url(#impressionsGrad)" />
                                </AreaChart>
                            </ResponsiveContainer>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default GscMetricsDashboard;
