import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import { 
  Users, Calendar, Clock, BarChart3, ChevronRight, 
  Search, Filter, ArrowLeft, Download, ExternalLink,
  Briefcase, Activity, Target, AlertCircle
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
  AreaChart,
  Area
} from 'recharts';

const getDateKey = (date = new Date()) => {
  const d = new Date(date);
  return d.toISOString().split('T')[0];
};

const EmployeeAnalysisModule = ({ token, users }) => {
  const [selectedId, setSelectedId] = useState('');
  const [dateRange, setDateRange] = useState({
    from: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
    to: new Date().toISOString().split('T')[0]
  });
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const employees = useMemo(() => users.filter(u => u.role === 'employee' || u.role === 'admin'), [users]);

  const config = useMemo(() => ({ headers: { Authorization: `Bearer ${token}` } }), [token]);

  const fetchAnalysis = async () => {
    if (!selectedId) return;
    setLoading(true);
    setError('');
    try {
      const { data } = await axios.get(`/api/attendance/admin/employee/${selectedId}?from=${dateRange.from}&to=${dateRange.to}`, config);
      setData(data);
    } catch (err) {
      setError('Failed to fetch detailed analysis');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedId) fetchAnalysis();
  }, [selectedId, dateRange]);

  const formatMinutes = (m) => {
    const h = Math.floor(m / 60);
    const mins = m % 60;
    return h > 0 ? `${h}h ${mins}m` : `${mins}m`;
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      {/* Selection Header */}
      <div className="bg-white rounded-[32px] p-8 shadow-sm border border-slate-100">
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6">
          <div className="flex-1 space-y-4">
            <div>
              <h2 className="text-2xl font-black text-slate-800 tracking-tight">Worksheet & Performance Analysis</h2>
              <p className="text-slate-500 text-sm font-medium mt-1">Deep dive into employee time tracking, productivity, and task completion.</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="space-y-1.5">
                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Select Employee</label>
                <div className="relative">
                  <Users className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                  <select 
                    value={selectedId} 
                    onChange={(e) => setSelectedId(e.target.value)}
                    className="w-full pl-11 pr-4 py-3 rounded-2xl bg-slate-50 border-2 border-transparent focus:border-indigo-500 focus:bg-white outline-none transition-all font-bold text-sm"
                  >
                    <option value="">Select Employee...</option>
                    {employees.map(e => <option key={e._id} value={e._id}>{e.name} ({e.role})</option>)}
                  </select>
                </div>
              </div>
              <div className="space-y-1.5">
                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">From Date</label>
                <div className="relative">
                  <Calendar className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                  <input 
                    type="date" 
                    value={dateRange.from}
                    onChange={(e) => setDateRange({...dateRange, from: e.target.value})}
                    className="w-full pl-11 pr-4 py-3 rounded-2xl bg-slate-50 border-2 border-transparent focus:border-indigo-500 focus:bg-white outline-none transition-all font-bold text-sm"
                  />
                </div>
              </div>
              <div className="space-y-1.5">
                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">To Date</label>
                <div className="relative">
                  <Calendar className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                  <input 
                    type="date" 
                    value={dateRange.to}
                    onChange={(e) => setDateRange({...dateRange, to: e.target.value})}
                    className="w-full pl-11 pr-4 py-3 rounded-2xl bg-slate-50 border-2 border-transparent focus:border-indigo-500 focus:bg-white outline-none transition-all font-bold text-sm"
                  />
                </div>
              </div>
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={fetchAnalysis} className="px-6 py-3.5 bg-indigo-600 text-white rounded-2xl font-black text-sm shadow-lg shadow-indigo-200 hover:bg-indigo-700 active:scale-95 transition-all">
              Update View
            </button>
          </div>
        </div>
      </div>

      {!selectedId && (
        <div className="bg-white rounded-[32px] p-20 text-center border border-slate-100 shadow-sm">
          <div className="w-20 h-20 bg-indigo-50 rounded-full flex items-center justify-center mx-auto mb-6 text-indigo-500">
            <BarChart3 size={40} />
          </div>
          <h3 className="text-xl font-black text-slate-800">No Employee Selected</h3>
          <p className="text-slate-500 max-w-xs mx-auto mt-2">Please select an employee and date range to view their worksheet and time analysis.</p>
        </div>
      )}

      {loading && (
        <div className="bg-white rounded-[32px] p-20 text-center border border-slate-100 shadow-sm animate-pulse">
          <Activity className="w-12 h-12 text-indigo-500 animate-spin mx-auto mb-4" />
          <p className="font-bold text-slate-600 uppercase tracking-widest text-xs">Generating Analysis...</p>
        </div>
      )}

      {data && !loading && (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm group hover:border-indigo-200 transition-colors">
              <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1">Total Worked</p>
              <div className="flex items-center justify-between">
                <h4 className="text-2xl font-black text-slate-800">{formatMinutes(data.totalWorkedMinutes)}</h4>
                <div className="w-10 h-10 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center">
                  <Clock size={20} />
                </div>
              </div>
              <p className="text-[10px] text-slate-500 mt-2 font-bold uppercase">{data.sessionsCount} Clock-in Sessions</p>
            </div>
            <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm group hover:border-emerald-200 transition-colors">
              <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1">Total Tracked</p>
              <div className="flex items-center justify-between">
                <h4 className="text-2xl font-black text-emerald-600">{formatMinutes(data.totalTrackedMinutes)}</h4>
                <div className="w-10 h-10 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center">
                  <Activity size={20} />
                </div>
              </div>
              <p className="text-[10px] text-slate-500 mt-2 font-bold uppercase">{data.logsCount} Worksheet Entries</p>
            </div>
            <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm group hover:border-indigo-200 transition-colors">
              <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1">Productivity</p>
              <div className="flex items-center justify-between">
                <h4 className="text-2xl font-black text-indigo-600">
                  {data.totalWorkedMinutes > 0 ? Math.round((data.totalTrackedMinutes / data.totalWorkedMinutes) * 100) : 0}%
                </h4>
                <div className="w-10 h-10 rounded-xl bg-indigo-50 text-indigo-600 flex items-center justify-center">
                  <Target size={20} />
                </div>
              </div>
              <p className="text-[10px] text-slate-500 mt-2 font-bold uppercase">Time Utilization Ratio</p>
            </div>
            <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm group hover:border-amber-200 transition-colors">
              <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1">Untracked Gap</p>
              <div className="flex items-center justify-between">
                <h4 className="text-2xl font-black text-amber-600">
                  {formatMinutes(Math.max(0, data.totalWorkedMinutes - data.totalTrackedMinutes))}
                </h4>
                <div className="w-10 h-10 rounded-xl bg-amber-50 text-amber-600 flex items-center justify-center">
                  <AlertCircle size={20} />
                </div>
              </div>
              <p className="text-[10px] text-slate-500 mt-2 font-bold uppercase">Unallocated Worked Time</p>
            </div>
          </div>

          {/* Activity Chart */}
          <div className="bg-white p-8 rounded-[32px] border border-slate-100 shadow-sm">
            <div className="flex items-center justify-between mb-8">
              <div>
                <h3 className="text-xl font-black text-slate-800 tracking-tight">Daily Performance Trend</h3>
                <p className="text-slate-500 text-xs font-medium uppercase tracking-wider mt-1">Worked Minutes vs Tracked Minutes</p>
              </div>
            </div>
            <div className="h-80 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.dailyBreakdown}>
                  <defs>
                    <linearGradient id="colorWorked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#6366f1" stopOpacity={0.1}/>
                      <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorTracked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.1}/>
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                  <XAxis 
                    dataKey="date" 
                    axisLine={false} 
                    tickLine={false} 
                    tick={{ fontSize: 10, fill: '#94a3b8', fontWeight: 600 }}
                    dy={10}
                    tickFormatter={(val) => val.split('-').slice(1).join('/')}
                  />
                  <YAxis 
                    axisLine={false} 
                    tickLine={false} 
                    tick={{ fontSize: 10, fill: '#94a3b8', fontWeight: 600 }}
                    tickFormatter={(val) => `${val}m`}
                  />
                  <Tooltip 
                    contentStyle={{ borderRadius: '16px', border: 'none', boxShadow: '0 20px 25px -5px rgb(0 0 0 / 0.1)' }}
                  />
                  <Area type="monotone" dataKey="workedMinutes" name="Worked Time" stroke="#6366f1" strokeWidth={3} fillOpacity={1} fill="url(#colorWorked)" />
                  <Area type="monotone" dataKey="trackedMinutes" name="Tracked Time" stroke="#10b981" strokeWidth={3} fillOpacity={1} fill="url(#colorTracked)" />
                  <Legend verticalAlign="top" height={36}/>
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Daily Breakdown List */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
             <div className="bg-white rounded-[32px] border border-slate-100 shadow-sm overflow-hidden">
                <div className="p-6 border-b border-slate-50 bg-slate-50/50">
                  <h3 className="text-lg font-black text-slate-800 tracking-tight">Worksheet History</h3>
                  <p className="text-slate-500 text-[10px] font-black uppercase tracking-widest">Chronological list of all logged activity</p>
                </div>
                <div className="max-h-[600px] overflow-y-auto">
                   {data.dailyBreakdown.map(day => (
                     <div key={day.date} className="p-6 border-b border-slate-50 last:border-0">
                        <div className="flex items-center justify-between mb-4">
                           <div className="px-3 py-1 bg-slate-900 text-white rounded-lg text-[10px] font-black uppercase tracking-widest">{day.date}</div>
                           <div className="flex gap-2">
                              <span className="px-2 py-0.5 bg-blue-50 text-blue-600 rounded text-[10px] font-bold">W: {formatMinutes(day.workedMinutes)}</span>
                              <span className="px-2 py-0.5 bg-emerald-50 text-emerald-600 rounded text-[10px] font-bold">T: {formatMinutes(day.trackedMinutes)}</span>
                           </div>
                        </div>
                        <div className="space-y-3">
                           {day.logs.map((log, idx) => (
                             <div key={idx} className="p-4 rounded-2xl bg-slate-50 border border-slate-100 group hover:border-indigo-200 transition-colors">
                                <div className="flex items-start justify-between">
                                   <div className="flex-1">
                                      <p className="text-xs font-black text-slate-900 line-clamp-1">{log.serviceName}</p>
                                      <p className="text-[10px] font-bold text-indigo-600 mt-0.5">{log.taskTitle}</p>
                                      {log.notes && <p className="text-[11px] text-slate-500 mt-2 italic bg-white p-2 rounded-lg border border-slate-100 line-clamp-2">{log.notes}</p>}
                                   </div>
                                   <div className="text-right ml-4">
                                      <p className="text-xs font-black text-slate-900">{log.minutes}m</p>
                                      <p className="text-[9px] font-black text-slate-400 uppercase mt-1">Logged</p>
                                   </div>
                                </div>
                             </div>
                           ))}
                           {day.logs.length === 0 && <p className="text-xs text-slate-400 italic py-2">No worksheets logged for this day</p>}
                        </div>
                     </div>
                   ))}
                </div>
             </div>

             <div className="bg-white rounded-[32px] border border-slate-100 shadow-sm overflow-hidden">
                <div className="p-6 border-b border-slate-50 bg-slate-50/50">
                  <h3 className="text-lg font-black text-slate-800 tracking-tight">Clock-in Sessions</h3>
                  <p className="text-slate-500 text-[10px] font-black uppercase tracking-widest">Attendance timestamps for selected period</p>
                </div>
                <div className="max-h-[600px] overflow-y-auto">
                   <table className="w-full text-left border-collapse">
                      <thead>
                         <tr className="bg-slate-50/30">
                            <th className="px-6 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Date</th>
                            <th className="px-6 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Clock In</th>
                            <th className="px-6 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Clock Out</th>
                            <th className="px-6 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-right">Duration</th>
                         </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-50">
                         {data.dailyBreakdown.flatMap(d => d.sessions).map(s => (
                           <tr key={s._id} className="hover:bg-slate-50/50 transition-colors group">
                              <td className="px-6 py-4 text-xs font-bold text-slate-700">{getDateKey(new Date(s.clockInAt))}</td>
                              <td className="px-6 py-4 text-xs font-medium text-slate-600">{new Date(s.clockInAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</td>
                              <td className="px-6 py-4 text-xs font-medium text-slate-600">{s.clockOutAt ? new Date(s.clockOutAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : <span className="text-emerald-500 font-bold animate-pulse">LIVE</span>}</td>
                              <td className="px-6 py-4 text-right">
                                 <span className="text-xs font-black text-slate-900">{formatMinutes(Math.round((s.totalSeconds || 0) / 60))}</span>
                              </td>
                           </tr>
                         ))}
                      </tbody>
                   </table>
                   {data.sessionsCount === 0 && <div className="p-20 text-center text-slate-400 italic">No attendance sessions found</div>}
                </div>
             </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default EmployeeAnalysisModule;
