import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import { 
  Calendar as CalendarIcon, LayoutGrid, Table, Search, 
  Filter, Plus, CheckCircle, AlertTriangle, XCircle, 
  ChevronLeft, ChevronRight, Download, RefreshCw,
  Building2, Briefcase, FileText, Activity
} from 'lucide-react';
import ComplianceTaskModal from './ComplianceTaskModal';

const CATEGORIES = ['Dashboard', 'GST', 'MCA', 'DIN KYC', 'TDS/TCS', 'Income Tax', 'Adv Tax', 'ESI', 'PF', 'PT', 'Notices'];
const MONTHS = ['APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC', 'JAN', 'FEB', 'MAR'];
const FULL_MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

const ComplianceModule = ({ token, employees = [], users = [] }) => {
  const [view, setView] = useState('calendar'); // 'calendar' or 'matrix'
  const [activeTab, setActiveTab] = useState('Dashboard');
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(false);
  const [currentMonth, setCurrentMonth] = useState(new Date().getMonth());
  const [currentYear, setCurrentYear] = useState(new Date().getFullYear());
  const [searchQuery, setSearchQuery] = useState('');
  
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [taskToEdit, setTaskToEdit] = useState(null);

  const config = useMemo(() => ({ headers: { Authorization: `Bearer ${token}` } }), [token]);

  const fetchRecords = async () => {
    setLoading(true);
    try {
      const { data } = await axios.get(`/api/compliance`, config);
      setRecords(data);
    } catch (err) {
      console.error('Failed to fetch compliance records');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRecords();
  }, []);

  const filteredRecords = useMemo(() => {
    return records.filter(r => {
      const matchesSearch = r.clientName.toLowerCase().includes(searchQuery.toLowerCase()) || 
                           r.taskName.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesCategory = activeTab === 'Dashboard' || r.category === activeTab;
      return matchesSearch && matchesCategory;
    });
  }, [records, searchQuery, activeTab]);

  const handleExportXLS = () => {
    if (filteredRecords.length === 0) return alert('No records to export');
    
    const headers = ['Client Name', 'Category', 'Task Name', 'Due Date', 'Period Month', 'Period Year', 'Status', 'Notes'];
    const csvRows = [headers.join(',')];

    filteredRecords.forEach(r => {
      const row = [
        `"${r.clientName.replace(/"/g, '""')}"`,
        `"${r.category}"`,
        `"${r.taskName.replace(/"/g, '""')}"`,
        `"${new Date(r.dueDate).toISOString().split('T')[0]}"`,
        `"${r.periodMonth}"`,
        `"${r.periodYear}"`,
        `"${r.status}"`,
        `"${(r.notes || '').replace(/"/g, '""')}"`
      ];
      csvRows.push(row.join(','));
    });

    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Compliance_Report_${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  // Calendar View Logic
  const daysInMonth = (month, year) => new Date(year, month + 1, 0).getDate();
  const firstDayOfMonth = (month, year) => new Date(year, month, 1).getDay();

  const calendarDays = useMemo(() => {
    const days = [];
    const count = daysInMonth(currentMonth, currentYear);
    const start = firstDayOfMonth(currentMonth, currentYear);
    
    for (let i = 0; i < start; i++) days.push(null);
    for (let i = 1; i <= count; i++) days.push(i);
    
    return days;
  }, [currentMonth, currentYear]);

  const getRecordsForDay = (day) => {
    if (!day) return [];
    return filteredRecords.filter(r => {
      const d = new Date(r.dueDate);
      return d.getDate() === day && d.getMonth() === currentMonth && d.getFullYear() === currentYear;
    });
  };

  // Matrix View Logic
  const clients = useMemo(() => [...new Set(records.map(r => r.clientName))].sort(), [records]);

  const getRecordForClientMonth = (client, month) => {
    return records.find(r => r.clientName === client && r.periodMonth === month && (activeTab === 'Dashboard' || r.category === activeTab));
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'Filed': return 'bg-emerald-50 text-emerald-600 border-emerald-100 hover:bg-emerald-100';
      case 'Late': return 'bg-amber-50 text-amber-600 border-amber-100 hover:bg-amber-100';
      case 'Missed': return 'bg-rose-50 text-rose-600 border-rose-100 hover:bg-rose-100';
      case 'Pending': return 'bg-blue-50 text-blue-600 border-blue-100 hover:bg-blue-100';
      default: return 'bg-slate-50 text-slate-400 border-slate-100';
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      {/* Header & Tabs */}
      <div className="bg-white rounded-[32px] p-6 shadow-sm border border-slate-100">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 mb-8">
          <div>
            <h2 className="text-2xl font-black text-slate-800 tracking-tight flex items-center gap-3">
              <CalendarIcon className="text-indigo-600" />
              Compliance Management
            </h2>
            <p className="text-slate-500 text-sm font-medium mt-1">Track statutory deadlines and filing status across all clients.</p>
          </div>
          
          <div className="flex items-center gap-3 bg-slate-50 p-1.5 rounded-2xl">
            <button 
              onClick={() => setView('calendar')}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-xl font-bold text-sm transition-all ${view === 'calendar' ? 'bg-white shadow-sm text-indigo-600' : 'text-slate-500 hover:text-slate-700'}`}
            >
              <LayoutGrid size={18} /> Calendar View
            </button>
            <button 
              onClick={() => setView('matrix')}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-xl font-bold text-sm transition-all ${view === 'matrix' ? 'bg-white shadow-sm text-indigo-600' : 'text-slate-500 hover:text-slate-700'}`}
            >
              <Table size={18} /> Matrix View
            </button>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          {CATEGORIES.map(cat => (
            <button
              key={cat}
              onClick={() => setActiveTab(cat)}
              className={`px-5 py-2 rounded-xl text-xs font-black uppercase tracking-widest transition-all border-2 ${activeTab === cat ? 'bg-indigo-600 text-white border-indigo-600 shadow-lg shadow-indigo-100' : 'bg-white text-slate-500 border-slate-100 hover:border-slate-200'}`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Controls */}
      <div className="flex flex-col md:flex-row gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input 
            type="text"
            placeholder="Search by client or task..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-11 pr-4 py-4 rounded-2xl bg-white border border-slate-100 focus:border-indigo-500 outline-none transition-all font-bold text-sm shadow-sm"
          />
        </div>
        <div className="flex gap-2">
          <button 
            onClick={handleExportXLS}
            className="px-6 py-4 bg-white border border-slate-100 text-slate-700 rounded-2xl font-black text-sm shadow-sm hover:border-slate-200 transition-all flex items-center gap-2"
          >
            <Download size={18} /> Export CSV
          </button>
          <button 
            onClick={() => {
              setTaskToEdit(null);
              setIsModalOpen(true);
            }}
            className="px-6 py-4 bg-indigo-600 text-white rounded-2xl font-black text-sm shadow-lg shadow-indigo-100 hover:bg-indigo-700 active:scale-95 transition-all flex items-center gap-2"
          >
            <Plus size={18} /> New Task
          </button>
        </div>
      </div>

      {/* Main View Area */}
      {view === 'calendar' ? (
        <div className="bg-white rounded-[40px] p-8 shadow-sm border border-slate-100">
          <div className="flex items-center justify-between mb-8">
            <h3 className="text-xl font-black text-slate-800 tracking-tight">{FULL_MONTHS[currentMonth]} {currentYear}</h3>
            <div className="flex items-center gap-2">
              <button 
                onClick={() => setCurrentMonth(prev => prev === 0 ? 11 : prev - 1)}
                className="w-10 h-10 rounded-xl border border-slate-100 flex items-center justify-center hover:bg-slate-50 transition-colors"
              >
                <ChevronLeft size={20} />
              </button>
              <button 
                onClick={() => setCurrentMonth(prev => prev === 11 ? 0 : prev + 1)}
                className="w-10 h-10 rounded-xl border border-slate-100 flex items-center justify-center hover:bg-slate-50 transition-colors"
              >
                <ChevronRight size={20} />
              </button>
            </div>
          </div>

          <div className="grid grid-cols-7 gap-px bg-slate-100 border border-slate-100 rounded-2xl overflow-hidden">
            {['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'].map(d => (
              <div key={d} className="bg-slate-50 py-3 text-center text-[10px] font-black text-slate-400 tracking-widest">{d}</div>
            ))}
            {calendarDays.map((day, idx) => {
              const dayRecords = getRecordsForDay(day);
              return (
                <div key={idx} className={`bg-white min-h-[140px] p-3 transition-colors ${day ? 'hover:bg-slate-50/50' : 'bg-slate-50/30'}`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className={`text-sm font-bold ${day === new Date().getDate() && currentMonth === new Date().getMonth() ? 'w-7 h-7 bg-indigo-600 text-white rounded-full flex items-center justify-center shadow-lg shadow-indigo-100' : 'text-slate-400'}`}>
                      {day}
                    </span>
                  </div>
                  <div className="space-y-1.5">
                    {dayRecords.map(r => (
                      <div 
                        key={r._id} 
                        onClick={() => {
                          setTaskToEdit(r);
                          setIsModalOpen(true);
                        }}
                        className={`p-2 rounded-lg border text-[10px] font-bold cursor-pointer transition-all hover:scale-[1.02] ${getStatusColor(r.status)}`}
                      >
                        <div className="flex items-center justify-between mb-0.5">
                           <span>{r.category}</span>
                           {r.status === 'Filed' && <CheckCircle size={10} />}
                        </div>
                        <div className="truncate opacity-80">{r.taskName}</div>
                        <div className="truncate text-[9px] uppercase mt-1 opacity-60">{r.clientName}</div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        <div className="bg-white rounded-[40px] shadow-sm border border-slate-100 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-50/50">
                  <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 sticky left-0 bg-slate-50/50 backdrop-blur-sm z-10">Client / Company</th>
                  {MONTHS.map(m => (
                    <th key={m} className="px-6 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-center">{m}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-50">
                {clients.map(client => (
                  <tr key={client} className="hover:bg-slate-50/30 transition-colors group">
                    <td className="px-8 py-5 sticky left-0 bg-white group-hover:bg-slate-50/30 transition-colors z-10 border-r border-slate-50">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-indigo-50 text-indigo-600 flex items-center justify-center font-black text-xs">
                          {client.charAt(0)}
                        </div>
                        <span className="text-sm font-black text-slate-700">{client}</span>
                      </div>
                    </td>
                    {MONTHS.map(m => {
                      const record = getRecordForClientMonth(client, m);
                      const status = record ? record.status : null;
                      return (
                        <td key={m} className="px-4 py-5 text-center">
                          {record ? (
                            <button 
                              onClick={() => {
                                setTaskToEdit(record);
                                setIsModalOpen(true);
                              }}
                              className={`inline-flex items-center gap-1 px-3 py-1.5 rounded-full border text-[10px] font-black uppercase tracking-wider transition-all hover:scale-105 ${getStatusColor(status)}`}
                            >
                              {status === 'Filed' && <CheckCircle size={10} />}
                              {status === 'Missed' && <XCircle size={10} />}
                              {status === 'Late' && <AlertTriangle size={10} />}
                              {status}
                            </button>
                          ) : (
                            <button 
                              onClick={() => {
                                setTaskToEdit({
                                  clientName: client,
                                  periodMonth: m,
                                  periodYear: String(currentYear)
                                });
                                setIsModalOpen(true);
                              }}
                              className="text-slate-300 hover:text-indigo-600 font-bold text-xs"
                              title="Add compliance for this month"
                            >
                              +
                            </button>
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
            {clients.length === 0 && (
              <div className="py-20 text-center text-slate-400 italic">No client records found.</div>
            )}
          </div>
        </div>
      )}

      {/* Compliance Task Modal */}
      <ComplianceTaskModal 
        isOpen={isModalOpen}
        onClose={() => {
          setIsModalOpen(false);
          setTaskToEdit(null);
        }}
        onSuccess={fetchRecords}
        token={token}
        taskToEdit={taskToEdit}
        employees={employees}
        clients={users}
      />
    </div>
  );
};

export default ComplianceModule;
