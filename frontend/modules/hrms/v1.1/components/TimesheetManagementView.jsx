import React, { useState, useEffect, useMemo, useCallback } from 'react';
import axios from 'axios';
import {
  Clock, Coffee, Play, Square, CheckCircle2, XCircle, AlertCircle,
  FileSpreadsheet, Download, ChevronLeft, ChevronRight, Filter,
  TrendingUp, Calendar, User, Briefcase, FileText, Send, Check, X,
  AlertTriangle, ShieldCheck, RefreshCw, BarChart2
} from 'lucide-react';
import * as XLSX from 'xlsx';

const formatSecondsToHoursMins = (secs = 0) => {
  const totalMinutes = Math.floor(secs / 60);
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  if (hours === 0) return `${minutes}m`;
  return `${hours}h ${minutes > 0 ? `${minutes}m` : ''}`;
};

const formatTimeOnly = (dateStr) => {
  if (!dateStr) return '--:--';
  const d = new Date(dateStr);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

const getDateKey = (date = new Date()) => date.toISOString().slice(0, 10);

const TimesheetManagementView = ({ role = 'employee', token, employees = [] }) => {
  const isAdmin = role === 'admin' || role === 'Admin';
  const config = useMemo(() => {
    const userInfo = JSON.parse(localStorage.getItem('userInfo') || '{}');
    const activeToken = token || userInfo?.token;
    return activeToken ? { headers: { Authorization: `Bearer ${activeToken}` } } : null;
  }, [token]);

  // Current view mode for Admin: 'audit' (timesheets review) vs 'my_timesheet'
  const [adminTab, setAdminTab] = useState(isAdmin ? 'review_queue' : 'my_timesheet');

  // Date Range state
  const [currentWeekOffset, setCurrentWeekOffset] = useState(0);
  const dateRange = useMemo(() => {
    const now = new Date();
    now.setDate(now.getDate() + currentWeekOffset * 7);
    const day = now.getDay();
    const diffToMonday = now.getDate() - day + (day === 0 ? -6 : 1);
    const monday = new Date(now.setDate(diffToMonday));
    const sunday = new Date(now.setDate(monday.getDate() + 6));
    return {
      startDate: getDateKey(monday),
      endDate: getDateKey(sunday),
      label: `${monday.toLocaleDateString([], { month: 'short', day: 'numeric' })} - ${sunday.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })}`
    };
  }, [currentWeekOffset]);

  // Employee Timesheet data state
  const [timesheetData, setTimesheetData] = useState(null);
  const [isLoadingTimesheet, setIsLoadingTimesheet] = useState(false);
  const [submissionNotes, setSubmissionNotes] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitFeedback, setSubmitFeedback] = useState('');

  // Admin Review Queue state
  const [reviewQueue, setReviewQueue] = useState([]);
  const [isLoadingQueue, setIsLoadingQueue] = useState(false);
  const [statusFilter, setStatusFilter] = useState('All');
  const [selectedEmployeeFilter, setSelectedEmployeeFilter] = useState('');
  const [selectedTimesheetForModal, setSelectedTimesheetForModal] = useState(null);
  const [reviewNotesInput, setReviewNotesInput] = useState('');
  const [isReviewing, setIsReviewing] = useState(false);

  // Live Attendance Status state (for breaks)
  const [liveStatus, setLiveStatus] = useState(null);
  const [breakTypeSelect, setBreakTypeSelect] = useState('Lunch');
  const [breakNotes, setBreakNotes] = useState('');
  const [isBreakModalOpen, setIsBreakModalOpen] = useState(false);
  const [breakLoading, setBreakLoading] = useState(false);

  // Expanded details row
  const [expandedDate, setExpandedDate] = useState(null);

  // 1. Fetch My Timesheet
  const fetchMyTimesheet = useCallback(async () => {
    if (!config) return;
    setIsLoadingTimesheet(true);
    try {
      const { data } = await axios.get(
        `/api/timesheets/my-timesheet?startDate=${dateRange.startDate}&endDate=${dateRange.endDate}&periodType=weekly`,
        config
      );
      setTimesheetData(data);
      setSubmissionNotes(data.submissionNotes || '');
    } catch (err) {
      console.error('Failed to fetch timesheet:', err);
    } finally {
      setIsLoadingTimesheet(false);
    }
  }, [config, dateRange]);

  // 2. Fetch Live Attendance / Break status
  const fetchLiveStatus = useCallback(async () => {
    if (!config) return;
    try {
      const { data } = await axios.get('/api/attendance/my-status', config);
      setLiveStatus(data);
    } catch (err) {
      console.error('Failed to fetch live status:', err);
    }
  }, [config]);

  // 3. Fetch Admin Review Queue
  const fetchAdminReviewQueue = useCallback(async () => {
    if (!config || !isAdmin) return;
    setIsLoadingQueue(true);
    try {
      const queryParams = new URLSearchParams();
      if (statusFilter !== 'All') queryParams.append('status', statusFilter);
      if (selectedEmployeeFilter) queryParams.append('employeeId', selectedEmployeeFilter);
      queryParams.append('startDate', dateRange.startDate);
      queryParams.append('endDate', dateRange.endDate);

      const { data } = await axios.get(`/api/timesheets/admin/list?${queryParams.toString()}`, config);
      setReviewQueue(data || []);
    } catch (err) {
      console.error('Failed to fetch review queue:', err);
    } finally {
      setIsLoadingQueue(false);
    }
  }, [config, isAdmin, statusFilter, selectedEmployeeFilter, dateRange]);

  useEffect(() => {
    fetchLiveStatus();
    if (adminTab === 'my_timesheet' || !isAdmin) {
      fetchMyTimesheet();
    } else {
      fetchAdminReviewQueue();
    }
  }, [fetchMyTimesheet, fetchAdminReviewQueue, fetchLiveStatus, adminTab, isAdmin]);

  // Handle Start Break
  const handleStartBreak = async () => {
    if (!config) return;
    setBreakLoading(true);
    try {
      await axios.post('/api/attendance/break-start', { breakType: breakTypeSelect, notes: breakNotes }, config);
      setIsBreakModalOpen(false);
      setBreakNotes('');
      await fetchLiveStatus();
      await fetchMyTimesheet();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to start break');
    } finally {
      setBreakLoading(false);
    }
  };

  // Handle End Break
  const handleEndBreak = async () => {
    if (!config) return;
    setBreakLoading(true);
    try {
      await axios.post('/api/attendance/break-end', {}, config);
      await fetchLiveStatus();
      await fetchMyTimesheet();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to end break');
    } finally {
      setBreakLoading(false);
    }
  };

  // Handle Submit Timesheet
  const handleSubmitTimesheet = async () => {
    if (!config || !timesheetData) return;
    setIsSubmitting(true);
    try {
      const payload = {
        startDate: timesheetData.startDate,
        endDate: timesheetData.endDate,
        periodType: 'weekly',
        submissionNotes,
        entries: timesheetData.entries,
        totalGrossSeconds: timesheetData.totalGrossSeconds,
        totalBreakSeconds: timesheetData.totalBreakSeconds,
        totalNetWorkedSeconds: timesheetData.totalNetWorkedSeconds,
        totalTaskSeconds: timesheetData.totalTaskSeconds,
        totalIdleSeconds: timesheetData.totalIdleSeconds,
        totalOvertimeSeconds: timesheetData.totalOvertimeSeconds,
        productivityPercentage: timesheetData.productivityPercentage
      };
      await axios.post('/api/timesheets/submit', payload, config);
      setSubmitFeedback('Timesheet submitted successfully for review!');
      setTimeout(() => setSubmitFeedback(''), 5000);
      fetchMyTimesheet();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to submit timesheet');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Handle Admin Review (Approve/Reject)
  const handleReviewTimesheet = async (status) => {
    if (!config || !selectedTimesheetForModal) return;
    setIsReviewing(true);
    try {
      await axios.put(
        `/api/timesheets/${selectedTimesheetForModal._id}/review`,
        { status, reviewNotes: reviewNotesInput },
        config
      );
      setSelectedTimesheetForModal(null);
      setReviewNotesInput('');
      fetchAdminReviewQueue();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to update review status');
    } finally {
      setIsReviewing(false);
    }
  };

  // Handle Excel Export
  const handleExportExcel = async () => {
    if (!config) return;
    try {
      const { data } = await axios.get(
        `/api/timesheets/admin/export?startDate=${dateRange.startDate}&endDate=${dateRange.endDate}`,
        config
      );

      const rows = (data.reportRows || []).map((r, index) => ({
        '#': index + 1,
        'Employee Name': r.name,
        'Email': r.email,
        'Role': r.role,
        'Days Present': r.daysPresent,
        'Total Gross Hours': r.totalGrossHours,
        'Total Break Hours': r.totalBreakHours,
        'Net Worked Hours': r.totalNetHours,
        'Active Task Hours': r.totalTaskHours,
        'Idle / Prep Hours': r.totalIdleHours,
        'Productivity (%)': `${r.productivityPercentage}%`,
        'Orders Worked Summary': r.ordersSummary || 'None'
      }));

      const ws = XLSX.utils.json_to_sheet(rows);
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, 'Timesheet_Report');
      XLSX.writeFile(wb, `VRHere_Timesheet_Report_${dateRange.startDate}_to_${dateRange.endDate}.xlsx`);
    } catch (err) {
      console.error('Export error:', err);
      alert('Failed to export timesheet data');
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Mode Toggle */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 p-6 rounded-3xl text-white shadow-xl">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 bg-indigo-500/20 rounded-xl text-indigo-400">
              <Clock size={22} />
            </span>
            <h2 className="text-2xl font-black tracking-tight">Timesheet & Shift Performance Desk</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Automated Clock-In reconciliation, Break tracking, Idle time analysis, and Payroll ready timesheets.
          </p>
        </div>

        {/* Live Break Indicator / Controls */}
        <div className="flex items-center gap-3">
          {liveStatus?.openSession ? (
            <div className="flex items-center gap-2 bg-white/10 backdrop-blur-md px-3.5 py-2 rounded-2xl border border-white/10">
              {liveStatus.activeBreak ? (
                <>
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-400 animate-ping" />
                  <span className="text-xs font-bold text-amber-300">
                    On Break: {liveStatus.activeBreak.breakType}
                  </span>
                  <button
                    onClick={handleEndBreak}
                    disabled={breakLoading}
                    className="ml-2 px-3 py-1 bg-emerald-500 hover:bg-emerald-600 text-white text-xs font-bold rounded-xl transition shadow flex items-center gap-1"
                  >
                    <Play size={12} /> Resume Shift
                  </button>
                </>
              ) : (
                <>
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
                  <span className="text-xs font-bold text-emerald-300">Shift Active</span>
                  <button
                    onClick={() => setIsBreakModalOpen(true)}
                    className="ml-2 px-3 py-1 bg-amber-500/90 hover:bg-amber-600 text-white text-xs font-bold rounded-xl transition shadow flex items-center gap-1"
                  >
                    <Coffee size={12} /> Take Break
                  </button>
                </>
              )}
            </div>
          ) : (
            <div className="px-3.5 py-2 rounded-2xl bg-white/5 border border-white/10 text-xs text-slate-400 font-medium">
              Not Clocked In
            </div>
          )}

          {isAdmin && (
            <div className="inline-flex rounded-xl bg-white/10 p-1 border border-white/10">
              <button
                onClick={() => setAdminTab('review_queue')}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition ${adminTab === 'review_queue' ? 'bg-indigo-600 text-white shadow' : 'text-slate-300 hover:text-white'}`}
              >
                Approval Queue
              </button>
              <button
                onClick={() => setAdminTab('my_timesheet')}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition ${adminTab === 'my_timesheet' ? 'bg-indigo-600 text-white shadow' : 'text-slate-300 hover:text-white'}`}
              >
                My Timesheet
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Date Range Navigator */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-white p-4 rounded-2xl border border-slate-200/80 shadow-sm">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setCurrentWeekOffset(prev => prev - 1)}
            className="p-2 hover:bg-slate-100 rounded-xl text-slate-600 transition"
            title="Previous Week"
          >
            <ChevronLeft size={18} />
          </button>
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-50 border border-slate-200 text-sm font-bold text-slate-800">
            <Calendar size={15} className="text-indigo-600" />
            <span>{dateRange.label}</span>
          </div>
          <button
            onClick={() => setCurrentWeekOffset(prev => prev + 1)}
            className="p-2 hover:bg-slate-100 rounded-xl text-slate-600 transition"
            title="Next Week"
          >
            <ChevronRight size={18} />
          </button>
          {currentWeekOffset !== 0 && (
            <button
              onClick={() => setCurrentWeekOffset(0)}
              className="text-xs font-bold text-indigo-600 hover:underline ml-1"
            >
              Current Week
            </button>
          )}
        </div>

        {isAdmin && (
          <div className="flex items-center gap-3">
            <button
              onClick={handleExportExcel}
              className="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold rounded-xl transition flex items-center gap-1.5 shadow-sm"
            >
              <FileSpreadsheet size={15} /> Export Payroll XLSX
            </button>
          </div>
        )}
      </div>

      {/* Break Dialog Modal */}
      {isBreakModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-3xl p-6 max-w-md w-full shadow-2xl border border-slate-100 animate-in zoom-in-95">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <span className="p-2 rounded-xl bg-amber-50 text-amber-600">
                  <Coffee size={20} />
                </span>
                <h3 className="text-lg font-black text-slate-900">Start a Break</h3>
              </div>
              <button onClick={() => setIsBreakModalOpen(false)} className="text-slate-400 hover:text-slate-600 p-1">
                <X size={18} />
              </button>
            </div>
            <p className="text-xs text-slate-500 mb-4">
              Your shift timer will be paused and logged as break duration until you resume work.
            </p>
            <div className="space-y-3">
              <div>
                <label className="text-xs font-bold text-slate-700">Break Type</label>
                <select
                  value={breakTypeSelect}
                  onChange={(e) => setBreakTypeSelect(e.target.value)}
                  className="w-full mt-1 p-2.5 border rounded-xl border-slate-200 bg-white text-sm font-semibold"
                >
                  <option value="Lunch">Lunch Break (Meal)</option>
                  <option value="Tea/Coffee">Tea / Coffee Break (15m)</option>
                  <option value="Meeting">Internal / Team Meeting</option>
                  <option value="Personal">Personal / Bio Break</option>
                  <option value="Other">Other</option>
                </select>
              </div>
              <div>
                <label className="text-xs font-bold text-slate-700">Notes (Optional)</label>
                <input
                  type="text"
                  value={breakNotes}
                  onChange={(e) => setBreakNotes(e.target.value)}
                  placeholder="e.g. Quick team standup"
                  className="w-full mt-1 p-2.5 border rounded-xl border-slate-200 text-sm"
                />
              </div>
            </div>
            <div className="mt-6 flex justify-end gap-2">
              <button
                onClick={() => setIsBreakModalOpen(false)}
                className="px-4 py-2 rounded-xl border border-slate-200 text-slate-600 text-sm font-bold hover:bg-slate-50"
              >
                Cancel
              </button>
              <button
                onClick={handleStartBreak}
                disabled={breakLoading}
                className="px-5 py-2 rounded-xl bg-amber-500 hover:bg-amber-600 text-white text-sm font-bold shadow transition flex items-center gap-1.5"
              >
                <Coffee size={15} /> Confirm Break
              </button>
            </div>
          </div>
        </div>
      )}

      {/* SCREEN 1: My Timesheet (Employee & Self-Service) */}
      {(adminTab === 'my_timesheet' || !isAdmin) && (
        <div className="space-y-6">
          {/* Timesheet Summary KPIs */}
          {timesheetData && (
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
              <div className="bg-white p-4 rounded-2xl border border-slate-200/80 shadow-sm">
                <p className="text-[11px] font-bold uppercase text-slate-400">Total Shift</p>
                <p className="text-xl font-black text-slate-900 mt-1">
                  {formatSecondsToHoursMins(timesheetData.totalGrossSeconds)}
                </p>
                <p className="text-[10px] text-slate-400 mt-0.5">Gross Clock Time</p>
              </div>
              <div className="bg-white p-4 rounded-2xl border border-slate-200/80 shadow-sm">
                <p className="text-[11px] font-bold uppercase text-amber-600">Breaks Taken</p>
                <p className="text-xl font-black text-amber-700 mt-1">
                  {formatSecondsToHoursMins(timesheetData.totalBreakSeconds)}
                </p>
                <p className="text-[10px] text-slate-400 mt-0.5">Tea, Lunch & Bio</p>
              </div>
              <div className="bg-white p-4 rounded-2xl border border-slate-200/80 shadow-sm">
                <p className="text-[11px] font-bold uppercase text-indigo-600">Net Worked</p>
                <p className="text-xl font-black text-indigo-700 mt-1">
                  {formatSecondsToHoursMins(timesheetData.totalNetWorkedSeconds)}
                </p>
                <p className="text-[10px] text-slate-400 mt-0.5">Shift Minus Breaks</p>
              </div>
              <div className="bg-white p-4 rounded-2xl border border-slate-200/80 shadow-sm">
                <p className="text-[11px] font-bold uppercase text-emerald-600">Order Work</p>
                <p className="text-xl font-black text-emerald-700 mt-1">
                  {formatSecondsToHoursMins(timesheetData.totalTaskSeconds)}
                </p>
                <p className="text-[10px] text-slate-400 mt-0.5">Tracked on Tasks</p>
              </div>
              <div className="bg-white p-4 rounded-2xl border border-slate-200/80 shadow-sm">
                <p className="text-[11px] font-bold uppercase text-slate-500">Idle / Non-Task</p>
                <p className="text-xl font-black text-slate-700 mt-1">
                  {formatSecondsToHoursMins(timesheetData.totalIdleSeconds)}
                </p>
                <p className="text-[10px] text-slate-400 mt-0.5">Prep & Unallocated</p>
              </div>
              <div className="bg-white p-4 rounded-2xl border border-slate-200/80 shadow-sm flex flex-col justify-between">
                <div>
                  <p className="text-[11px] font-bold uppercase text-indigo-600">Productivity</p>
                  <p className="text-xl font-black text-indigo-900 mt-1">
                    {timesheetData.productivityPercentage}%
                  </p>
                </div>
                <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden mt-2">
                  <div
                    className={`h-full ${timesheetData.productivityPercentage >= 75 ? 'bg-emerald-500' : timesheetData.productivityPercentage >= 50 ? 'bg-amber-500' : 'bg-rose-500'}`}
                    style={{ width: `${Math.min(100, timesheetData.productivityPercentage)}%` }}
                  />
                </div>
              </div>
            </div>
          )}

          {/* Daily Timesheet Table */}
          <div className="bg-white rounded-3xl border border-slate-200/80 shadow-sm overflow-hidden">
            <div className="p-5 border-b border-slate-100 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="font-bold text-slate-900 text-lg">Weekly Timesheet Breakdown</h3>
                <p className="text-xs text-slate-400 mt-0.5">Individual daily shifts, breaks, and order tasks reconciliation</p>
              </div>
              {timesheetData && (
                <span className={`px-3 py-1 rounded-full text-xs font-black uppercase tracking-wider ${
                  timesheetData.status === 'Approved' ? 'bg-emerald-100 text-emerald-800' :
                  timesheetData.status === 'Submitted' ? 'bg-indigo-100 text-indigo-800' :
                  timesheetData.status === 'Rejected' ? 'bg-rose-100 text-rose-800' :
                  'bg-slate-100 text-slate-700'
                }`}>
                  Status: {timesheetData.status}
                </span>
              )}
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-slate-50 text-slate-500 text-[11px] uppercase font-bold tracking-wider border-b border-slate-100">
                  <tr>
                    <th className="text-left px-5 py-3">Day & Date</th>
                    <th className="text-left px-5 py-3">In / Out</th>
                    <th className="text-left px-5 py-3">Gross Shift</th>
                    <th className="text-left px-5 py-3">Breaks</th>
                    <th className="text-left px-5 py-3">Net Worked</th>
                    <th className="text-left px-5 py-3">Order Work</th>
                    <th className="text-left px-5 py-3">Idle Time</th>
                    <th className="text-left px-5 py-3">Status</th>
                    <th className="text-right px-5 py-3">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-medium">
                  {timesheetData?.entries?.map((entry) => {
                    const isExpanded = expandedDate === entry.date;
                    const hasTasks = entry.ordersWorked && entry.ordersWorked.length > 0;

                    return (
                      <React.Fragment key={entry.date}>
                        <tr className="hover:bg-slate-50/80 transition">
                          <td className="px-5 py-3.5">
                            <p className="font-bold text-slate-900">{entry.dayName}</p>
                            <p className="text-xs text-slate-400">{entry.date}</p>
                          </td>
                          <td className="px-5 py-3.5 text-xs">
                            <p className="text-emerald-700 font-semibold">In: {formatTimeOnly(entry.clockInAt)}</p>
                            <p className="text-slate-500">Out: {formatTimeOnly(entry.clockOutAt)}</p>
                          </td>
                          <td className="px-5 py-3.5 font-semibold text-slate-800">
                            {formatSecondsToHoursMins(entry.grossShiftSeconds)}
                          </td>
                          <td className="px-5 py-3.5 text-amber-700 font-semibold">
                            {formatSecondsToHoursMins(entry.breakSeconds)}
                          </td>
                          <td className="px-5 py-3.5 font-bold text-indigo-700">
                            {formatSecondsToHoursMins(entry.netWorkedSeconds)}
                          </td>
                          <td className="px-5 py-3.5 font-bold text-emerald-700">
                            {formatSecondsToHoursMins(entry.taskWorkedSeconds)}
                          </td>
                          <td className="px-5 py-3.5 text-slate-500 font-semibold">
                            {formatSecondsToHoursMins(entry.idleSeconds)}
                          </td>
                          <td className="px-5 py-3.5">
                            <span className={`px-2.5 py-1 rounded-full text-[10px] font-black uppercase ${
                              entry.status === 'Present' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                              entry.status === 'Half Day' ? 'bg-amber-50 text-amber-700 border border-amber-200' :
                              entry.status === 'Weekend' ? 'bg-slate-100 text-slate-500' :
                              'bg-rose-50 text-rose-700 border border-rose-200'
                            }`}>
                              {entry.status}
                            </span>
                          </td>
                          <td className="px-5 py-3.5 text-right">
                            {hasTasks ? (
                              <button
                                onClick={() => setExpandedDate(isExpanded ? null : entry.date)}
                                className="px-2.5 py-1 rounded-lg bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-bold transition"
                              >
                                {isExpanded ? 'Hide' : `${entry.ordersWorked.length} Tasks`}
                              </button>
                            ) : (
                              <span className="text-slate-300 text-xs italic">No tasks</span>
                            )}
                          </td>
                        </tr>

                        {/* Expanded Task Logs for the day */}
                        {isExpanded && (
                          <tr className="bg-indigo-50/40">
                            <td colSpan={9} className="p-4 border-y border-indigo-100">
                              <p className="text-xs font-bold text-indigo-900 mb-2">
                                📋 Detailed Tasks Worked on {entry.date}:
                              </p>
                              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                                {entry.ordersWorked.map((t, idx) => (
                                  <div key={idx} className="bg-white p-2.5 rounded-xl border border-indigo-100 shadow-sm text-xs">
                                    <p className="font-bold text-slate-800">{t.serviceName}</p>
                                    <p className="text-slate-500 text-[11px] truncate">{t.taskTitle}</p>
                                    <span className="inline-block mt-1 font-black text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded">
                                      {t.minutes} mins
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Timesheet Submission Footer */}
            <div className="p-5 bg-slate-50 border-t border-slate-100 flex flex-wrap items-center justify-between gap-4">
              <div className="flex-1 min-w-[280px]">
                <label className="text-xs font-bold text-slate-700">Submission Remarks / Notes</label>
                <input
                  type="text"
                  value={submissionNotes}
                  onChange={(e) => setSubmissionNotes(e.target.value)}
                  disabled={timesheetData?.status === 'Approved'}
                  placeholder="e.g. Completed GST audit for Faizan Traders, standard hours"
                  className="w-full mt-1 p-2.5 border rounded-xl border-slate-200 bg-white text-sm"
                />
              </div>

              <div className="flex items-center gap-3">
                {submitFeedback && (
                  <span className="text-xs font-bold text-emerald-600 flex items-center gap-1">
                    <CheckCircle2 size={15} /> {submitFeedback}
                  </span>
                )}

                <button
                  onClick={handleSubmitTimesheet}
                  disabled={isSubmitting || timesheetData?.status === 'Approved'}
                  className="px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-bold text-sm shadow-md shadow-indigo-200 transition disabled:opacity-50 flex items-center gap-2"
                >
                  {isSubmitting ? (
                    'Submitting...'
                  ) : timesheetData?.status === 'Submitted' ? (
                    <>
                      <Check size={16} /> Re-Submit Timesheet
                    </>
                  ) : (
                    <>
                      <Send size={16} /> Submit Weekly Timesheet
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SCREEN 2: Admin / PM Approval Queue */}
      {isAdmin && adminTab === 'review_queue' && (
        <div className="space-y-6">
          {/* Filter Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 bg-white p-4 rounded-2xl border border-slate-200/80 shadow-sm">
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-1.5 text-xs font-bold text-slate-500">
                <Filter size={14} /> Status:
              </div>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="p-2 border rounded-xl border-slate-200 text-xs font-semibold bg-white"
              >
                <option value="All">All Statuses</option>
                <option value="Submitted">Submitted (Pending Review)</option>
                <option value="Approved">Approved</option>
                <option value="Rejected">Rejected</option>
                <option value="Draft">Drafts</option>
              </select>

              <select
                value={selectedEmployeeFilter}
                onChange={(e) => setSelectedEmployeeFilter(e.target.value)}
                className="p-2 border rounded-xl border-slate-200 text-xs font-semibold bg-white"
              >
                <option value="">All Employees</option>
                {employees.map(emp => (
                  <option key={emp._id} value={emp._id}>{emp.name} ({emp.role})</option>
                ))}
              </select>
            </div>

            <button
              onClick={fetchAdminReviewQueue}
              className="p-2 rounded-xl border border-slate-200 text-slate-600 hover:bg-slate-50 transition"
              title="Refresh Queue"
            >
              <RefreshCw size={14} />
            </button>
          </div>

          {/* Queue List Table */}
          <div className="bg-white rounded-3xl border border-slate-200/80 shadow-sm overflow-hidden">
            <div className="p-5 border-b border-slate-100 flex items-center justify-between">
              <div>
                <h3 className="font-bold text-slate-900 text-lg">Staff Timesheet Submissions</h3>
                <p className="text-xs text-slate-400 mt-0.5">Audit shift times, break allocations, and order work before payroll sign-off</p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-slate-50 text-slate-500 text-[11px] uppercase font-bold tracking-wider border-b border-slate-100">
                  <tr>
                    <th className="text-left px-5 py-3">Employee</th>
                    <th className="text-left px-5 py-3">Period</th>
                    <th className="text-left px-5 py-3">Shift Hours</th>
                    <th className="text-left px-5 py-3">Breaks</th>
                    <th className="text-left px-5 py-3">Net Worked</th>
                    <th className="text-left px-5 py-3">Task Work</th>
                    <th className="text-left px-5 py-3">Productivity</th>
                    <th className="text-left px-5 py-3">Status</th>
                    <th className="text-right px-5 py-3">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-medium">
                  {reviewQueue.map((ts) => (
                    <tr key={ts._id} className="hover:bg-slate-50/80 transition">
                      <td className="px-5 py-3.5">
                        <p className="font-bold text-slate-900">{ts.employee?.name || 'Employee'}</p>
                        <p className="text-xs text-slate-400">{ts.employee?.email}</p>
                      </td>
                      <td className="px-5 py-3.5 text-xs text-slate-600">
                        {ts.startDate} → {ts.endDate}
                      </td>
                      <td className="px-5 py-3.5 font-semibold text-slate-800">
                        {formatSecondsToHoursMins(ts.totalGrossSeconds)}
                      </td>
                      <td className="px-5 py-3.5 text-amber-700 font-semibold">
                        {formatSecondsToHoursMins(ts.totalBreakSeconds)}
                      </td>
                      <td className="px-5 py-3.5 font-bold text-indigo-700">
                        {formatSecondsToHoursMins(ts.totalNetWorkedSeconds)}
                      </td>
                      <td className="px-5 py-3.5 font-bold text-emerald-700">
                        {formatSecondsToHoursMins(ts.totalTaskSeconds)}
                      </td>
                      <td className="px-5 py-3.5">
                        <span className={`px-2 py-0.5 rounded-md text-xs font-black ${
                          ts.productivityPercentage >= 75 ? 'bg-emerald-50 text-emerald-700' :
                          ts.productivityPercentage >= 50 ? 'bg-amber-50 text-amber-700' :
                          'bg-rose-50 text-rose-700'
                        }`}>
                          {ts.productivityPercentage}%
                        </span>
                      </td>
                      <td className="px-5 py-3.5">
                        <span className={`px-2.5 py-1 rounded-full text-[10px] font-black uppercase ${
                          ts.status === 'Approved' ? 'bg-emerald-100 text-emerald-800' :
                          ts.status === 'Submitted' ? 'bg-indigo-100 text-indigo-800 animate-pulse' :
                          ts.status === 'Rejected' ? 'bg-rose-100 text-rose-800' :
                          'bg-slate-100 text-slate-600'
                        }`}>
                          {ts.status}
                        </span>
                      </td>
                      <td className="px-5 py-3.5 text-right">
                        <button
                          onClick={() => {
                            setSelectedTimesheetForModal(ts);
                            setReviewNotesInput(ts.reviewNotes || '');
                          }}
                          className="px-3 py-1.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold shadow-sm transition"
                        >
                          Audit & Review
                        </button>
                      </td>
                    </tr>
                  ))}
                  {reviewQueue.length === 0 && (
                    <tr>
                      <td colSpan={9} className="py-12 text-center text-slate-400 italic">
                        No timesheet submissions found for this filter criteria.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Audit & Review Modal */}
          {selectedTimesheetForModal && (
            <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
              <div className="bg-white rounded-3xl p-6 max-w-2xl w-full shadow-2xl border border-slate-100 animate-in zoom-in-95 max-h-[90vh] overflow-y-auto">
                <div className="flex items-center justify-between pb-4 border-b border-slate-100">
                  <div>
                    <h3 className="text-xl font-black text-slate-900">
                      Timesheet Audit: {selectedTimesheetForModal.employee?.name}
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Period: {selectedTimesheetForModal.startDate} to {selectedTimesheetForModal.endDate}
                    </p>
                  </div>
                  <button onClick={() => setSelectedTimesheetForModal(null)} className="text-slate-400 hover:text-slate-600 p-1">
                    <X size={20} />
                  </button>
                </div>

                <div className="grid grid-cols-4 gap-2 my-4">
                  <div className="p-3 bg-slate-50 rounded-xl text-center">
                    <p className="text-[10px] font-bold uppercase text-slate-400">Shift Time</p>
                    <p className="text-sm font-bold text-slate-800 mt-0.5">
                      {formatSecondsToHoursMins(selectedTimesheetForModal.totalGrossSeconds)}
                    </p>
                  </div>
                  <div className="p-3 bg-amber-50 rounded-xl text-center">
                    <p className="text-[10px] font-bold uppercase text-amber-700">Breaks</p>
                    <p className="text-sm font-bold text-amber-800 mt-0.5">
                      {formatSecondsToHoursMins(selectedTimesheetForModal.totalBreakSeconds)}
                    </p>
                  </div>
                  <div className="p-3 bg-indigo-50 rounded-xl text-center">
                    <p className="text-[10px] font-bold uppercase text-indigo-700">Net Worked</p>
                    <p className="text-sm font-bold text-indigo-800 mt-0.5">
                      {formatSecondsToHoursMins(selectedTimesheetForModal.totalNetWorkedSeconds)}
                    </p>
                  </div>
                  <div className="p-3 bg-emerald-50 rounded-xl text-center">
                    <p className="text-[10px] font-bold uppercase text-emerald-700">Productivity</p>
                    <p className="text-sm font-bold text-emerald-800 mt-0.5">
                      {selectedTimesheetForModal.productivityPercentage}%
                    </p>
                  </div>
                </div>

                {selectedTimesheetForModal.submissionNotes && (
                  <div className="p-3 bg-slate-50 rounded-xl border border-slate-100 text-xs mb-4">
                    <span className="font-bold text-slate-700">Employee Remarks:</span>{' '}
                    <span className="text-slate-600">{selectedTimesheetForModal.submissionNotes}</span>
                  </div>
                )}

                <div className="space-y-3">
                  <label className="text-xs font-bold text-slate-700">Manager / Admin Audit Remarks</label>
                  <textarea
                    rows={3}
                    value={reviewNotesInput}
                    onChange={(e) => setReviewNotesInput(e.target.value)}
                    placeholder="Provide audit feedback, approve for payroll, or request adjustments..."
                    className="w-full p-3 border rounded-xl border-slate-200 text-sm"
                  />
                </div>

                <div className="mt-6 flex justify-end gap-3">
                  <button
                    onClick={() => setSelectedTimesheetForModal(null)}
                    className="px-4 py-2 rounded-xl border border-slate-200 text-slate-600 font-bold text-sm hover:bg-slate-50"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => handleReviewTimesheet('Rejected')}
                    disabled={isReviewing}
                    className="px-4 py-2 rounded-xl bg-rose-50 hover:bg-rose-100 text-rose-700 font-bold text-sm transition flex items-center gap-1.5"
                  >
                    <XCircle size={16} /> Request Changes
                  </button>
                  <button
                    onClick={() => handleReviewTimesheet('Approved')}
                    disabled={isReviewing}
                    className="px-5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-sm transition shadow flex items-center gap-1.5"
                  >
                    <CheckCircle2 size={16} /> Approve Timesheet
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default TimesheetManagementView;
