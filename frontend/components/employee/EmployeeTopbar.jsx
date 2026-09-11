import React, { useState } from 'react';
import { Pause, Play, RefreshCw, Square, Coffee, ChevronDown, Check } from 'lucide-react';
import { EMPLOYEE_TABS } from './constants';

const BREAK_OPTIONS = [
  { type: 'Lunch', label: 'Lunch Break (45m)', icon: '🍱' },
  { type: 'Tea', label: 'Tea / Snack Break (15m)', icon: '☕' },
  { type: 'Meeting', label: 'Internal Meeting', icon: '👥' },
  { type: 'Personal', label: 'Personal / Short Break', icon: '🚶' }
];

const EmployeeTopbar = ({
  activeTab,
  userInfo,
  onRefresh,
  isClockedIn,
  shiftElapsedLabel,
  onClockIn,
  onClockOut,
  activeBreak,
  breakElapsedLabel,
  onStartBreak,
  onEndBreak,
  activeTaskDetails,
  activeTaskElapsedLabel,
  onPauseTask,
  onCompleteTask
}) => {
  const active = EMPLOYEE_TABS.find((tab) => tab.id === activeTab);
  const [showBreakMenu, setShowBreakMenu] = useState(false);

  return (
    <header className="px-4 sm:px-6 py-3 border-b border-slate-200/70 bg-white/70 backdrop-blur-md sticky top-0 z-20 transition-all">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-xs text-slate-500 font-medium">VR Here Staff Workplace</p>
          <h1 className="font-extrabold text-xl sm:text-2xl text-slate-900">{active?.label || 'Employee Dashboard'}</h1>
        </div>

        <div className="flex items-center gap-3">
          {/* Shift & Break Controls */}
          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-xl border border-slate-200 bg-white shadow-xs text-xs text-slate-600">
            <span className="text-slate-500 font-medium">Shift:</span>
            <span className="font-bold font-mono text-indigo-700">{shiftElapsedLabel || '00:00:00'}</span>

            {!isClockedIn ? (
              <button
                onClick={onClockIn}
                className="inline-flex items-center px-2.5 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold transition shadow-xs"
              >
                <Play size={12} className="mr-1 fill-current" />
                Clock In
              </button>
            ) : (
              <div className="flex items-center gap-2 pl-1 border-l border-slate-200">
                {/* Break Controls */}
                {activeBreak ? (
                  <div className="flex items-center gap-1.5 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded-lg">
                    <span className="animate-pulse w-2 h-2 rounded-full bg-amber-500"></span>
                    <span className="text-[11px] font-bold text-amber-900">
                      On {activeBreak.breakType} ({breakElapsedLabel || '00:00'})
                    </span>
                    <button
                      onClick={onEndBreak}
                      className="ml-1 px-2 py-0.5 bg-emerald-600 hover:bg-emerald-700 text-white text-[10px] font-extrabold rounded shadow-xs"
                    >
                      Resume
                    </button>
                  </div>
                ) : (
                  <div className="relative">
                    <button
                      onClick={() => setShowBreakMenu(!showBreakMenu)}
                      className="inline-flex items-center px-2 py-1 rounded-lg bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-200 text-xs font-bold transition"
                    >
                      <Coffee size={12} className="mr-1" />
                      Break
                      <ChevronDown size={11} className="ml-0.5" />
                    </button>

                    {showBreakMenu && (
                      <div className="absolute right-0 mt-1 w-52 bg-white rounded-xl shadow-xl border border-slate-200 py-1.5 z-50 animate-in fade-in zoom-in-95">
                        <p className="px-3 py-1 text-[10px] uppercase tracking-wider font-extrabold text-slate-400">Take a Break</p>
                        {BREAK_OPTIONS.map((opt) => (
                          <button
                            key={opt.type}
                            onClick={() => {
                              setShowBreakMenu(false);
                              onStartBreak(opt.type);
                            }}
                            className="w-full text-left px-3 py-1.5 text-xs text-slate-700 hover:bg-amber-50 hover:text-amber-900 flex items-center gap-2 font-medium"
                          >
                            <span>{opt.icon}</span>
                            <span>{opt.label}</span>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                <button
                  onClick={onClockOut}
                  className="inline-flex items-center px-2.5 py-1 rounded-lg bg-rose-600 hover:bg-rose-700 text-white text-xs font-bold transition shadow-xs"
                >
                  <Square size={12} className="mr-1 fill-current" />
                  Clock Out
                </button>
              </div>
            )}
          </div>

          <button
            onClick={onRefresh}
            className="inline-flex items-center px-3 py-1.5 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-slate-600 text-xs sm:text-sm font-medium transition shadow-xs"
          >
            <RefreshCw size={14} className="mr-1.5" />
            Refresh
          </button>

          <div className="w-9 h-9 rounded-full bg-gradient-to-br from-indigo-600 to-blue-500 text-white flex items-center justify-center font-bold text-xs shadow-xs">
            {userInfo?.name?.charAt(0) || 'E'}
          </div>
        </div>
      </div>

      {activeTaskDetails && (
        <div className="mt-2.5">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2 bg-indigo-50 border border-indigo-100 rounded-xl px-3 py-2 shadow-xs">
            <div className="text-xs">
              <span className="font-extrabold text-indigo-700">Active Task:</span>{' '}
              <span className="text-slate-800 font-semibold">{activeTaskDetails.serviceName} - {activeTaskDetails.taskTitle}</span>{' '}
              <span className="font-mono font-extrabold text-indigo-700 ml-2 bg-indigo-100 px-1.5 py-0.5 rounded">{activeTaskElapsedLabel}</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={onPauseTask}
                className="inline-flex items-center px-2.5 py-1 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-xs font-bold transition"
              >
                <Pause size={12} className="mr-1" />
                Pause
              </button>
              <button
                onClick={onCompleteTask}
                className="inline-flex items-center px-2.5 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold transition"
              >
                <Square size={12} className="mr-1" />
                Complete
              </button>
            </div>
          </div>
        </div>
      )}
    </header>
  );
};

export default EmployeeTopbar;
