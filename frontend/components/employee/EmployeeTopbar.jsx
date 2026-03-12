import React from 'react';
import { Pause, Play, RefreshCw, Square } from 'lucide-react';
import { EMPLOYEE_TABS } from './constants';

const EmployeeTopbar = ({
  activeTab,
  userInfo,
  onRefresh,
  isClockedIn,
  shiftElapsedLabel,
  onClockIn,
  onClockOut,
  activeTaskDetails,
  activeTaskElapsedLabel,
  onPauseTask,
  onCompleteTask
}) => {
  const active = EMPLOYEE_TABS.find((tab) => tab.id === activeTab);

  return (
    <header className="h-20 px-4 sm:px-6 flex flex-col justify-center border-b border-slate-200/70 bg-white/60 backdrop-blur-md sticky top-0 z-20">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-xs text-slate-500">VR Here Employee Panel</p>
          <h1 className="font-bold text-xl sm:text-2xl text-slate-900">{active?.label || 'Employee Dashboard'}</h1>
        </div>
        <div className="flex items-center gap-3">
          <div className="hidden md:flex items-center gap-2 px-3 py-2 rounded-xl border border-slate-200 bg-white text-xs text-slate-600">
            <span className="text-slate-500 font-medium">Shift</span>
            <span className="font-bold text-indigo-700">{shiftElapsedLabel || '00:00:00'}</span>
            {!isClockedIn ? (
              <button onClick={onClockIn} className="inline-flex items-center px-2 py-1 rounded bg-emerald-600 text-white text-xs font-bold">
                <Play size={12} className="mr-1" />
                Clock In
              </button>
            ) : (
              <button onClick={onClockOut} className="inline-flex items-center px-2 py-1 rounded bg-rose-600 text-white text-xs font-bold">
                <Square size={12} className="mr-1" />
                Clock Out
              </button>
            )}
          </div>

          <button
            onClick={onRefresh}
            className="inline-flex items-center px-3 py-2 rounded-xl border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 text-xs sm:text-sm font-medium"
          >
            <RefreshCw size={14} className="mr-2" />
            Refresh
          </button>
          <div className="w-10 h-10 rounded-full bg-gradient-to-br from-indigo-600 to-blue-500 text-white flex items-center justify-center font-semibold text-xs">
            {userInfo?.name?.charAt(0) || 'E'}
          </div>
        </div>
      </div>

      {activeTaskDetails && (
        <div className="pt-3">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2 bg-indigo-50 border border-indigo-100 rounded-xl px-3 py-2.5">
            <div className="text-sm">
              <span className="font-bold text-indigo-700">Active Task:</span>{' '}
              <span className="text-slate-700">{activeTaskDetails.serviceName} - {activeTaskDetails.taskTitle}</span>{' '}
              <span className="font-bold text-indigo-700 ml-2">{activeTaskElapsedLabel}</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={onPauseTask}
                className="inline-flex items-center px-2.5 py-1.5 rounded bg-amber-600 text-white text-xs font-bold"
              >
                <Pause size={12} className="mr-1" />
                Pause
              </button>
              <button
                onClick={onCompleteTask}
                className="inline-flex items-center px-2.5 py-1.5 rounded bg-emerald-600 text-white text-xs font-bold"
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
