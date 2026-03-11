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
    <header className="bg-white/90 backdrop-blur-md border-b border-slate-200 sticky top-0 z-20">
      <div className="h-16 flex items-center justify-between px-6">
        <h1 className="text-xl font-bold text-slate-800">{active?.label || 'Employee Dashboard'}</h1>
        <div className="flex items-center gap-3">
          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-200 bg-slate-50 text-sm">
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
            className="inline-flex items-center px-3 py-1.5 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 text-sm font-medium"
          >
            <RefreshCw size={14} className="mr-2" />
            Refresh
          </button>
          <div className="w-8 h-8 rounded-full bg-indigo-100 text-indigo-700 flex items-center justify-center font-bold text-xs">
            {userInfo?.name?.charAt(0) || 'E'}
          </div>
        </div>
      </div>

      {activeTaskDetails && (
        <div className="px-6 pb-3">
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
