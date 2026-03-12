import React from 'react';
import { formatDuration, toHours } from './helpers';

const WorkloadPanel = ({ attendanceSummary }) => (
  <div className="rounded-xl border border-slate-200 bg-white p-4">
    <p className="font-semibold text-slate-800">Time Analytics (Attendance vs Task Logs)</p>
    <p className="text-xs text-slate-500 mb-3">Worked hours from clock-in/out and tracked hours from task logs.</p>
    <div className="space-y-2">
      {(attendanceSummary.items || []).map((item) => (
        <div key={item.employeeId} className="rounded-lg border border-slate-200 p-3">
          <div className="flex items-center justify-between gap-2">
            <p className="font-semibold text-sm text-slate-800">{item.employeeName}</p>
            <span className="text-xs px-2 py-1 rounded-full bg-indigo-100 text-indigo-700 font-semibold">{item.productivityPercent}% tracked</span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Worked: {formatDuration(item.workedSeconds)} | Tracked: {toHours(item.trackedMinutes)}h | Untracked: {toHours(item.untrackedMinutes)}h
          </p>
        </div>
      ))}
      {!attendanceSummary.items?.length && <p className="text-xs text-slate-500">No attendance records in selected range.</p>}
    </div>
  </div>
);

export default WorkloadPanel;
