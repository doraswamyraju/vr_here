import React, { useState } from 'react';
import { Upload } from 'lucide-react';
import { TASK_STATUSES } from './constants';

const AssignmentSelect = ({ value, employees, onChange, label = 'Unassigned' }) => (
  <select
    value={value || ''}
    onChange={(event) => onChange(event.target.value || null)}
    className="p-2 border rounded-lg border-slate-300 bg-white text-xs"
  >
    <option value="">{label}</option>
    {employees.map((employee) => (
      <option key={employee._id} value={employee._id}>{employee.name}</option>
    ))}
  </select>
);

const OrderTasksTab = ({
  selectedOrder,
  employees,
  onTaskStatusChange,
  onTaskAssign,
  onSubtaskUpdate,
  onImportTaskWorkbook
}) => {
  const [taskFile, setTaskFile] = useState(null);
  const [replaceExisting, setReplaceExisting] = useState(true);
  const [isImporting, setIsImporting] = useState(false);

  const handleImport = async () => {
    if (!taskFile) return;
    setIsImporting(true);
    try {
      await onImportTaskWorkbook(taskFile, replaceExisting);
      setTaskFile(null);
    } finally {
      setIsImporting(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-slate-200 p-4 bg-slate-50">
        <p className="font-semibold text-slate-700 mb-2">Import Tasks & Sub Tasks (Excel)</p>
        <p className="text-xs text-slate-500 mb-3">Use sheet names: `Parent Tasks` and `Sub Tasks`.</p>
        <div className="flex flex-wrap items-center gap-3">
          <input type="file" accept=".xlsx,.xls" onChange={(event) => setTaskFile(event.target.files?.[0] || null)} className="text-sm" />
          <label className="text-xs text-slate-600 inline-flex items-center gap-1">
            <input type="checkbox" checked={replaceExisting} onChange={(event) => setReplaceExisting(event.target.checked)} />
            Replace existing tasks
          </label>
          <button
            onClick={handleImport}
            disabled={!taskFile || isImporting}
            className="px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-semibold disabled:opacity-50 inline-flex items-center gap-1"
          >
            <Upload size={14} />
            {isImporting ? 'Importing...' : 'Import Workbook'}
          </button>
        </div>
      </div>

      <div className="space-y-3">
        {(selectedOrder.tasks || []).map((task) => (
          <div key={task._id} className="rounded-xl border border-slate-200 p-4 bg-white">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="font-semibold text-slate-800">{task.taskCode ? `${task.taskCode} - ${task.title}` : task.title}</p>
                <p className="text-xs text-slate-500">{task.description || '-'}</p>
              </div>
              <select
                value={task.status}
                onChange={(event) => onTaskStatusChange(task._id, event.target.value)}
                className="p-2 border rounded-lg border-slate-300 bg-white text-xs"
              >
                {TASK_STATUSES.map((status) => (
                  <option key={status} value={status}>{status}</option>
                ))}
              </select>
            </div>

            <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-2">
              <div>
                <p className="text-[11px] text-slate-500 mb-1">Task Owner</p>
                <AssignmentSelect
                  value={task.assignedTo?._id || task.assignedTo}
                  employees={employees}
                  onChange={(employeeId) => onTaskAssign(task._id, { employeeId })}
                />
              </div>
              <div>
                <p className="text-[11px] text-slate-500 mb-1">Maker</p>
                <AssignmentSelect
                  value={task.assignedMaker?._id || task.assignedMaker}
                  employees={employees}
                  onChange={(makerId) => onTaskAssign(task._id, { makerId })}
                />
              </div>
              <div>
                <p className="text-[11px] text-slate-500 mb-1">Checker</p>
                <AssignmentSelect
                  value={task.assignedChecker?._id || task.assignedChecker}
                  employees={employees}
                  onChange={(checkerId) => onTaskAssign(task._id, { checkerId })}
                />
              </div>
            </div>

            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-xs min-w-[700px]">
                <thead className="text-slate-500 uppercase">
                  <tr>
                    <th className="text-left py-2">Sub Task</th>
                    <th className="text-left py-2">Maker</th>
                    <th className="text-left py-2">Checker</th>
                    <th className="text-left py-2">Status</th>
                    <th className="text-left py-2">Done</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {(task.subtasks || []).map((subtask) => (
                    <tr key={subtask._id}>
                      <td className="py-2">
                        <p className="font-medium text-slate-700">{subtask.subTaskCode ? `${subtask.subTaskCode} - ${subtask.title}` : subtask.title}</p>
                        <p className="text-[11px] text-slate-500">{subtask.duration ? `Duration: ${subtask.duration}` : ''}</p>
                      </td>
                      <td className="py-2">
                        <AssignmentSelect
                          value={subtask.assignedToMaker?._id || subtask.assignedToMaker}
                          employees={employees}
                          onChange={(makerId) => onSubtaskUpdate(task._id, subtask._id, { makerId })}
                        />
                      </td>
                      <td className="py-2">
                        <AssignmentSelect
                          value={subtask.assignedToChecker?._id || subtask.assignedToChecker}
                          employees={employees}
                          onChange={(checkerId) => onSubtaskUpdate(task._id, subtask._id, { checkerId })}
                        />
                      </td>
                      <td className="py-2">
                        <select
                          value={subtask.status || 'Pending'}
                          onChange={(event) => onSubtaskUpdate(task._id, subtask._id, { status: event.target.value })}
                          className="p-2 border rounded-lg border-slate-300 bg-white text-xs"
                        >
                          {TASK_STATUSES.map((status) => (
                            <option key={status} value={status}>{status}</option>
                          ))}
                        </select>
                      </td>
                      <td className="py-2">
                        <input
                          type="checkbox"
                          checked={Boolean(subtask.isCompleted)}
                          onChange={(event) => onSubtaskUpdate(task._id, subtask._id, { isCompleted: event.target.checked })}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default OrderTasksTab;
