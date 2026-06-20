import React, { useState } from 'react';
import { Upload, Plus, Trash2, ListPlus } from 'lucide-react';
import { TASK_STATUSES } from '../constants/constants';

const OrderTasksTab = ({
  selectedOrder,
  employees,
  freelancers = [],
  onTaskStatusChange,
  onTaskAssign,
  onSubtaskUpdate,
  onImportTaskWorkbook,
  onAddTask
}) => {
  const AssignmentSelect = ({ value, employees: _ignored, onChange, label = 'Unassigned' }) => (
    <select
      value={value || ''}
      onChange={(event) => onChange(event.target.value || null)}
      className="p-2 border rounded-lg border-slate-300 bg-white text-xs"
    >
      <option value="">{label}</option>
      {employees && employees.length > 0 && (
        <optgroup label="Employees">
          {employees.map((employee) => (
            <option key={employee._id} value={employee._id}>{employee.name}</option>
          ))}
        </optgroup>
      )}
      {freelancers && freelancers.length > 0 && (
        <optgroup label="Freelancers">
          {freelancers.map((freelancer) => (
            <option key={freelancer._id} value={freelancer._id}>{freelancer.name}</option>
          ))}
        </optgroup>
      )}
    </select>
  );
  const [taskFile, setTaskFile] = useState(null);
  const [replaceExisting, setReplaceExisting] = useState(true);
  const [isImporting, setIsImporting] = useState(false);
  const [showManualForm, setShowManualForm] = useState(false);
  const [newTaskTitle, setNewTaskTitle] = useState('');
  const [newTaskMaker, setNewTaskMaker] = useState('');
  const [newTaskChecker, setNewTaskChecker] = useState('');
  const [newSubtasks, setNewSubtasks] = useState([]);
  const [manualLoading, setManualLoading] = useState(false);

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
          
          <div className="h-4 w-px bg-slate-200 mx-1 hidden sm:block"></div>
          
          <button
            onClick={() => setShowManualForm(!showManualForm)}
            className="px-4 py-2 rounded-lg bg-white border border-indigo-600 text-indigo-700 text-sm font-bold hover:bg-slate-900 hover:text-white transition-all inline-flex items-center gap-1"
          >
            <Plus size={14} />
            {showManualForm ? 'Discard Manual' : 'Add Manual Task'}
          </button>
        </div>

        {showManualForm && (
           <div className="mt-4 p-4 bg-white rounded-xl border border-indigo-100 space-y-4 animate-fade-in shadow-sm shadow-indigo-100">
              <div className="space-y-2">
                 <label className="text-[10px] uppercase font-black text-slate-400 tracking-widest">Main Task Title</label>
                 <input 
                   value={newTaskTitle}
                   onChange={(e) => setNewTaskTitle(e.target.value)}
                   placeholder="e.g. GST Returns Preparation"
                   className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold focus:ring-2 focus:ring-indigo-500 outline-none"
                 />
              </div>

              <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                     <label className="text-[10px] uppercase font-black text-slate-400 tracking-widest">Main Task Maker</label>
                     <AssignmentSelect 
                       value={newTaskMaker} 
                       employees={employees} 
                       onChange={setNewTaskMaker} 
                       label="Select Maker"
                     />
                  </div>
                  <div className="space-y-1.5">
                     <label className="text-[10px] uppercase font-black text-slate-400 tracking-widest">Main Task Checker</label>
                     <AssignmentSelect 
                       value={newTaskChecker} 
                       employees={employees} 
                       onChange={setNewTaskChecker} 
                       label="Select Checker"
                     />
                  </div>
               </div>

              <div className="space-y-2">
                 <label className="text-[10px] uppercase font-black text-slate-400 tracking-widest flex items-center justify-between">
                    Sub-Tasks & Assignments
                    <button 
                      onClick={() => setNewSubtasks([...newSubtasks, { title: '', makerId: '', checkerId: '', id: Math.random() }])}
                      className="text-indigo-600 hover:underline normal-case font-bold"
                    >
                      + Add Item
                    </button>
                 </label>
                 <div className="space-y-2">
                    {newSubtasks.map((sub, idx) => (
                       <div key={sub.id} className="flex gap-2">
                          <input 
                            value={sub.title}
                            onChange={(e) => {
                               const updated = [...newSubtasks];
                               updated[idx].title = e.target.value;
                               setNewSubtasks(updated);
                            }}
                            placeholder={`Step ${idx + 1}`}
                            className="flex-1 p-2 bg-slate-50 border border-slate-100 rounded-lg text-xs outline-none"
                          />
                          <AssignmentSelect 
                             value={sub.makerId} 
                             employees={employees} 
                             onChange={(id) => {
                                const updated = [...newSubtasks];
                                updated[idx].makerId = id;
                                setNewSubtasks(updated);
                             }} 
                             label="Maker"
                           />
                           <AssignmentSelect 
                             value={sub.checkerId} 
                             employees={employees} 
                             onChange={(id) => {
                                const updated = [...newSubtasks];
                                updated[idx].checkerId = id;
                                setNewSubtasks(updated);
                             }} 
                             label="Checker"
                           />
                          <button 
                            onClick={() => setNewSubtasks(newSubtasks.filter((_, i) => i !== idx))}
                            className="p-2 text-rose-500 hover:bg-rose-50 rounded-lg"
                          >
                             <Trash2 size={14} />
                          </button>
                       </div>
                    ))}
                    {newSubtasks.length === 0 && <p className="text-[11px] text-slate-400 italic">No sub-tasks added yet.</p>}
                 </div>
              </div>

              <div className="pt-2">
                 <button 
                    disabled={!newTaskTitle || manualLoading}
                    onClick={async () => {
                       setManualLoading(true);
                       try {
                          await onAddTask(selectedOrder._id, {
                             title: newTaskTitle,
                             assignedMaker: newTaskMaker || null,
                             assignedChecker: newTaskChecker || null,
                             subtasks: newSubtasks.map(s => ({ 
                                title: s.title,
                                assignedToMaker: s.makerId || null,
                                assignedToChecker: s.checkerId || null
                             }))
                          });
                          setNewTaskTitle('');
                          setNewTaskMaker('');
                          setNewTaskChecker('');
                          setNewSubtasks([]);
                          setShowManualForm(false);
                       } finally {
                          setManualLoading(false);
                       }
                    }}
                    className="w-full py-3 bg-indigo-600 text-white rounded-xl font-black text-sm shadow-xl shadow-indigo-100 hover:bg-slate-900 transition-all flex items-center justify-center gap-2"
                 >
                    {manualLoading ? 'Processing...' : <><ListPlus size={18} /> Confirm Add Task</>}
                 </button>
              </div>
           </div>
        )}
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

        {/* Render Linked TODOs */}
        {(selectedOrder.linkedTodos || []).map((todo) => (
          <div key={todo._id} className="rounded-xl border border-indigo-100 bg-indigo-50/30 p-4 border-dashed">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-[10px] uppercase font-bold text-indigo-500 tracking-wider">Linked TODO Task</p>
                <p className="font-bold text-slate-800">{todo.title}</p>
                {todo.description && <p className="text-xs text-slate-500">{todo.description}</p>}
                {todo.priority && <span className="text-[10px] font-black uppercase text-indigo-600 bg-indigo-100 px-1.5 py-0.5 rounded-full mt-1 inline-block">{todo.priority}</span>}
              </div>
              <div className="flex items-center gap-3">
                <div className="text-right">
                   <p className="text-[10px] uppercase font-bold text-slate-400">Status</p>
                   <p className="text-sm font-bold text-slate-700">{todo.status}</p>
                </div>
                <div className="text-right border-l pl-3 border-indigo-100">
                   <p className="text-[10px] uppercase font-bold text-slate-400">Assigned To</p>
                   <p className="text-sm font-bold text-slate-700">{todo.assignedTo?.name || 'Unassigned'}</p>
                </div>
              </div>
            </div>
          </div>
        ))}

        {(selectedOrder.tasks || []).length === 0 && (selectedOrder.linkedTodos || []).length === 0 && (
          <div className="py-20 flex flex-col items-center justify-center bg-slate-50 border-2 border-dashed rounded-3xl">
            <p className="text-slate-400 font-bold">No tasks assigned yet.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default OrderTasksTab;
