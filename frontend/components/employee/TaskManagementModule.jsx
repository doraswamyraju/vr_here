import React from 'react';
import { CheckSquare } from 'lucide-react';

const columns = ['Pending', 'In Progress', 'Completed'];

const TaskManagementModule = ({
  selectedOrder,
  setSelectedOrder,
  onTaskStatusChange,
  onToggleSubtask
}) => {
  if (!selectedOrder) {
    return (
      <div className="bg-white rounded-2xl border border-slate-200 p-6 text-sm text-slate-500">
        Select an order from Work Queue or Order Processing to manage tasks.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="bg-white border border-slate-200 rounded-xl p-4 flex items-center justify-between">
        <div>
          <h3 className="font-bold text-slate-800">Task Board</h3>
          <p className="text-sm text-slate-500">{selectedOrder.serviceName}</p>
        </div>
        <button className="text-sm text-indigo-600 font-semibold" onClick={() => setSelectedOrder(null)}>
          Change Order
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {columns.map((column) => (
          <div key={column} className="bg-slate-50 rounded-xl border border-slate-200 p-4 min-h-[260px]">
            <h4 className="text-xs uppercase tracking-wide text-slate-500 font-bold mb-3">{column}</h4>
            <div className="space-y-3">
              {(selectedOrder.tasks || [])
                .filter((task) => task.status === column)
                .map((task) => (
                  <div key={task._id} className="bg-white p-3 rounded-lg border border-slate-200">
                    <div className="flex items-start justify-between">
                      <p className="font-semibold text-sm text-slate-700">{task.title}</p>
                      <button
                        onClick={() => {
                          const nextStatus =
                            column === 'Pending'
                              ? 'In Progress'
                              : column === 'In Progress'
                                ? 'Completed'
                                : 'Pending';
                          onTaskStatusChange(selectedOrder._id, task._id, nextStatus);
                        }}
                        className="text-[10px] px-2 py-1 rounded bg-indigo-50 text-indigo-700 font-bold"
                      >
                        Move
                      </button>
                    </div>
                    <div className="mt-2 space-y-2">
                      {(task.subtasks || []).map((subtask) => (
                        <label key={subtask._id} className="flex items-center gap-2 text-xs">
                          <input
                            type="checkbox"
                            checked={Boolean(subtask.isCompleted)}
                            onChange={() => onToggleSubtask(selectedOrder._id, task._id, subtask._id)}
                          />
                          <span className={subtask.isCompleted ? 'line-through text-slate-400' : 'text-slate-600'}>
                            {subtask.title}
                          </span>
                        </label>
                      ))}
                    </div>
                  </div>
                ))}
            </div>
          </div>
        ))}
      </div>

      <div className="bg-indigo-50 rounded-xl border border-indigo-100 p-4 text-sm text-indigo-700">
        <CheckSquare className="inline mr-2" size={16} />
        Placeholder-ready: add task creation, reassignment, and due-date management module here.
      </div>
    </div>
  );
};

export default TaskManagementModule;

