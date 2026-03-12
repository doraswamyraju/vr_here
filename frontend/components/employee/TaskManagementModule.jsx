import React from 'react';
import { CheckSquare } from 'lucide-react';

const columns = ['Pending', 'In Progress', 'Completed'];

const TaskManagementModule = ({
  selectedOrder,
  setSelectedOrder,
  onTaskStatusChange,
  onUpdateSubtask,
  activeTaskSession,
  activeTaskElapsedSeconds,
  onStartTask,
  onPauseTask,
  onCompleteTask,
  isClockedIn
}) => {
  if (!selectedOrder) {
    return (
      <div className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] p-6 text-sm text-slate-500">
        Select an order from Work Queue or Order Processing to manage tasks.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] p-4 flex items-center justify-between">
        <div>
          <h3 className="font-bold text-slate-800">Task Board</h3>
          <p className="text-sm text-slate-500">{selectedOrder.serviceName}</p>
          {!isClockedIn && (
            <p className="text-xs text-rose-600 font-semibold mt-1">
              Clock in first to start any task timer.
            </p>
          )}
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
                      <div>
                        <p className="font-semibold text-sm text-slate-700">{task.taskCode ? `${task.taskCode} - ${task.title}` : task.title}</p>
                        <p className="text-[10px] text-slate-500">
                          Maker: {task.assignedMaker?.name || 'Unassigned'} | Checker: {task.assignedChecker?.name || 'Unassigned'}
                        </p>
                      </div>
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
                        <div key={subtask._id} className="rounded-md border border-slate-200 p-2">
                          <label className="flex items-center gap-2 text-xs">
                            <input
                              type="checkbox"
                              checked={Boolean(subtask.isCompleted)}
                              onChange={(event) => onUpdateSubtask(selectedOrder._id, task._id, subtask._id, { isCompleted: event.target.checked })}
                            />
                            <span className={subtask.isCompleted ? 'line-through text-slate-400' : 'text-slate-600'}>
                              {subtask.subTaskCode ? `${subtask.subTaskCode} - ${subtask.title}` : subtask.title}
                            </span>
                          </label>
                          <div className="mt-1 flex items-center justify-between gap-2">
                            <span className="text-[10px] text-slate-500">Maker: {subtask.assignedToMaker?.name || 'Unassigned'} | Checker: {subtask.assignedToChecker?.name || 'Unassigned'}</span>
                            <select
                              value={subtask.status || 'Pending'}
                              onChange={(event) => onUpdateSubtask(selectedOrder._id, task._id, subtask._id, { status: event.target.value })}
                              className="text-[10px] p-1 border rounded border-slate-300"
                            >
                              <option value="Pending">Pending</option>
                              <option value="In Progress">In Progress</option>
                              <option value="Completed">Completed</option>
                            </select>
                          </div>
                        </div>
                      ))}
                    </div>

                    <div className="mt-3 flex items-center gap-2 flex-wrap">
                      {activeTaskSession?.orderId === selectedOrder._id && activeTaskSession?.taskId === task._id ? (
                        <>
                          <span className="text-[11px] font-bold text-indigo-700 bg-indigo-50 px-2 py-1 rounded">
                            Running: {new Date(activeTaskElapsedSeconds * 1000).toISOString().slice(11, 19)}
                          </span>
                          <button
                            onClick={onPauseTask}
                            className="text-[10px] px-2 py-1 rounded bg-amber-100 text-amber-700 font-bold"
                          >
                            Pause
                          </button>
                          <button
                            onClick={onCompleteTask}
                            className="text-[10px] px-2 py-1 rounded bg-emerald-100 text-emerald-700 font-bold"
                          >
                            Complete
                          </button>
                        </>
                      ) : (
                        <>
                          <button
                            onClick={() => onStartTask({
                              orderId: selectedOrder._id,
                              taskId: task._id,
                              serviceName: selectedOrder.serviceName,
                              taskTitle: task.title
                            })}
                            disabled={!isClockedIn || Boolean(activeTaskSession)}
                            className="text-[10px] px-2 py-1 rounded bg-indigo-100 text-indigo-700 font-bold disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            Start
                          </button>
                          {!isClockedIn ? (
                            <span className="text-[10px] text-rose-600 font-semibold">
                              Clock in required
                            </span>
                          ) : activeTaskSession ? (
                            <span className="text-[10px] text-rose-600 font-semibold">
                              One task at a time
                            </span>
                          ) : null}
                        </>
                      )}
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
