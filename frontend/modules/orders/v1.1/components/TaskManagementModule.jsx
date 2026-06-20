import React, { useMemo, useState } from 'react';
import { CheckSquare, Kanban, List } from 'lucide-react';

const columns = ['Pending', 'In Progress', 'Completed'];
const statusPriority = {
  'In Progress': 0,
  'Pending Documents': 1,
  'Documents Verified': 2,
  'Processing at Portal': 3,
  'Waiting for Clarification': 4,
  Completed: 5
};

const normalizeId = (value) => {
  if (!value) return '';
  if (typeof value === 'string') return value;
  if (value?._id) return String(value._id);
  return String(value);
};

const TaskManagementModule = ({
  orders,
  userInfo,
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
  const [viewMode, setViewMode] = useState('list');
  const employeeId = userInfo?._id ? String(userInfo._id) : '';

  const projectTasks = useMemo(() => {
    const mapped = (orders || [])
      .map((order) => {
        const tasks = (order.tasks || []).filter((task) => {
          const taskAssignees = [
            task.assignedTo,
            task.assignedMaker,
            task.assignedChecker
          ].map(normalizeId).filter(Boolean);

          const subtaskAssignees = (task.subtasks || [])
            .flatMap((subtask) => [subtask.assignedToMaker, subtask.assignedToChecker])
            .map(normalizeId)
            .filter(Boolean);

          if (!employeeId) return false;
          return [...taskAssignees, ...subtaskAssignees].includes(employeeId);
        });

        return { order, tasks };
      })
      .filter((item) => item.tasks.length > 0)
      .sort((a, b) => {
        const rankA = statusPriority[a.order.status] ?? 99;
        const rankB = statusPriority[b.order.status] ?? 99;
        if (rankA !== rankB) return rankA - rankB;
        return new Date(a.order.createdAt || 0).getTime() - new Date(b.order.createdAt || 0).getTime();
      });

    return mapped;
  }, [orders, employeeId]);

  const boardOrder = selectedOrder || projectTasks[0]?.order || null;
  const boardTasks = useMemo(() => {
    if (!boardOrder) return [];
    const fromMap = projectTasks.find((item) => item.order._id === boardOrder._id);
    return fromMap?.tasks || [];
  }, [projectTasks, boardOrder]);

  const renderTaskActions = (order, task) => {
    if (task.status === 'Completed') {
      return (
        <span className="text-[10px] px-2 py-1 rounded bg-emerald-100 text-emerald-700 font-bold border border-emerald-200">
          Completed
        </span>
      );
    }

    const isActiveCurrent = activeTaskSession?.orderId === order._id && activeTaskSession?.taskId === task._id;
    if (isActiveCurrent) {
      return (
        <div className="flex flex-col items-end gap-2">
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-bold text-indigo-700 bg-indigo-50 px-2 py-1 rounded">
              Running: {new Date(activeTaskElapsedSeconds * 1000).toISOString().slice(11, 19)}
            </span>
            <button onClick={onPauseTask} className="text-[10px] px-2 py-1 rounded bg-amber-100 text-amber-700 font-bold hover:bg-amber-200 transition">Pause</button>
            <button onClick={onCompleteTask} className="text-[10px] px-2 py-1 rounded bg-emerald-100 text-emerald-700 font-bold hover:bg-emerald-200 transition">Complete</button>
          </div>
          {(task.subtasks || []).length > 0 && (
            <div className="flex flex-wrap items-center justify-end gap-2 mt-1 max-w-md">
              {task.subtasks.map(subtask => (
                <label key={subtask._id} className="flex items-center gap-1.5 text-[10px] font-medium bg-slate-50 border border-slate-200 px-2 py-1 rounded cursor-pointer hover:bg-slate-100 transition">
                  <input
                    type="checkbox"
                    className="w-3 h-3 text-indigo-600 rounded border-slate-300 focus:ring-indigo-500 cursor-pointer"
                    checked={Boolean(subtask.isCompleted)}
                    onChange={(e) => onUpdateSubtask(order._id, task._id, subtask._id, { isCompleted: e.target.checked })}
                  />
                  <span className={subtask.isCompleted ? 'line-through text-slate-400' : 'text-slate-700'}>
                    {subtask.subTaskCode ? `${subtask.subTaskCode} - ` : ''}{subtask.title}
                  </span>
                </label>
              ))}
            </div>
          )}
        </div>
      );
    }

    return (
      <div className="flex items-center gap-2">
        <button
          onClick={() => onStartTask({
            orderId: order._id,
            taskId: task._id,
            serviceName: order.serviceName,
            taskTitle: task.title
          })}
          disabled={!isClockedIn || Boolean(activeTaskSession)}
          className="text-[10px] px-2 py-1 rounded bg-indigo-100 text-indigo-700 font-bold disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Start
        </button>
        {!isClockedIn ? (
          <span className="text-[10px] text-rose-600 font-semibold">Clock in required</span>
        ) : activeTaskSession ? (
          <span className="text-[10px] text-rose-600 font-semibold">One task at a time</span>
        ) : null}
      </div>
    );
  };

  return (
    <div className="space-y-4">
      <div className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] p-4 flex items-center justify-between">
        <div>
          <h3 className="font-bold text-slate-800">Assigned Project Tasks</h3>
          <p className="text-sm text-slate-500">Projects are ordered by priority and current status.</p>
          {!isClockedIn && (
            <p className="text-xs text-rose-600 font-semibold mt-1">
              Clock in first to start any task timer.
            </p>
          )}
        </div>
        <div className="inline-flex rounded-lg border border-slate-200 bg-white overflow-hidden">
          <button onClick={() => setViewMode('list')} className={`px-3 py-2 text-sm flex items-center gap-1 ${viewMode === 'list' ? 'bg-indigo-50 text-indigo-700' : 'text-slate-600'}`}>
            <List size={14} /> List
          </button>
          <button onClick={() => setViewMode('board')} className={`px-3 py-2 text-sm flex items-center gap-1 ${viewMode === 'board' ? 'bg-indigo-50 text-indigo-700' : 'text-slate-600'}`}>
            <Kanban size={14} /> Board
          </button>
        </div>
      </div>

      {viewMode === 'list' && (
        <div className="space-y-4">
          {projectTasks.map(({ order, tasks }, index) => (
            <div key={order._id} className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] p-4">
              <div className="flex items-center justify-between gap-3 mb-3">
                <div>
                  <p className="text-xs text-slate-500">Priority #{index + 1}</p>
                  <h4 className="font-bold text-slate-800">{order.serviceName}</h4>
                  <p className="text-xs text-slate-500">Status: {order.status}</p>
                </div>
                <button className="text-sm text-indigo-600 font-semibold" onClick={() => setSelectedOrder(order)}>
                  Open Board
                </button>
              </div>
              <div className="space-y-3">
                {tasks.map((task) => (
                  <div key={task._id} className="rounded-lg border border-slate-200 p-3 bg-white">
                    <div className="flex items-center justify-between gap-2">
                      <div>
                        <p className="font-semibold text-sm text-slate-700">{task.taskCode ? `${task.taskCode} - ${task.title}` : task.title}</p>
                        <p className="text-[10px] text-slate-500">Task Status: {task.status || 'Pending'}</p>
                      </div>
                      {renderTaskActions(order, task)}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
          {projectTasks.length === 0 && (
            <div className="rounded-2xl border border-dashed border-slate-300 bg-white/80 p-6 text-sm text-slate-500">
              No assigned tasks yet for your user.
            </div>
          )}
        </div>
      )}

      {viewMode === 'board' && (
        <div className="space-y-3">
          <div className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] p-4 flex items-center justify-between">
            <div>
              <h4 className="font-bold text-slate-800">{boardOrder?.serviceName || 'No Project Selected'}</h4>
              <p className="text-xs text-slate-500">Showing assigned tasks in board format.</p>
            </div>
            <select
              value={boardOrder?._id || ''}
              onChange={(event) => {
                const order = projectTasks.find((item) => item.order._id === event.target.value)?.order || null;
                setSelectedOrder(order);
              }}
              className="p-2 border rounded-lg border-slate-300 bg-white text-sm"
            >
              {projectTasks.map((item) => (
                <option key={item.order._id} value={item.order._id}>{item.order.serviceName}</option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {columns.map((column) => (
              <div key={column} className="bg-slate-50 rounded-xl border border-slate-200 p-4 min-h-[260px]">
                <h4 className="text-xs uppercase tracking-wide text-slate-500 font-bold mb-3">{column}</h4>
                <div className="space-y-3">
                  {boardTasks
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
                              if (!isClockedIn) {
                                alert('Please clock in before moving tasks.');
                                return;
                              }
                              const nextStatus =
                                column === 'Pending' ? 'In Progress' : column === 'In Progress' ? 'Completed' : 'Pending';
                              onTaskStatusChange(boardOrder._id, task._id, nextStatus);
                            }}
                            className="text-[10px] px-2 py-1 rounded bg-indigo-50 text-indigo-700 font-bold disabled:opacity-50"
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
                                  onChange={(event) => {
                                    if (!isClockedIn) {
                                      alert('Please clock in before updating subtasks.');
                                      return;
                                    }
                                    onUpdateSubtask(boardOrder._id, task._id, subtask._id, { isCompleted: event.target.checked });
                                  }}
                                />
                                <span className={subtask.isCompleted ? 'line-through text-slate-400' : 'text-slate-600'}>
                                  {subtask.subTaskCode ? `${subtask.subTaskCode} - ${subtask.title}` : subtask.title}
                                </span>
                              </label>
                              <div className="mt-1 flex items-center justify-between gap-2">
                                <span className="text-[10px] text-slate-500">
                                  Maker: {subtask.assignedToMaker?.name || 'Unassigned'} | Checker: {subtask.assignedToChecker?.name || 'Unassigned'}
                                </span>
                                <select
                                  value={subtask.status || 'Pending'}
                                  onChange={(event) => {
                                    if (!isClockedIn) {
                                      alert('Please clock in before updating subtasks.');
                                      return;
                                    }
                                    onUpdateSubtask(boardOrder._id, task._id, subtask._id, { status: event.target.value });
                                  }}
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
                          {renderTaskActions(boardOrder, task)}
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="bg-indigo-50 rounded-xl border border-indigo-100 p-4 text-sm text-indigo-700">
        <CheckSquare className="inline mr-2" size={16} />
        Task actions track live timer and one-active-task rule across all projects.
      </div>
    </div>
  );
};

export default TaskManagementModule;
