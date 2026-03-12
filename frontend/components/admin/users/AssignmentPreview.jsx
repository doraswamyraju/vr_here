import React from 'react';

const AssignmentPreview = ({ employeeId, orders }) => {
  if (!employeeId) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-4 text-sm text-slate-500">
        Select an employee to preview order/task/subtask assignments.
      </div>
    );
  }

  const assignedOrders = [];

  (orders || []).forEach((order) => {
    const matchesOrderLevel = [order.assignedEmployee, order.assignedMaker, order.assignedChecker]
      .map((item) => item?._id || item)
      .filter(Boolean)
      .some((id) => String(id) === String(employeeId));

    const tasks = (order.tasks || []).filter((task) => {
      const taskMatch = [task.assignedTo, task.assignedMaker, task.assignedChecker]
        .map((item) => item?._id || item)
        .filter(Boolean)
        .some((id) => String(id) === String(employeeId));

      const subtaskMatch = (task.subtasks || []).some((subtask) =>
        [subtask.assignedToMaker, subtask.assignedToChecker]
          .map((item) => item?._id || item)
          .filter(Boolean)
          .some((id) => String(id) === String(employeeId))
      );

      return taskMatch || subtaskMatch;
    });

    if (matchesOrderLevel || tasks.length) {
      assignedOrders.push({ order, tasks });
    }
  });

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4">
      <p className="font-semibold text-slate-800">Assignment Preview</p>
      <div className="mt-3 space-y-3">
        {assignedOrders.map(({ order, tasks }) => (
          <div key={order._id} className="rounded-lg border border-slate-200 p-3">
            <p className="font-semibold text-sm text-slate-800">{order.serviceName}</p>
            <p className="text-xs text-slate-500">Order ID: {order._id.slice(-8)}</p>
            <div className="mt-2 space-y-1">
              {tasks.map((task) => (
                <p key={task._id} className="text-xs text-indigo-700">{task.taskCode ? `${task.taskCode} - ${task.title}` : task.title}</p>
              ))}
              {!tasks.length && <p className="text-xs text-slate-500">Order-level assignment only</p>}
            </div>
          </div>
        ))}
        {!assignedOrders.length && <p className="text-xs text-slate-500">No assignments found for this employee.</p>}
      </div>
    </div>
  );
};

export default AssignmentPreview;
