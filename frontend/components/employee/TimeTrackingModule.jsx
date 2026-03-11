import React, { useMemo, useState } from 'react';

const TimeTrackingModule = ({
  orders,
  selectedOrder,
  setSelectedOrder,
  onLogTime,
  activeTaskSession,
  activeTaskElapsedSeconds
}) => {
  const [selectedOrderId, setSelectedOrderId] = useState(selectedOrder?._id || '');
  const [selectedTaskId, setSelectedTaskId] = useState('');
  const [manualMinutes, setManualMinutes] = useState('');
  const [manualNotes, setManualNotes] = useState('');

  const currentOrder = useMemo(
    () => orders.find((order) => order._id === selectedOrderId) || null,
    [orders, selectedOrderId]
  );

  const currentTasks = currentOrder?.tasks || [];

  const projectSummary = useMemo(() => {
    return orders
      .map((order) => {
        const minutes = (order.tasks || []).reduce((sum, task) => sum + Number(task.totalMinutes || 0), 0);
        return {
          orderId: order._id,
          serviceName: order.serviceName,
          minutes,
          hours: (minutes / 60).toFixed(2)
        };
      })
      .filter((item) => item.minutes > 0)
      .sort((a, b) => b.minutes - a.minutes);
  }, [orders]);

  const taskSummary = useMemo(() => {
    const rows = [];
    orders.forEach((order) => {
      (order.tasks || []).forEach((task) => {
        const minutes = Number(task.totalMinutes || 0);
        if (minutes > 0) {
          rows.push({
            key: `${order._id}-${task._id}`,
            serviceName: order.serviceName,
            taskTitle: task.title,
            minutes,
            hours: (minutes / 60).toFixed(2)
          });
        }
      });
    });
    return rows.sort((a, b) => b.minutes - a.minutes);
  }, [orders]);

  const totalTrackedMinutes = useMemo(
    () => taskSummary.reduce((sum, row) => sum + row.minutes, 0),
    [taskSummary]
  );

  const submitManualLog = async (event) => {
    event.preventDefault();
    if (!selectedOrderId || !selectedTaskId || !manualMinutes) return;

    await onLogTime(selectedOrderId, selectedTaskId, Number(manualMinutes), manualNotes);
    setManualMinutes('');
    setManualNotes('');
  };

  const activeTimerLabel = new Date((activeTaskElapsedSeconds || 0) * 1000).toISOString().slice(11, 19);

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-2xl border border-slate-200 p-6">
        <h3 className="font-bold text-slate-800 mb-2">Live Task Tracker</h3>
        {activeTaskSession ? (
          <p className="text-sm text-indigo-700 font-semibold">
            Running timer is controlled from Task Management. Elapsed: {activeTimerLabel}
          </p>
        ) : (
          <p className="text-sm text-slate-500">No active running task timer. Start one from Task Management tab.</p>
        )}
      </div>

      <div className="bg-white rounded-2xl border border-slate-200 p-6">
        <h3 className="font-bold text-slate-800 mb-3">Manual Time Log (Optional)</h3>
        <form onSubmit={submitManualLog} className="grid grid-cols-1 lg:grid-cols-4 gap-3">
          <select
            value={selectedOrderId}
            onChange={(e) => {
              const nextOrderId = e.target.value;
              setSelectedOrderId(nextOrderId);
              setSelectedTaskId('');
              const order = orders.find((item) => item._id === nextOrderId);
              if (order) setSelectedOrder(order);
            }}
            className="p-3 border border-slate-200 rounded-lg text-sm"
            required
          >
            <option value="">Project/service</option>
            {orders.map((order) => (
              <option key={order._id} value={order._id}>{order.serviceName}</option>
            ))}
          </select>

          <select
            value={selectedTaskId}
            onChange={(e) => setSelectedTaskId(e.target.value)}
            className="p-3 border border-slate-200 rounded-lg text-sm"
            required
          >
            <option value="">Task</option>
            {currentTasks.map((task) => (
              <option key={task._id} value={task._id}>{task.title}</option>
            ))}
          </select>

          <input
            type="number"
            min="1"
            value={manualMinutes}
            onChange={(e) => setManualMinutes(e.target.value)}
            placeholder="Minutes"
            className="p-3 border border-slate-200 rounded-lg text-sm"
            required
          />

          <button className="px-4 py-2.5 rounded-lg bg-slate-900 text-white font-bold text-sm">Add Log</button>

          <textarea
            value={manualNotes}
            onChange={(e) => setManualNotes(e.target.value)}
            rows={2}
            placeholder="Optional note"
            className="lg:col-span-4 p-3 border border-slate-200 rounded-lg text-sm"
          />
        </form>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-white rounded-2xl border border-slate-200 p-6">
          <h3 className="font-bold text-slate-800 mb-1">Project-wise Hours</h3>
          <p className="text-sm text-slate-500 mb-4">Total hours spent per project/service.</p>
          <div className="space-y-2">
            {projectSummary.map((row) => (
              <div key={row.orderId} className="flex items-center justify-between p-2.5 bg-slate-50 rounded-lg text-sm">
                <span className="text-slate-700 font-medium">{row.serviceName}</span>
                <span className="font-bold text-indigo-700">{row.hours} h</span>
              </div>
            ))}
            {projectSummary.length === 0 && <p className="text-sm text-slate-500">No tracked hours yet.</p>}
          </div>
        </div>

        <div className="bg-white rounded-2xl border border-slate-200 p-6">
          <h3 className="font-bold text-slate-800 mb-1">Task-wise Hours</h3>
          <p className="text-sm text-slate-500 mb-4">Detailed breakdown by task.</p>
          <div className="space-y-2 max-h-[340px] overflow-auto pr-1">
            {taskSummary.map((row) => (
              <div key={row.key} className="p-2.5 bg-slate-50 rounded-lg text-sm">
                <p className="font-semibold text-slate-800">{row.taskTitle}</p>
                <div className="flex items-center justify-between mt-1">
                  <span className="text-slate-500 text-xs">{row.serviceName}</span>
                  <span className="font-bold text-indigo-700">{row.hours} h</span>
                </div>
              </div>
            ))}
            {taskSummary.length === 0 && <p className="text-sm text-slate-500">No task-level time logs yet.</p>}
          </div>
          <p className="mt-3 text-sm font-semibold text-slate-700">
            Total tracked: <span className="text-indigo-700">{(totalTrackedMinutes / 60).toFixed(2)} h</span>
          </p>
        </div>
      </div>
    </div>
  );
};

export default TimeTrackingModule;
