import React, { useEffect, useMemo, useRef, useState } from 'react';

const SHIFT_STORAGE_KEY = 'employee_shift_state_v1';
const TASK_TIMER_STORAGE_KEY = 'employee_task_timer_v1';

const formatDuration = (totalSeconds) => {
  const safe = Math.max(0, Number(totalSeconds || 0));
  const hours = Math.floor(safe / 3600);
  const minutes = Math.floor((safe % 3600) / 60);
  const seconds = safe % 60;
  return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
};

const TimeTrackingModule = ({
  orders,
  selectedOrder,
  setSelectedOrder,
  onLogTime,
  userInfo
}) => {
  const [selectedOrderId, setSelectedOrderId] = useState(selectedOrder?._id || '');
  const [selectedTaskId, setSelectedTaskId] = useState('');
  const [manualMinutes, setManualMinutes] = useState('');
  const [manualNotes, setManualNotes] = useState('');

  const [isClockedIn, setIsClockedIn] = useState(false);
  const [shiftStartedAt, setShiftStartedAt] = useState(null);
  const [shiftElapsedSeconds, setShiftElapsedSeconds] = useState(0);

  const [isTaskTimerRunning, setIsTaskTimerRunning] = useState(false);
  const [taskTimerStartedAt, setTaskTimerStartedAt] = useState(null);
  const [taskElapsedSeconds, setTaskElapsedSeconds] = useState(0);

  const shiftIntervalRef = useRef(null);
  const taskIntervalRef = useRef(null);

  const currentOrder = useMemo(
    () => orders.find((order) => order._id === selectedOrderId) || null,
    [orders, selectedOrderId]
  );

  const currentTasks = currentOrder?.tasks || [];

  useEffect(() => {
    if (selectedOrder?._id) {
      setSelectedOrderId(selectedOrder._id);
    }
  }, [selectedOrder]);

  useEffect(() => {
    if (!selectedOrderId && orders.length > 0) {
      setSelectedOrderId(orders[0]._id);
    }
  }, [orders, selectedOrderId]);

  useEffect(() => {
    if (currentOrder && setSelectedOrder) {
      setSelectedOrder(currentOrder);
    }
  }, [currentOrder, setSelectedOrder]);

  useEffect(() => {
    const rawShift = localStorage.getItem(SHIFT_STORAGE_KEY);
    if (rawShift) {
      try {
        const parsed = JSON.parse(rawShift);
        if (parsed?.isClockedIn && parsed?.shiftStartedAt) {
          setIsClockedIn(true);
          setShiftStartedAt(parsed.shiftStartedAt);
          const elapsed = Math.floor((Date.now() - new Date(parsed.shiftStartedAt).getTime()) / 1000);
          setShiftElapsedSeconds(Math.max(0, elapsed));
        }
      } catch (error) {
        localStorage.removeItem(SHIFT_STORAGE_KEY);
      }
    }

    const rawTask = localStorage.getItem(TASK_TIMER_STORAGE_KEY);
    if (rawTask) {
      try {
        const parsed = JSON.parse(rawTask);
        if (parsed?.isRunning && parsed?.startedAt) {
          setSelectedOrderId(parsed.selectedOrderId || '');
          setSelectedTaskId(parsed.selectedTaskId || '');
          setIsTaskTimerRunning(true);
          setTaskTimerStartedAt(parsed.startedAt);
          const elapsed = Math.floor((Date.now() - new Date(parsed.startedAt).getTime()) / 1000);
          setTaskElapsedSeconds(Math.max(0, elapsed));
        }
      } catch (error) {
        localStorage.removeItem(TASK_TIMER_STORAGE_KEY);
      }
    }
  }, []);

  useEffect(() => {
    if (isClockedIn && shiftStartedAt) {
      shiftIntervalRef.current = setInterval(() => {
        const elapsed = Math.floor((Date.now() - new Date(shiftStartedAt).getTime()) / 1000);
        setShiftElapsedSeconds(Math.max(0, elapsed));
      }, 1000);
    }

    return () => {
      if (shiftIntervalRef.current) {
        clearInterval(shiftIntervalRef.current);
        shiftIntervalRef.current = null;
      }
    };
  }, [isClockedIn, shiftStartedAt]);

  useEffect(() => {
    if (isTaskTimerRunning && taskTimerStartedAt) {
      taskIntervalRef.current = setInterval(() => {
        const elapsed = Math.floor((Date.now() - new Date(taskTimerStartedAt).getTime()) / 1000);
        setTaskElapsedSeconds(Math.max(0, elapsed));
      }, 1000);
    }

    return () => {
      if (taskIntervalRef.current) {
        clearInterval(taskIntervalRef.current);
        taskIntervalRef.current = null;
      }
    };
  }, [isTaskTimerRunning, taskTimerStartedAt]);

  const clockIn = () => {
    const startedAt = new Date().toISOString();
    setIsClockedIn(true);
    setShiftStartedAt(startedAt);
    setShiftElapsedSeconds(0);
    localStorage.setItem(SHIFT_STORAGE_KEY, JSON.stringify({ isClockedIn: true, shiftStartedAt: startedAt }));
  };

  const clockOut = () => {
    setIsClockedIn(false);
    setShiftStartedAt(null);
    setShiftElapsedSeconds(0);
    localStorage.removeItem(SHIFT_STORAGE_KEY);
  };

  const startTaskTimer = () => {
    if (!selectedOrderId || !selectedTaskId) return;
    const startedAt = new Date().toISOString();
    setIsTaskTimerRunning(true);
    setTaskTimerStartedAt(startedAt);
    setTaskElapsedSeconds(0);
    localStorage.setItem(
      TASK_TIMER_STORAGE_KEY,
      JSON.stringify({
        isRunning: true,
        startedAt,
        selectedOrderId,
        selectedTaskId
      })
    );
  };

  const stopTaskTimer = async () => {
    if (!isTaskTimerRunning || !taskTimerStartedAt || !selectedOrderId || !selectedTaskId) return;

    const elapsedSeconds = Math.floor((Date.now() - new Date(taskTimerStartedAt).getTime()) / 1000);
    const minutes = Math.max(1, Math.round(elapsedSeconds / 60));

    setIsTaskTimerRunning(false);
    setTaskTimerStartedAt(null);
    setTaskElapsedSeconds(0);
    localStorage.removeItem(TASK_TIMER_STORAGE_KEY);

    await onLogTime(selectedOrderId, selectedTaskId, minutes, `Timer session by ${userInfo?.name || 'employee'}`);
  };

  const submitManualLog = async (event) => {
    event.preventDefault();
    if (!selectedOrderId || !selectedTaskId || !manualMinutes) return;

    await onLogTime(selectedOrderId, selectedTaskId, Number(manualMinutes), manualNotes);
    setManualMinutes('');
    setManualNotes('');
  };

  const projectSummary = useMemo(() => {
    return orders.map((order) => {
      const minutes = (order.tasks || []).reduce((sum, task) => sum + Number(task.totalMinutes || 0), 0);
      return {
        orderId: order._id,
        serviceName: order.serviceName,
        minutes,
        hours: (minutes / 60).toFixed(2)
      };
    }).filter((item) => item.minutes > 0).sort((a, b) => b.minutes - a.minutes);
  }, [orders]);

  const taskSummary = useMemo(() => {
    const rows = [];
    orders.forEach((order) => {
      (order.tasks || []).forEach((task) => {
        const minutes = Number(task.totalMinutes || 0);
        if (minutes > 0) {
          rows.push({
            taskId: task._id,
            orderId: order._id,
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

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-white rounded-2xl border border-slate-200 p-6">
          <h3 className="font-bold text-slate-800 mb-3">Attendance Clock</h3>
          <p className="text-sm text-slate-500 mb-4">Clock in/out for work shift tracking.</p>
          <div className="text-3xl font-black text-indigo-600 mb-4">{formatDuration(shiftElapsedSeconds)}</div>
          {!isClockedIn ? (
            <button onClick={clockIn} className="px-4 py-2.5 rounded-lg bg-emerald-600 text-white font-bold text-sm">Clock In</button>
          ) : (
            <button onClick={clockOut} className="px-4 py-2.5 rounded-lg bg-rose-600 text-white font-bold text-sm">Clock Out</button>
          )}
        </div>

        <div className="bg-white rounded-2xl border border-slate-200 p-6">
          <h3 className="font-bold text-slate-800 mb-3">Task Timer</h3>
          <p className="text-sm text-slate-500 mb-4">Track time against a specific project/task.</p>

          <div className="space-y-3 mb-4">
            <select
              value={selectedOrderId}
              onChange={(e) => {
                setSelectedOrderId(e.target.value);
                setSelectedTaskId('');
              }}
              className="w-full p-3 border border-slate-200 rounded-lg text-sm"
              disabled={isTaskTimerRunning}
            >
              <option value="">Select project/service</option>
              {orders.map((order) => (
                <option key={order._id} value={order._id}>{order.serviceName}</option>
              ))}
            </select>

            <select
              value={selectedTaskId}
              onChange={(e) => setSelectedTaskId(e.target.value)}
              className="w-full p-3 border border-slate-200 rounded-lg text-sm"
              disabled={isTaskTimerRunning}
            >
              <option value="">Select task</option>
              {currentTasks.map((task) => (
                <option key={task._id} value={task._id}>{task.title}</option>
              ))}
            </select>
          </div>

          <div className="text-3xl font-black text-indigo-600 mb-4">{formatDuration(taskElapsedSeconds)}</div>

          {!isTaskTimerRunning ? (
            <button
              onClick={startTaskTimer}
              disabled={!selectedOrderId || !selectedTaskId}
              className="px-4 py-2.5 rounded-lg bg-indigo-600 text-white font-bold text-sm disabled:opacity-50"
            >
              Start Task Timer
            </button>
          ) : (
            <button onClick={stopTaskTimer} className="px-4 py-2.5 rounded-lg bg-amber-600 text-white font-bold text-sm">
              Stop & Save
            </button>
          )}
        </div>
      </div>

      <div className="bg-white rounded-2xl border border-slate-200 p-6">
        <h3 className="font-bold text-slate-800 mb-3">Manual Time Log (Optional)</h3>
        <form onSubmit={submitManualLog} className="grid grid-cols-1 lg:grid-cols-4 gap-3">
          <select
            value={selectedOrderId}
            onChange={(e) => {
              setSelectedOrderId(e.target.value);
              setSelectedTaskId('');
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
              <div key={row.taskId} className="p-2.5 bg-slate-50 rounded-lg text-sm">
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
