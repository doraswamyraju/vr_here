import React, { useMemo, useState } from 'react';

const TimeTrackingModule = ({ selectedOrder, onLogTime }) => {
  const [selectedTaskId, setSelectedTaskId] = useState('');
  const [minutes, setMinutes] = useState('');
  const [notes, setNotes] = useState('');

  const tasks = selectedOrder?.tasks || [];
  const totalTracked = useMemo(() => tasks.reduce((sum, task) => sum + Number(task.totalMinutes || 0), 0), [tasks]);

  const submitLog = (event) => {
    event.preventDefault();
    if (!selectedOrder || !selectedTaskId || !minutes) return;
    onLogTime(selectedOrder._id, selectedTaskId, Number(minutes), notes);
    setMinutes('');
    setNotes('');
  };

  if (!selectedOrder) {
    return <div className="bg-white rounded-2xl border border-slate-200 p-6 text-sm text-slate-500">Select an order to track task time.</div>;
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div className="bg-white rounded-2xl border border-slate-200 p-6">
        <h3 className="font-bold text-slate-800 mb-4">Log Time</h3>
        <form onSubmit={submitLog} className="space-y-3">
          <select
            value={selectedTaskId}
            onChange={(e) => setSelectedTaskId(e.target.value)}
            className="w-full p-3 border border-slate-200 rounded-lg text-sm"
            required
          >
            <option value="">Select task</option>
            {tasks.map((task) => (
              <option key={task._id} value={task._id}>{task.title}</option>
            ))}
          </select>
          <input
            value={minutes}
            onChange={(e) => setMinutes(e.target.value)}
            type="number"
            min="1"
            placeholder="Minutes"
            className="w-full p-3 border border-slate-200 rounded-lg text-sm"
            required
          />
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={3}
            placeholder="Work notes (optional)"
            className="w-full p-3 border border-slate-200 rounded-lg text-sm"
          />
          <button className="w-full px-4 py-2.5 rounded-lg bg-indigo-600 text-white text-sm font-bold">Add Time Log</button>
        </form>
      </div>

      <div className="bg-white rounded-2xl border border-slate-200 p-6">
        <h3 className="font-bold text-slate-800 mb-4">Tracked Summary</h3>
        <p className="text-3xl font-black text-indigo-600 mb-5">{totalTracked} min</p>
        <div className="space-y-2">
          {tasks.map((task) => (
            <div key={task._id} className="flex items-center justify-between p-2.5 bg-slate-50 rounded-lg text-sm">
              <span className="text-slate-700 font-medium">{task.title}</span>
              <span className="font-bold text-slate-500">{task.totalMinutes || 0} min</span>
            </div>
          ))}
          {tasks.length === 0 && <p className="text-sm text-slate-500">No tasks available for time tracking.</p>}
        </div>
      </div>
    </div>
  );
};

export default TimeTrackingModule;

