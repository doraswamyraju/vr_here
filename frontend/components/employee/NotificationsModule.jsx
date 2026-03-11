import React from 'react';

const NotificationsModule = ({ notifications }) => {
  return (
    <div className="bg-white rounded-2xl border border-slate-200 p-6">
      <h3 className="font-bold text-slate-800 mb-4">Notifications</h3>
      <div className="space-y-3">
        {notifications.map((notification) => (
          <div key={notification._id} className="p-3 border border-slate-200 rounded-lg">
            <p className="font-semibold text-slate-700">{notification.title || 'Notification'}</p>
            <p className="text-sm text-slate-500 mt-1">{notification.message}</p>
            <p className="text-xs text-slate-400 mt-1">{new Date(notification.createdAt || Date.now()).toLocaleString()}</p>
          </div>
        ))}
        {notifications.length === 0 && <p className="text-sm text-slate-500">No new notifications.</p>}
      </div>
    </div>
  );
};

export default NotificationsModule;

