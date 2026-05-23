import React, { useState, useMemo } from 'react';
import NotificationCard from './NotificationCard';
import { Bell, CheckCheck, Trash2, Filter } from 'lucide-react';

const NotificationsFeed = ({ 
  notifications = [], 
  onMarkRead, 
  onMarkAllRead, 
  onClickAction 
}) => {
  const [activeTab, setActiveTab] = useState('All'); // 'All', 'Unread', 'Read'
  const [selectedType, setSelectedType] = useState('All'); // 'All', 'Order', 'Payment', 'Ticket', 'System'

  // Filter logic
  const filteredNotifications = useMemo(() => {
    return notifications.filter(notif => {
      // 1. Filter by Read/Unread tab
      if (activeTab === 'Unread' && notif.isRead) return false;
      if (activeTab === 'Read' && !notif.isRead) return false;

      // 2. Filter by Type
      if (selectedType !== 'All' && notif.type !== selectedType) return false;

      return true;
    });
  }, [notifications, activeTab, selectedType]);

  const unreadCount = useMemo(() => {
    return notifications.filter(n => !n.isRead).length;
  }, [notifications]);

  return (
    <div className="w-full space-y-6">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 pb-5">
        <div>
          <h2 className="text-xl font-black text-slate-900 tracking-tight flex items-center gap-2">
            Notification Center
            {unreadCount > 0 && (
              <span className="px-2 py-0.5 rounded-md bg-indigo-50 border border-indigo-100 text-indigo-600 text-[10px] font-black uppercase tracking-wider animate-pulse">
                {unreadCount} New
              </span>
            )}
          </h2>
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider mt-1">Lockscreen stacks & Activity Logs</p>
        </div>

        {/* Action triggers */}
        {unreadCount > 0 && onMarkAllRead && (
          <button
            onClick={onMarkAllRead}
            className="flex items-center gap-1.5 self-start sm:self-auto px-4 py-2 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white rounded-xl text-xs font-black uppercase tracking-wider shadow-lg shadow-indigo-100 active:scale-95 transition-all"
          >
            <CheckCheck size={14} /> Mark all as read
          </button>
        )}
      </div>

      {/* Tabs and filters section */}
      <div className="flex flex-col gap-4">
        {/* Tab triggers */}
        <div className="flex items-center gap-2 p-1.5 bg-slate-100/70 border border-slate-200/40 rounded-xl self-start">
          {['All', 'Unread', 'Read'].map(tab => {
            const active = activeTab === tab;
            return (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`
                  px-4 py-2 rounded-lg text-xs font-black uppercase tracking-wider transition-all
                  ${active 
                    ? 'bg-white text-slate-900 shadow-md border border-slate-200/10' 
                    : 'text-slate-500 hover:text-slate-800'}
                `}
              >
                {tab}
              </button>
            );
          })}
        </div>

        {/* Filter by category pill badges */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-none">
          <div className="flex items-center text-slate-400 gap-1.5 mr-1 text-[10px] font-black uppercase tracking-widest">
            <Filter size={11} /> Filter
          </div>
          {['All', 'Order', 'Payment', 'Ticket', 'System'].map(category => {
            const active = selectedType === category;
            return (
              <button
                key={category}
                onClick={() => setSelectedType(category)}
                className={`
                  px-3 py-1.5 rounded-full text-[10px] font-black uppercase tracking-widest border transition-all active:scale-95
                  ${active 
                    ? 'bg-indigo-600 text-white border-indigo-600 shadow-md shadow-indigo-100' 
                    : 'bg-white text-slate-600 border-slate-200/60 hover:bg-slate-50'}
                `}
              >
                {category}s
              </button>
            );
          })}
        </div>
      </div>

      {/* Main notification feed list stack */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredNotifications.map(notification => (
          <NotificationCard
            key={notification._id}
            notification={notification}
            onMarkRead={onMarkRead}
            onClickAction={onClickAction}
          />
        ))}
      </div>

      {/* Empty State */}
      {filteredNotifications.length === 0 && (
        <div className="flex flex-col items-center justify-center p-12 bg-white border border-slate-100 rounded-3xl text-center space-y-4">
          <div className="w-16 h-16 bg-slate-50 rounded-2xl flex items-center justify-center text-slate-400 border border-slate-100 shadow-inner">
            <Bell size={28} />
          </div>
          <div>
            <h3 className="font-bold text-slate-800 text-sm">Quiet as a lockscreen</h3>
            <p className="text-xs text-slate-500 mt-1 max-w-xs leading-normal">
              No notifications match your current active filters. We'll update you as soon as project activity commences.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

export default NotificationsFeed;
