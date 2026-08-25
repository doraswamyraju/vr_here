import React from 'react';
import { Bell, X, ArrowUpRight, MessageSquare, CreditCard, AlertCircle } from 'lucide-react';

// Utility function to get relative time
const getRelativeTime = (dateString) => {
  if (!dateString) return 'Just now';
  const now = new Date();
  const past = new Date(dateString);
  const diffMs = now - past;
  
  const diffMins = Math.floor(diffMs / (1000 * 60));
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${diffDays}d ago`;
};

// Utility function to map notification types to icons and badges
const getNotificationTypeConfig = (type) => {
  switch (type) {
    case 'Order':
      return {
        icon: Bell,
        colorClass: 'text-indigo-600',
        bgClass: 'bg-indigo-50 border-indigo-100',
      };
    case 'Payment':
      return {
        icon: CreditCard,
        colorClass: 'text-emerald-600',
        bgClass: 'bg-emerald-50 border-emerald-100',
      };
    case 'Ticket':
      return {
        icon: MessageSquare,
        colorClass: 'text-amber-600',
        bgClass: 'bg-amber-50 border-amber-100',
      };
    default:
      return {
        icon: AlertCircle,
        colorClass: 'text-slate-600',
        bgClass: 'bg-slate-50 border-slate-100',
      };
  }
};

const NotificationCard = ({ notification, onMarkRead, onClickAction, isBanner = false }) => {
  const { _id, title, message, type, isRead, createdAt } = notification;
  const config = getNotificationTypeConfig(type);
  const Icon = config.icon;
  const relativeTime = getRelativeTime(createdAt);

  return (
    <div 
      className={`
        w-full rounded-2xl transition-all duration-200 relative overflow-hidden p-4.5 p-4
        ${isBanner 
          ? 'bg-slate-900/95 text-white backdrop-blur-xl border border-slate-800 shadow-2xl shadow-slate-950/40' 
          : 'bg-white text-slate-800 border border-slate-200/90 shadow-sm hover:shadow-md hover:border-indigo-200/80'}
        ${!isRead && !isBanner ? 'ring-2 ring-indigo-500/20 border-l-4 border-l-indigo-600 bg-indigo-50/15' : ''}
      `}
    >
      {/* Top Header Bar */}
      <div className="flex items-center justify-between mb-3 border-b border-slate-100 pb-2">
        <div className="flex items-center gap-2">
          <div className="w-5 h-5 rounded-md bg-gradient-to-br from-indigo-600 to-blue-600 flex items-center justify-center text-[9px] font-black text-white shadow-sm">
            VR
          </div>
          <span className={`text-[10px] font-black uppercase tracking-wider ${isBanner ? 'text-indigo-300' : 'text-slate-600'}`}>
            VR HERE BMS
          </span>
          <span className={`text-[10px] ${isBanner ? 'text-slate-400' : 'text-slate-500'} font-bold`}>
            • {relativeTime}
          </span>
        </div>
        
        {/* Right Mark as Read Button */}
        <div className="flex items-center gap-1.5">
          {!isRead && onMarkRead && (
            <button 
              onClick={() => onMarkRead(_id)}
              className={`text-[9px] font-black uppercase px-2 py-0.5 rounded-full border tracking-widest active:scale-95 transition-all
                ${isBanner 
                  ? 'border-indigo-800 text-indigo-300 hover:bg-white/10' 
                  : 'border-indigo-200 text-indigo-700 bg-indigo-50 hover:bg-indigo-100'}`}
            >
              Mark Read
            </button>
          )}
        </div>
      </div>

      {/* Main notification content */}
      <div className="flex items-start gap-3">
        {/* Icon Badge */}
        <div className={`p-2.5 rounded-xl border flex-shrink-0 flex items-center justify-center
          ${isBanner 
            ? 'bg-white/10 border-white/10 text-indigo-300' 
            : `${config.bgClass} ${config.colorClass}`}`}
        >
          <Icon size={18} />
        </div>

        {/* Text Details */}
        <div className="flex-1 min-w-0">
          <p className={`text-sm font-bold leading-tight ${isBanner ? 'text-white' : 'text-slate-900'}`}>
            {title}
          </p>
          <p className={`text-xs mt-1 leading-relaxed font-medium ${isBanner ? 'text-slate-300' : 'text-slate-600'}`}>
            {message}
          </p>
          
          {/* Quick Action Navigation Link */}
          {onClickAction && (
            <button 
              onClick={() => onClickAction(notification)}
              className={`mt-3 flex items-center gap-1 text-[11px] font-black uppercase tracking-wider transition-colors group
                ${isBanner ? 'text-indigo-300 hover:text-white' : 'text-indigo-600 hover:text-indigo-800'}`}
            >
              <span>View Details</span>
              <ArrowUpRight size={13} className="transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
};


export default NotificationCard;
