import React from 'react';
import { Bell, Order, X, ArrowUpRight, MessageSquare, CreditCard, AlertCircle } from 'lucide-react';

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
        w-full max-w-sm rounded-[1.25rem] transition-all duration-300 relative overflow-hidden
        ${isBanner 
          ? 'bg-slate-900/90 text-white backdrop-blur-lg border border-slate-800/80 shadow-2xl shadow-slate-950/20' 
          : 'bg-white/80 text-slate-800 backdrop-blur-md border border-slate-200/60 shadow-lg hover:shadow-xl hover:translate-y-[-2px]'}
        ${!isRead && !isBanner ? 'ring-2 ring-indigo-500/20' : ''}
        p-4.5 p-4
      `}
    >
      {/* Top Branding Banner Bar */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          {/* Miniature App Badge Icon */}
          <div className="w-5 h-5 rounded-md bg-gradient-to-br from-indigo-500 to-blue-600 flex items-center justify-center text-[9px] font-black text-white shadow-sm shadow-indigo-200">
            VR
          </div>
          <span className={`text-[10px] font-black uppercase tracking-wider ${isBanner ? 'text-indigo-300' : 'text-slate-400'}`}>
            VR HERE
          </span>
          <span className={`text-[10px] ${isBanner ? 'text-slate-400' : 'text-slate-400'} font-bold`}>
            • {relativeTime}
          </span>
        </div>
        
        {/* Right close button or Mark as read trigger */}
        <div className="flex items-center gap-1.5">
          {!isRead && onMarkRead && (
            <button 
              onClick={() => onMarkRead(_id)}
              className={`text-[9px] font-black uppercase px-2 py-0.5 rounded-full border tracking-widest active:scale-95 transition-all
                ${isBanner 
                  ? 'border-indigo-800 text-indigo-300 hover:bg-white/5' 
                  : 'border-indigo-100 text-indigo-600 bg-indigo-50/50 hover:bg-indigo-50'}`}
            >
              Read
            </button>
          )}
        </div>
      </div>

      {/* Main notification body */}
      <div className="flex items-start gap-3">
        {/* Round Icon */}
        <div className={`p-2.5 rounded-xl border flex-shrink-0 flex items-center justify-center
          ${isBanner 
            ? 'bg-white/5 border-white/10 text-indigo-400' 
            : `${config.bgClass} ${config.colorClass}`}`}
        >
          <Icon size={16} />
        </div>

        {/* Text columns */}
        <div className="flex-1 min-w-0">
          <p className={`text-xs font-black leading-tight tracking-tight ${isBanner ? 'text-white' : 'text-slate-900'}`}>
            {title}
          </p>
          <p className={`text-xs mt-1 leading-normal font-medium ${isBanner ? 'text-slate-300' : 'text-slate-500'}`}>
            {message}
          </p>
          
          {/* Quick Action Navigation */}
          {onClickAction && (
            <button 
              onClick={() => onClickAction(notification)}
              className={`mt-2.5 flex items-center gap-1 text-[10px] font-black uppercase tracking-wider transition-colors active:translate-x-0.5
                ${isBanner ? 'text-indigo-400 hover:text-indigo-300' : 'text-indigo-600 hover:text-indigo-800'}`}
            >
              View Update <ArrowUpRight size={11} />
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default NotificationCard;
