import React, { useEffect, useState } from 'react';
import NotificationCard from './NotificationCard';
import { X } from 'lucide-react';

const InAppBanner = ({ activeNotification, onDismiss, onClickAction }) => {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (activeNotification) {
      setVisible(true);
      // Auto dismiss after 5 seconds
      const timer = setTimeout(() => {
        handleDismiss();
      }, 5000);
      return () => clearTimeout(timer);
    } else {
      setVisible(false);
    }
  }, [activeNotification]);

  const handleDismiss = () => {
    setVisible(false);
    // Wait for slide-out transition to complete before clearing state
    setTimeout(() => {
      if (onDismiss) onDismiss();
    }, 300);
  };

  if (!activeNotification) return null;

  return (
    <div 
      className={`
        fixed top-4 right-4 sm:right-6 z-[9999] pointer-events-none w-full max-w-sm px-4 sm:px-0
        transition-all duration-300 ease-[cubic-bezier(0.16,1,0.3,1)]
        ${visible 
          ? 'translate-y-0 opacity-100 scale-100' 
          : '-translate-y-8 opacity-0 scale-95'}
      `}
    >
      <div className="pointer-events-auto relative group">
        <NotificationCard 
          notification={activeNotification}
          onMarkRead={() => handleDismiss()}
          onClickAction={onClickAction}
          isBanner={true}
        />
        
        {/* Floating close X in corner */}
        <button 
          onClick={handleDismiss}
          className="absolute -top-1.5 -right-1.5 w-6 h-6 rounded-full bg-slate-800 border border-slate-700 text-slate-400 flex items-center justify-center hover:text-white hover:bg-slate-700 shadow-md opacity-0 group-hover:opacity-100 transition-opacity"
        >
          <X size={12} />
        </button>
      </div>
    </div>
  );
};

export default InAppBanner;
