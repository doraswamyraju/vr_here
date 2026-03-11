import React from 'react';
import { RefreshCw } from 'lucide-react';
import { EMPLOYEE_TABS } from './constants';

const EmployeeTopbar = ({ activeTab, userInfo, onRefresh }) => {
  const active = EMPLOYEE_TABS.find((tab) => tab.id === activeTab);

  return (
    <header className="h-16 bg-white/80 backdrop-blur-md border-b border-slate-200 flex items-center justify-between px-6 sticky top-0 z-10">
      <h1 className="text-xl font-bold text-slate-800">{active?.label || 'Employee Dashboard'}</h1>
      <div className="flex items-center gap-3">
        <button
          onClick={onRefresh}
          className="inline-flex items-center px-3 py-1.5 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 text-sm font-medium"
        >
          <RefreshCw size={14} className="mr-2" />
          Refresh
        </button>
        <div className="w-8 h-8 rounded-full bg-indigo-100 text-indigo-700 flex items-center justify-center font-bold text-xs">
          {userInfo?.name?.charAt(0) || 'E'}
        </div>
      </div>
    </header>
  );
};

export default EmployeeTopbar;

