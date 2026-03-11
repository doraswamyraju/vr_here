import React from 'react';
import { LogOut } from 'lucide-react';
import { EMPLOYEE_TABS } from './constants';

const EmployeeSidebar = ({
  activeTab,
  setActiveTab,
  collapsed,
  setCollapsed,
  onLogout
}) => {
  return (
    <aside
      className={`${collapsed ? 'w-20' : 'w-72'} bg-white h-full border-r border-slate-200 flex flex-col z-20 transition-all duration-300`}
      onMouseEnter={() => setCollapsed(false)}
      onMouseLeave={() => setCollapsed(true)}
    >
      <div className="h-20 flex items-center justify-center border-b border-slate-100">
        <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center text-white font-bold text-lg shadow-lg">
          VR
        </div>
      </div>

      <div className="flex-1 py-5 px-3 space-y-1 overflow-y-auto">
        {EMPLOYEE_TABS.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`flex items-center w-full p-3 rounded-xl transition-all ${
                activeTab === item.id
                  ? 'bg-indigo-50 text-indigo-600 font-bold'
                  : 'text-slate-500 hover:bg-slate-50'
              }`}
            >
              <Icon size={20} className="shrink-0" />
              <span className={`ml-3 whitespace-nowrap transition-all duration-300 ${collapsed ? 'opacity-0 w-0 overflow-hidden' : 'opacity-100'}`}>
                {item.label}
              </span>
            </button>
          );
        })}
      </div>

      <div className="p-4 border-t border-slate-100">
        <button onClick={onLogout} className="flex items-center w-full p-2 rounded-lg text-rose-500 hover:bg-rose-50">
          <LogOut size={20} />
          <span className={`ml-3 text-sm transition-all duration-300 ${collapsed ? 'opacity-0 w-0 overflow-hidden' : 'opacity-100'}`}>
            Logout
          </span>
        </button>
      </div>
    </aside>
  );
};

export default EmployeeSidebar;

