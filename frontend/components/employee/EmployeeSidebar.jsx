import React from 'react';
import { LogOut, ChevronLeft, ChevronRight, X } from 'lucide-react';
import { EMPLOYEE_TABS } from './constants';

const EmployeeSidebar = ({
  activeTab,
  setActiveTab,
  collapsed,
  setCollapsed,
  onLogout,
  userInfo,
  mobileOpen = false,
  setMobileOpen = () => {}
}) => {
  const isPMOrAdmin = userInfo?.role === 'admin' || userInfo?.role === 'Admin' || userInfo?.designation?.toLowerCase()?.includes('project manager') || userInfo?.role === 'Project Manager';

  const visibleTabs = EMPLOYEE_TABS.filter(item => {
    if (item.id === 'support') {
      const hasCategories = userInfo?.assignedTicketCategories && userInfo.assignedTicketCategories.length > 0;
      return userInfo?.role === 'admin' || hasCategories;
    }
    if (item.id === 'commercials' || item.id === 'finance') {
      return isPMOrAdmin;
    }
    return true;
  });

  return (
    <>
      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-slate-900/40 backdrop-blur-xs z-40 lg:hidden animate-fade-in"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside
        className={`fixed lg:static z-50 h-screen bg-white/85 backdrop-blur-md border-r border-slate-200/80 flex flex-col transition-all duration-300 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        } ${collapsed ? 'w-20' : 'w-72'}`}
      >
        {/* Header with Logo & Toggle Button */}
        <div className="h-20 px-4 flex items-center justify-between border-b border-slate-200/70">
          {!collapsed ? (
            <div className="flex items-center gap-3 group min-w-0">
              <img src="/logo.png" alt="VR Here" className="h-10 w-auto object-contain group-hover:scale-105 transition-transform shrink-0" />
              <div className="flex flex-col min-w-0">
                <span className="font-black text-slate-900 text-base leading-none tracking-tight">VR Here</span>
                <span className="text-[8.5px] font-extrabold text-indigo-600 uppercase tracking-widest mt-0.5 truncate">Staff Workplace</span>
              </div>
            </div>
          ) : (
            <div className="mx-auto block" title="VR Here Staff Workplace">
              <img src="/logo.png" alt="VR Here" className="h-9 w-auto object-contain mx-auto hover:scale-105 transition-transform" />
            </div>
          )}

          <div className="flex items-center gap-1 shrink-0">
            {/* Collapse/Expand active toggle icon button */}
            <button
              onClick={() => setCollapsed(!collapsed)}
              className="hidden lg:flex p-1.5 rounded-xl text-slate-400 hover:text-slate-800 hover:bg-slate-100 transition"
              title={collapsed ? 'Expand / Activate Sidebar' : 'Collapse / Inactivate Sidebar'}
            >
              {collapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
            </button>
            <button
              className="lg:hidden text-slate-500 p-1.5 hover:bg-slate-100 rounded-xl"
              onClick={() => setMobileOpen(false)}
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex-1 py-4 px-3 space-y-1 overflow-y-auto custom-scrollbar">
          {visibleTabs.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  setActiveTab(item.id);
                  setMobileOpen(false);
                }}
                title={collapsed ? item.label : undefined}
                className={`flex items-center w-full px-3 py-2.5 rounded-xl text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-gradient-to-r from-indigo-600 to-blue-600 text-white font-bold shadow-lg shadow-indigo-600/20'
                    : 'text-slate-600 hover:bg-indigo-50 hover:text-indigo-900'
                } ${collapsed ? 'justify-center' : ''}`}
              >
                <Icon size={19} className="shrink-0" />
                {!collapsed && (
                  <span className="ml-3 truncate">{item.label}</span>
                )}
              </button>
            );
          })}
        </div>

        {/* Logout Footer */}
        <div className="p-3 border-t border-slate-200/70">
          <button
            onClick={onLogout}
            title={collapsed ? 'Logout' : undefined}
            className={`flex items-center w-full px-3 py-2.5 rounded-xl text-sm font-medium text-rose-600 hover:bg-rose-50 transition ${
              collapsed ? 'justify-center' : ''
            }`}
          >
            <LogOut size={19} className="shrink-0" />
            {!collapsed && <span className="ml-3">Logout</span>}
          </button>
        </div>
      </aside>
    </>
  );
};

export default EmployeeSidebar;
