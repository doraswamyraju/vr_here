import React, { useState, useEffect } from 'react';
import { 
  LayoutDashboard, CheckSquare, Clock, Calendar, Settings, Bell, Search, 
  Menu, LogOut, Play, Square, Pause, ChevronRight, AlertCircle, 
  Coffee, Briefcase, FileText, User, Filter, ArrowRight, Layers,
  ChevronDown as ChevronDownIcon, ChevronRight as ChevronRightIcon,
  MoreVertical, ArrowDownRight, Building2, Plus, Globe, Scale, Factory
} from 'lucide-react';

// --- MOCK DATA ---
const EMPLOYEE_PROFILE = { name: 'Rahul Sharma', role: 'Audit Assistant' };

const MY_TASKS = [
  { id: 101, project: 'TechFlow Solutions', title: 'Vouching - Sales Invoices', status: 'Pending', priority: 'High', start: '2024-10-01', end: '2024-10-05', duration: '4h' },
  { id: 102, project: 'Green Earth NGO', title: 'Expense Verification', status: 'In Progress', priority: 'Medium', start: '2024-10-02', end: '2024-10-02', duration: '3h' },
];

// WBS Data for Project View (Same structure as Admin)
const PROJECT_WBS = [
  { 
    id: '1', sNo: '1', name: 'Planning & Risk Assessment', duration: '', start: '01 Apr 24', end: '10 Apr 24', progress: '100%', plannedStart: '-', plannedEnd: '-', dep: '', type: 'parent', expanded: true,
    children: [
      { id: '1-1', sNo: '', name: 'Engagement Letter Signing', duration: '1 day', start: '01 Apr 24', end: '01 Apr 24', progress: '100%', plannedStart: '01 Apr 24', plannedEnd: '01 Apr 24', dep: '-', type: 'child', assignee: 'Suresh (Partner)' },
      { id: '1-2', sNo: '', name: 'Internal Control Review', duration: '5 days', start: '02 Apr 24', end: '07 Apr 24', progress: '100%', plannedStart: '02 Apr 24', plannedEnd: '07 Apr 24', dep: '1-1', type: 'child', assignee: 'Rahul (Senior)' },
    ]
  },
  { 
    id: '2', sNo: '2', name: 'Execution (Vouching & Verification)', duration: '', start: '11 Apr 24', end: '30 Apr 24', progress: '40%', plannedStart: '-', plannedEnd: '-', dep: '', type: 'parent', expanded: true,
    children: [
      { id: '2-1', sNo: '', name: 'Sales & Revenue Vouching', duration: '5 days', start: '11 Apr 24', end: '16 Apr 24', progress: '100%', plannedStart: '-', plannedEnd: '-', dep: '1-2', type: 'child', assignee: 'Arjun (Article)' },
      { id: '2-2', sNo: '', name: 'Purchase & Expense Vouching', duration: '7 days', start: '17 Apr 24', end: '24 Apr 24', progress: '20%', plannedStart: '-', plannedEnd: '-', dep: '2-1', type: 'child', assignee: 'Priya (Article)' },
    ]
  },
  // Ensure unique IDs here. If "Carpentry Works" was intended as a separate phase or just duplicate data, giving it a unique ID '3' solves the conflict.
  { id: '3', sNo: '3', name: 'Compliance Review', duration: '', start: '01 May 24', end: '10 May 24', progress: '0%', plannedStart: '-', plannedEnd: '-', dep: '', type: 'parent', expanded: false, children: [] }, 
];

const StatusBadge = ({ status }) => {
  const styles = { 'Pending': 'bg-slate-100 text-slate-600', 'In Progress': 'bg-indigo-100 text-indigo-700', 'Completed': 'bg-emerald-100 text-emerald-700' };
  return <span className={`px-2 py-1 rounded text-xs font-bold ${styles[status]}`}>{status}</span>;
};

// --- PROJECT VIEW FOR EMPLOYEES ---
const EmployeeProjectView = () => {
  const [tasks, setTasks] = useState(PROJECT_WBS);
  const toggleExpand = (id) => setTasks(tasks.map(t => t.id === id ? { ...t, expanded: !t.expanded } : t));

  return (
    <div className="space-y-6 animate-in fade-in zoom-in duration-300">
       <div className="flex justify-between items-center mb-4">
          <div><h2 className="text-2xl font-bold text-slate-800">Statutory Audit FY 2024-25 (Project View)</h2><p className="text-slate-500">Full Schedule & Dependencies</p></div>
       </div>
       <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden flex-1 flex flex-col">
          <div className="overflow-auto flex-1">
             <table className="w-full text-left border-collapse min-w-[1000px]">
                <thead className="bg-slate-50 text-[11px] font-bold text-slate-500 uppercase sticky top-0 z-10 text-center">
                   <tr>
                      <th className="px-4 py-3 border-b border-r w-12">S.No</th>
                      <th className="px-6 py-3 border-b border-r text-left w-64">Audit Procedure</th>
                      <th className="px-4 py-3 border-b border-r">Duration</th>
                      <th className="px-4 py-3 border-b border-r">Start Date</th>
                      <th className="px-4 py-3 border-b border-r">End Date</th>
                      <th className="px-4 py-3 border-b border-r">Progress</th>
                      <th className="px-4 py-3 border-b border-r">Planned Start</th>
                      <th className="px-4 py-3 border-b border-r">Planned End</th>
                      <th className="px-4 py-3 border-b">Dep.</th>
                   </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 text-xs">
                   {tasks.map(task => (
                      <React.Fragment key={task.id}>
                         <tr className="bg-slate-50/50 hover:bg-slate-100 font-bold text-slate-700">
                            <td className="px-4 py-3 border-r text-center">{task.sNo}</td>
                            <td className="px-6 py-3 border-r flex items-center cursor-pointer" onClick={() => toggleExpand(task.id)}>
                               {task.children.length > 0 ? (task.expanded ? <ChevronDownIcon size={14} className="mr-2"/> : <ChevronRightIcon size={14} className="mr-2"/>) : <span className="w-5 mr-1"></span>}
                               {task.name}
                            </td>
                            <td className="px-4 py-3 border-r text-center text-slate-500">{task.duration}</td>
                            <td className="px-4 py-3 border-r text-center">{task.start}</td>
                            <td className="px-4 py-3 border-r text-center">{task.end}</td>
                            <td className="px-4 py-3 border-r text-center">{task.progress}</td>
                            <td className="px-4 py-3 border-r text-center text-slate-400">-</td>
                            <td className="px-4 py-3 border-r text-center text-slate-400">-</td>
                            <td className="px-4 py-3 text-center text-slate-400"></td>
                         </tr>
                         {task.expanded && task.children.map(child => (
                            <tr key={child.id} className="hover:bg-indigo-50/30 transition-colors">
                               <td className="px-4 py-3 border-r text-center"></td>
                               <td className="px-6 py-3 border-r pl-10 flex items-center text-slate-600 font-medium">
                                  <ArrowDownRight size={12} className="mr-2 text-slate-300"/> {child.name}
                                  {child.assignee && child.assignee.includes('Rahul') && <span className="ml-2 text-[10px] bg-indigo-100 text-indigo-700 px-1.5 rounded">YOU</span>}
                               </td>
                               <td className="px-4 py-3 border-r text-center text-slate-500">{child.duration}</td>
                               <td className="px-4 py-3 border-r text-center">{child.start}</td>
                               <td className="px-4 py-3 border-r text-center">{child.end}</td>
                               <td className="px-4 py-3 border-r text-center text-indigo-600 font-bold">{child.progress}</td>
                               <td className="px-4 py-3 border-r text-center text-slate-500">{child.plannedStart}</td>
                               <td className="px-4 py-3 border-r text-center text-slate-500">{child.plannedEnd}</td>
                               <td className="px-4 py-3 text-center text-indigo-500 font-mono">{child.dep}</td>
                            </tr>
                         ))}
                      </React.Fragment>
                   ))}
                </tbody>
             </table>
          </div>
       </div>
    </div>
  );
};

// --- LOGIN COMPONENT WITH SERVICES ---
const LoginView = ({ onLogin }) => {
  const [loading, setLoading] = useState(false);

  const handleLogin = (e) => {
    e.preventDefault();
    setLoading(true);
    setTimeout(() => {
      onLogin();
    }, 1500);
  };

  return (
    <div className="min-h-screen bg-slate-900 flex items-center justify-center relative overflow-hidden">
      {/* Background Decor */}
      <div className="absolute top-0 left-0 w-full h-full overflow-hidden">
        <div className="absolute -top-[20%] -left-[10%] w-[50%] h-[50%] bg-indigo-500/20 rounded-full blur-[100px]" />
        <div className="absolute top-[40%] -right-[10%] w-[40%] h-[40%] bg-purple-500/20 rounded-full blur-[100px]" />
      </div>

      <div className="bg-white/10 backdrop-blur-lg border border-white/20 p-8 rounded-3xl shadow-2xl w-full max-w-md relative z-10">
        <div className="text-center mb-8">
          <div className="w-16 h-16 bg-gradient-to-tr from-indigo-500 to-purple-600 rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-lg shadow-indigo-500/30">
            <CheckSquare className="text-white w-8 h-8" />
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">VR <span className="text-indigo-400">Here</span></h1>
          <p className="text-slate-400 mt-2 text-sm uppercase tracking-wider font-semibold">Employee Portal</p>
        </div>

        {/* Services List Ticker */}
        <div className="mb-8 p-4 bg-slate-800/50 rounded-xl border border-slate-700/50">
           <p className="text-xs text-indigo-300 font-bold uppercase mb-2 text-center">Authorized Access For</p>
           <div className="flex flex-wrap gap-2 justify-center">
              {['Audit & Taxation', 'Industrial Support', 'ISO Certification', 'Business Registration', 'Govt Licensing', 'Compliance'].map(service => (
                 <span key={service} className="text-[10px] px-2 py-1 bg-slate-700 rounded text-slate-300 border border-slate-600">{service}</span>
              ))}
           </div>
        </div>

        <form onSubmit={handleLogin} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">Employee ID / Email</label>
            <input type="email" defaultValue="rahul@vrhere.com" className="w-full bg-slate-800/50 border border-slate-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all" />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">Password</label>
            <input type="password" defaultValue="password" className="w-full bg-slate-800/50 border border-slate-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all" />
          </div>
          <button 
            type="submit" 
            disabled={loading}
            className="w-full bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white font-bold py-3.5 rounded-xl shadow-lg shadow-indigo-500/25 transition-all transform hover:scale-[1.02] active:scale-[0.98] flex items-center justify-center"
          >
            {loading ? <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : 'Secure Login'}
          </button>
        </form>
        <div className="mt-6 text-center">
          <p className="text-xs text-slate-500">VR Here Platform v2.0 • Secured System</p>
        </div>
      </div>
    </div>
  );
};

// --- MAIN EMPLOYEE APP ---
export default function EmployeeApp() {
  const [activeTab, setActiveTab] = useState('Dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true);
  const [isClockedIn, setIsClockedIn] = useState(false);
  const [activeTask, setActiveTask] = useState(null); 
  const [isLoggedIn, setIsLoggedIn] = useState(false); // Added Login State

  const handleTaskStart = (task) => {
    if (!isClockedIn) { alert("Clock In first!"); return; }
    setActiveTask(task);
  };

  const handleTaskStop = () => { setActiveTask(null); };

  if (!isLoggedIn) return <LoginView onLogin={() => setIsLoggedIn(true)} />;

  // Dashboard View (Simplified)
  const DashboardView = () => (
    <div className="space-y-6 animate-in fade-in">
       <div className="bg-slate-900 rounded-3xl p-8 text-white flex justify-between items-center">
          <div><h2 className="text-2xl font-bold">Welcome, {EMPLOYEE_PROFILE.name}</h2><p className="text-slate-400">Status: {isClockedIn ? 'Online' : 'Offline'}</p></div>
          <button onClick={() => setIsClockedIn(!isClockedIn)} className={`px-6 py-3 rounded-xl font-bold ${isClockedIn ? 'bg-rose-500' : 'bg-emerald-500'}`}>{isClockedIn ? 'Clock Out' : 'Clock In'}</button>
       </div>
       {activeTask && <div className="bg-indigo-50 border border-indigo-200 p-6 rounded-2xl flex justify-between items-center"><div className="flex items-center gap-4"><Clock className="text-indigo-600"/><h3 className="font-bold text-slate-800">{activeTask.title}</h3></div><button onClick={handleTaskStop} className="w-10 h-10 bg-rose-500 text-white rounded-full flex items-center justify-center"><Square size={14} fill="currentColor"/></button></div>}
       <h3 className="font-bold text-slate-800">My Tasks Queue</h3>
       <div className="space-y-3">
          {MY_TASKS.map(task => (
             <div key={task.id} className="bg-white p-4 rounded-xl border border-slate-200 flex justify-between items-center">
                <div><h4 className="font-bold text-slate-700">{task.title}</h4><p className="text-xs text-slate-500">{task.project}</p></div>
                <button onClick={() => handleTaskStart(task)} disabled={!isClockedIn || activeTask} className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm font-bold disabled:opacity-50">Start</button>
             </div>
          ))}
       </div>
    </div>
  );

  return (
    <div className="flex h-screen bg-slate-50 font-sans text-slate-800 overflow-hidden">
      <aside className={`${sidebarCollapsed ? 'w-20' : 'w-64'} bg-white h-full border-r border-slate-200 flex flex-col z-20 transition-all duration-300`} onMouseEnter={() => setSidebarCollapsed(false)} onMouseLeave={() => setSidebarCollapsed(true)}>
        <div className="h-20 flex items-center justify-center border-b border-slate-100"><div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center text-white font-bold text-lg shadow-lg">VR</div></div>
        <div className="flex-1 py-6 px-3 space-y-1">
           {['Dashboard', 'Projects', 'My Tasks', 'Timesheet', 'Leaves', 'Payslips'].map(item => (
             <button key={item} onClick={() => setActiveTab(item)} className={`flex items-center w-full p-3 rounded-xl transition-all ${activeTab === item ? 'bg-indigo-50 text-indigo-600 font-bold' : 'text-slate-500 hover:bg-slate-50'}`}>
               <div className="shrink-0">{item === 'Projects' ? <Layers size={20}/> : item === 'Dashboard' ? <LayoutDashboard size={20}/> : <CheckSquare size={20}/>}</div>
               <span className={`ml-3 whitespace-nowrap transition-all duration-300 ${sidebarCollapsed ? 'opacity-0 w-0 overflow-hidden' : 'opacity-100'}`}>{item}</span>
             </button>
           ))}
        </div>
        <div className="p-4 border-t border-slate-100"><button className="flex items-center w-full p-2 rounded-lg text-rose-500 hover:bg-rose-50"><LogOut size={20} /><span className={`ml-3 text-sm transition-all duration-300 ${sidebarCollapsed ? 'opacity-0' : 'opacity-100'}`}>Logout</span></button></div>
      </aside>
      <main className="flex-1 flex flex-col h-full overflow-hidden relative">
        <header className="h-16 bg-white/80 backdrop-blur-md border-b border-slate-200 flex items-center justify-between px-8 sticky top-0 z-10"><h1 className="text-xl font-bold text-slate-800">{activeTab}</h1></header>
        <div className="flex-1 overflow-y-auto p-8">
           {activeTab === 'Dashboard' && <DashboardView />}
           {activeTab === 'Projects' && <EmployeeProjectView />}
           {activeTab === 'My Tasks' && <DashboardView />} 
           {activeTab !== 'Dashboard' && activeTab !== 'Projects' && activeTab !== 'My Tasks' && <div className="flex h-full items-center justify-center text-slate-400">Module: {activeTab}</div>}
        </div>
      </main>
    </div>
  );
}