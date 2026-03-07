import React, { useState, useEffect } from 'react';
import {
  LayoutDashboard, Users, FileText, CheckSquare, Shield, Settings, Bell, Search,
  Menu, ChevronDown, MoreVertical, ArrowUpRight, ArrowDownRight, Clock, CheckCircle2,
  AlertCircle, Briefcase, LogOut, Plus, Eye, EyeOff, Download, Trash2, Building2,
  User, CreditCard, MapPin, Phone, Mail, Calendar, ChevronRight, X, Kanban, List,
  ArrowRight, PieChart, ChevronLeft, Layers, FileInput, MessageSquare, Anchor,
  Globe, Factory, Stamp, HardHat, DollarSign, FolderOpen, BookOpen, Truck, BarChart,
  ChevronDown as ChevronDownIcon, ChevronRight as ChevronRightIcon, Landmark, Scale,
  Receipt, FileSpreadsheet, Percent, Database, UserCheck, Briefcase as ServiceIcon,
  MessageCircle, FileCheck
} from 'lucide-react';
import { PieChart as RechartsPie, Pie, Cell, Tooltip, ResponsiveContainer, BarChart as RechartsBarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import ServicesMasterView from './components/admin/ServicesMasterView';

const CHECKLIST_TEMPLATES = {
  'Pvt Ltd Incorporation': [
    'Collect KYC Documents (PAN, Aadhaar)',
    'Apply for DSC (Digital Signature)',
    'Name Reservation (RUN)',
    'Draft MOA & AOA',
    'File SPICe+ Form',
    'PAN & TAN Allotment',
    'Upload Final Certificate'
  ],
  'GST Registration': [
    'Collect Business Details',
    'Prepare Rent Agreement/NOC',
    'File GST REG-01',
    'Respond to Clarifications (if any)',
    'Final Certificate Download'
  ]
};

const EMPLOYEES_LIST = [
  { id: 1, name: 'Rahul Sharma', role: 'Maker' },
  { id: 2, name: 'Priya Verma', role: 'Maker' },
  { id: 3, name: 'Suresh Kumar', role: 'Checker' },
  { id: 4, name: 'Amit Patel', role: 'Checker' }
];

const INITIAL_TODO = [
  { id: 1, task: 'File GSTR-1 for TechFlow', due: 'Today', priority: 'High', assignee: 'Arjun' },
  { id: 2, task: 'Renew DSC for Director (Green Earth)', due: 'Tomorrow', priority: 'Medium', assignee: 'Priya' },
  { id: 3, task: 'Prepare Minutes for AGM (Apex)', due: 'Next Week', priority: 'Low', assignee: 'Rahul' },
];

const INITIAL_QUOTES = [
  { id: 'QT-2024-001', client: 'New Horizon Ventures', subject: 'Company Incorporation & Trademark', amount: 45000, status: 'Sent' },
  { id: 'QT-2024-002', client: 'Delta Exports', subject: 'IEC Registration & GeM Listing', amount: 15000, status: 'Draft' },
];

const INITIAL_INVOICES = [
  { id: 'INV-24-101', client: 'TechFlow Solutions', date: '01 Apr 2024', amount: 25000, status: 'Paid' },
  { id: 'INV-24-102', client: 'Green Earth NGO', date: '15 Apr 2024', amount: 15000, status: 'Overdue' },
];

const INITIAL_REPORTS = [
  { id: 1, name: 'GST Filing Status Report - Oct 2024', type: 'Compliance', generated: '10 Oct 2024' },
  { id: 2, name: 'Pending TDS Returns (Q2)', type: 'Taxation', generated: '05 Oct 2024' },
  { id: 3, name: 'Employee Utilization - Sep 2024', type: 'Internal', generated: '01 Oct 2024' },
];

const StatusBadge = ({ status }) => {
  const styles = {
    'In Progress': 'bg-blue-50 text-blue-700',
    'Completed': 'bg-emerald-50 text-emerald-700',
    'Paid': 'bg-emerald-50 text-emerald-700',
    'Sent': 'bg-blue-50 text-blue-700',
    'Overdue': 'bg-rose-50 text-rose-700',
    'Pending': 'bg-amber-50 text-amber-700',
    'Review': 'bg-purple-50 text-purple-700',
    'Draft': 'bg-slate-100 text-slate-600',
    'New': 'bg-indigo-100 text-indigo-700',
    'Assigned': 'bg-cyan-100 text-cyan-700',
    'Pending Documents': 'bg-amber-100 text-amber-700',
    'Documents Verified': 'bg-blue-100 text-blue-700',
    'Processing at Portal': 'bg-indigo-100 text-indigo-700',
    'Waiting for Clarification': 'bg-purple-100 text-purple-700'
  };
  return <span className={`px-2 py-1 rounded text-xs font-bold ${styles[status] || 'bg-slate-100'}`}>{status}</span>;
};

const SidebarItem = ({ icon: Icon, label, active, onClick, collapsed }) => (
  <button onClick={onClick} className={`flex items-center w-full p-3 mb-1 rounded-xl transition-all duration-200 ${active ? 'bg-indigo-600 text-white shadow-lg' : 'text-slate-500 hover:bg-slate-50 hover:text-indigo-600'}`} title={collapsed ? label : ''}>
    <Icon size={20} className="shrink-0" />
    <span className={`ml-3 font-medium text-sm whitespace-nowrap transition-all duration-300 ${collapsed ? 'opacity-0 w-0' : 'opacity-100 w-auto text-left'}`}>{label}</span>
  </button>
);

const ProjectWizard = ({ onClose, onSave }) => {
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState({
    title: '', client: '', service: 'Pvt Ltd Incorporation',
    maker: '', checker: '', checklist: CHECKLIST_TEMPLATES['Pvt Ltd Incorporation']
  });

  const handleServiceChange = (e) => {
    const service = e.target.value;
    setFormData({
      ...formData,
      service,
      checklist: CHECKLIST_TEMPLATES[service] || []
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-sm">
      <div className="bg-white w-[900px] h-[650px] rounded-3xl shadow-2xl flex overflow-hidden animate-in zoom-in-95 duration-300">
        <div className="w-1/3 bg-slate-900 p-8 flex flex-col justify-between text-white relative overflow-hidden">
          <div className="absolute top-0 right-0 w-64 h-64 bg-indigo-600 rounded-full blur-3xl -mr-16 -mt-16 opacity-50"></div>
          <div><h2 className="text-3xl font-bold mb-2">New Engagement</h2><p className="text-slate-400">Set up a new client mandate.</p></div>
          <div className="space-y-6 relative z-10">
            {[1, 2, 3].map(i => (
              <div key={i} className={`flex items-center gap-4 ${step === i ? 'opacity-100' : 'opacity-40'}`}>
                <div className={`w-8 h-8 rounded-full flex items-center justify-center font-bold border-2 ${step === i ? 'bg-indigo-500 border-indigo-500 text-white' : 'border-slate-600 text-slate-400'}`}>{i}</div>
                <div><p className="font-bold text-sm">{i === 1 ? 'Details & Service' : i === 2 ? 'Team & Tasks' : 'Commercials'}</p><p className="text-xs text-slate-400">{i === 1 ? 'Client Info' : i === 2 ? 'Maker-Checker' : 'Fees'}</p></div>
              </div>
            ))}
          </div>
        </div>
        <div className="flex-1 p-10 flex flex-col bg-slate-50">
          <div className="flex-1 overflow-y-auto pr-2">
            {step === 1 && (
              <div className="space-y-6 animate-in slide-in-from-right-4 duration-300">
                <h3 className="text-xl font-bold text-slate-800">Engagement Basics</h3>
                <div className="grid grid-cols-2 gap-5">
                  <div className="col-span-2"><label className="text-xs font-bold text-slate-500 uppercase">Engagement Title</label><input className="w-full p-3 border border-slate-200 rounded-xl bg-white outline-none" placeholder="e.g. Statutory Audit FY 2024-25" /></div>
                  <div><label className="text-xs font-bold text-slate-500 uppercase">Client</label><input className="w-full p-3 border border-slate-200 rounded-xl bg-white" placeholder="Search Client..." /></div>
                  <div>
                    <label className="text-xs font-bold text-slate-500 uppercase">Service Type</label>
                    <select className="w-full p-3 border border-slate-200 rounded-xl bg-white" value={formData.service} onChange={handleServiceChange}>
                      {Object.keys(CHECKLIST_TEMPLATES).map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </div>
                  <div><label className="text-xs font-bold text-slate-500 uppercase">Start Date</label><input type="date" className="w-full p-3 border border-slate-200 rounded-xl bg-white" /></div>
                  <div><label className="text-xs font-bold text-slate-500 uppercase">Deadline</label><input type="date" className="w-full p-3 border border-slate-200 rounded-xl bg-white" /></div>
                </div>
              </div>
            )}
            {step === 2 && (
              <div className="space-y-6 animate-in slide-in-from-right-4 duration-300">
                <h3 className="text-xl font-bold text-slate-800">Team & Workflow</h3>
                <div className="grid grid-cols-2 gap-5">
                  <div>
                    <label className="text-xs font-bold text-slate-500 uppercase">Assign Maker</label>
                    <select className="w-full p-3 border border-slate-200 rounded-xl bg-white">
                      <option value="">Select Staff</option>
                      {EMPLOYEES_LIST.filter(e => e.role === 'Maker').map(e => <option key={e.id} value={e.id}>{e.name}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="text-xs font-bold text-slate-500 uppercase">Assign Checker</label>
                    <select className="w-full p-3 border border-slate-200 rounded-xl bg-white">
                      <option value="">Select Senior</option>
                      {EMPLOYEES_LIST.filter(e => e.role === 'Checker').map(e => <option key={e.id} value={e.id}>{e.name}</option>)}
                    </select>
                  </div>
                </div>
              </div>
            )}
            {step === 3 && (
              <div className="space-y-6 animate-in slide-in-from-right-4 duration-300">
                <h3 className="text-xl font-bold text-slate-800">Finalize</h3>
                <p className="text-slate-500">Confirm all details and create the engagement.</p>
              </div>
            )}
          </div>
          <div className="flex justify-between pt-6 mt-4 border-t border-slate-200">
            {step > 1 ? <button onClick={() => setStep(s => s - 1)} className="px-6 py-2 text-slate-500 font-medium hover:bg-slate-200 rounded-xl">Back</button> : <button onClick={onClose} className="px-6 py-2 text-slate-500 font-medium hover:bg-slate-200 rounded-xl">Cancel</button>}
            {step < 3 ? <button onClick={() => setStep(s => s + 1)} className="px-6 py-2 bg-indigo-600 text-white font-bold rounded-xl shadow-lg">Continue</button> : <button onClick={() => { onSave(); onClose(); }} className="px-6 py-2 bg-emerald-600 text-white font-bold rounded-xl shadow-lg">Create Engagement</button>}
          </div>
        </div>
      </div>
    </div>
  );
};

const GenericListView = ({ title, sub, data, columns }) => (
  <div className="animate-in fade-in zoom-in duration-300">
    <div className="flex justify-between items-center mb-6">
      <div><h2 className="text-2xl font-bold text-slate-800">{title}</h2><p className="text-slate-500">{sub}</p></div>
    </div>
    <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden text-left">
      <table className="w-full text-left">
        <thead className="bg-slate-50 border-b border-slate-200 text-xs font-bold text-slate-500 uppercase">
          <tr>{columns.map((col, i) => <th key={i} className="px-6 py-4">{col}</th>)}<th className="px-6 py-4">Action</th></tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {data.map((item, i) => (
            <tr key={i} className="hover:bg-slate-50">
              {Object.values(item).slice(1).map((val, j) => (
                <td key={j} className="px-6 py-4 text-sm text-slate-700 font-medium">{val}</td>
              ))}
              <td className="px-6 py-4"><MoreVertical size={16} className="text-slate-400" /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </div>
);

const ReportsView = () => (
  <div className="animate-in fade-in zoom-in duration-300">
    <div className="mb-6 text-left"><h2 className="text-2xl font-bold text-slate-800">Reports Center</h2><p className="text-slate-500">Practice Performance Reports</p></div>
    <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden text-left">
      <table className="w-full text-left">
        <thead className="bg-slate-50 border-b border-slate-200 text-xs font-bold text-slate-500 uppercase">
          <tr><th className="px-6 py-4">Report Name</th><th className="px-6 py-4">Category</th><th className="px-6 py-4">Generated Date</th><th className="px-6 py-4">Action</th></tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {INITIAL_REPORTS.map((report) => (
            <tr key={report.id} className="hover:bg-slate-50">
              <td className="px-6 py-4 text-sm font-medium text-slate-700 flex items-center"><FileSpreadsheet size={16} className="mr-2 text-emerald-600" />{report.name}</td>
              <td className="px-6 py-4 text-sm text-slate-600">{report.type}</td>
              <td className="px-6 py-4 text-sm text-slate-500">{report.generated}</td>
              <td className="px-6 py-4"><button className="text-indigo-600 hover:text-indigo-800 text-xs font-bold flex items-center"><Download size={14} className="mr-1" /> Download</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </div>
);

function App() {
  const [activeTab, setActiveTab] = useState('Dashboard');
  const [currentView, setCurrentView] = useState('list');
  const [selectedProject, setSelectedProject] = useState(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [userInfo, setUserInfo] = useState(null);
  const [detailTab, setDetailTab] = useState('Overview');
  const [orders, setOrders] = useState([]);
  const [employees, setEmployees] = useState([]);
  const [users, setUsers] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    const user = localStorage.getItem('userInfo');
    if (user) {
      const parsed = JSON.parse(user);
      if (parsed.role === 'admin') {
        setUserInfo(parsed);
        setIsLoggedIn(true);
      } else {
        alert("Access Denied. Admin only.");
        navigate('/');
      }
    } else {
      navigate('/');
    }
  }, [navigate]);

  const fetchData = async () => {
    if (!userInfo) return;
    try {
      const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
      const [ordersRes, empRes, usersRes] = await Promise.all([
        axios.get('/api/orders', config),
        axios.get('/api/auth/employees', config),
        axios.get('/api/auth/users', config)
      ]);
      setOrders(ordersRes.data);
      setEmployees(empRes.data);
      setUsers(usersRes.data);
    } catch (error) {
      console.error("Failed to fetch data:", error);
    }
  };

  useEffect(() => {
    fetchData();
  }, [userInfo]);

  const handleLogout = () => {
    localStorage.removeItem('userInfo');
    navigate('/login');
  };

  const assignEmployee = async (orderId, employeeId) => {
    try {
      const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
      await axios.put(`/api/orders/${orderId}/assign`, { employeeId }, config);
      alert("Order assigned successfully!");
      fetchData();
    } catch (e) {
      alert("Error assigning employee.");
    }
  };

  const updateTask = async (orderId, taskId, updates) => {
    try {
      const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
      await axios.put(`/api/orders/${orderId}/tasks/${taskId}`, updates, config);
      fetchData();
    } catch (e) { alert("Error updating task."); }
  };

  const addSubtask = async (orderId, taskId, title) => {
    try {
      const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
      await axios.post(`/api/orders/${orderId}/tasks/${taskId}/subtasks`, { title }, config);
      fetchData();
    } catch (e) { alert("Error adding subtask."); }
  };

  const toggleChecklist = async (orderId, itemId) => {
    try {
      const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
      await axios.put(`/api/orders/${orderId}/checklists/${itemId}/toggle`, {}, config);
      fetchData();
    } catch (e) { alert("Error toggling checklist."); }
  };

  if (!isLoggedIn) return <div className="min-h-screen flex items-center justify-center bg-slate-900 text-white font-bold">Verifying Access...</div>;

  const DashboardView = () => (
    <div className="animate-in fade-in zoom-in duration-300">
      <div className="mb-8 text-left"><h1 className="text-2xl font-bold text-slate-800">Admin Overview</h1><p className="text-slate-500">Practice Performance & Active Projects</p></div>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        {[
          { label: 'Total Revenue', val: `₹ ${orders.reduce((acc, curr) => acc + curr.price, 0).toLocaleString()}`, icon: Receipt, color: 'text-emerald-600', bg: 'bg-emerald-50' },
          { label: 'Total Orders', val: orders.length, icon: Layers, color: 'text-indigo-600', bg: 'bg-indigo-50' },
          { label: 'Pending Assignment', val: orders.filter(o => !o.assignedEmployee).length, icon: Users, color: 'text-amber-600', bg: 'bg-amber-50' },
          { label: 'Completed Orders', val: orders.filter(o => o.status === 'Completed').length, icon: CheckSquare, color: 'text-blue-600', bg: 'bg-blue-50' }
        ].map((stat, i) => (
          <div key={i} className="bg-white p-6 rounded-2xl border border-slate-100 shadow-sm flex items-start justify-between text-left">
            <div><p className="text-slate-500 text-sm font-medium mb-1">{stat.label}</p><h3 className="text-2xl font-bold text-slate-800">{stat.val}</h3></div>
            <div className={`p-3 rounded-xl ${stat.bg} ${stat.color}`}><stat.icon size={20} /></div>
          </div>
        ))}
      </div>
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden text-left">
        <div className="p-5 border-b border-slate-100"><h3 className="font-bold text-slate-800">Recent Orders</h3></div>
        <table className="w-full text-left">
          <thead className="bg-slate-50 text-xs font-bold text-slate-500 uppercase">
            <tr><th className="p-4">Client</th><th className="p-4">Service</th><th className="p-4">Status</th></tr>
          </thead>
          <tbody className="divide-y divide-slate-100 text-sm">
            {orders.slice(0, 5).map(order => (
              <tr key={order._id}><td className="p-4 font-medium">{order.user?.name}</td><td className="p-4">{order.serviceName}</td><td className="p-4"><StatusBadge status={order.status} /></td></tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  const ProjectListView = () => (
    <div className="animate-in fade-in zoom-in duration-300">
      <div className="mb-6 text-left"><h2 className="text-2xl font-bold text-slate-800">Engagements</h2><p className="text-slate-500">Manage client orders and staff assignments.</p></div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {orders.map(proj => (
          <div key={proj._id} onClick={() => { setSelectedProject(proj); setCurrentView('detail'); }} className="bg-white p-5 rounded-2xl border border-slate-200 shadow-sm hover:shadow-md cursor-pointer text-left">
            <div className="flex justify-between mb-3"><StatusBadge status={proj.status} /></div>
            <h3 className="font-bold text-lg text-slate-800">{proj.serviceName}</h3>
            <p className="text-sm text-slate-500">Client: {proj.user?.name}</p>
          </div>
        ))}
      </div>
    </div>
  );

  const ProjectDetailView = ({ project, onBack, employees, assignEmployee }) => {
    return (
      <div className="h-full flex flex-col animate-in slide-in-from-right duration-300 text-left">
        <div className="bg-white p-6 border-b border-slate-200 flex justify-between items-center">
          <div className="flex items-center gap-4">
            <button onClick={onBack} className="p-2 hover:bg-slate-100 rounded-full text-slate-500 transition-colors"><ChevronLeft size={24} /></button>
            <div>
              <h1 className="text-2xl font-bold text-slate-800">{project.serviceName}</h1>
              <p className="text-slate-500 text-sm flex items-center mt-1"><Building2 size={14} className="mr-1" /> {project.user?.name} | <span className="text-indigo-600 font-medium ml-2">Value: ₹ {project.price.toLocaleString()}</span></p>
            </div>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto p-6 bg-slate-50 grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
            <h3 className="font-bold text-lg mb-4 text-slate-800">Order Information</h3>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between border-b pb-2"><span className="text-slate-500">Status</span><StatusBadge status={project.status} /></div>
              <div className="flex justify-between border-b pb-2"><span className="text-slate-500">Service</span><span className="font-bold">{project.serviceName}</span></div>
              <div className="flex justify-between border-b pb-2"><span className="text-slate-500">Client</span><span className="font-bold">{project.user?.name}</span></div>
            </div>
          </div>
          <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
            <h3 className="font-bold text-lg mb-4 text-slate-800 flex items-center"><Users className="mr-2 text-indigo-600" /> Team Assignment</h3>
            <select
              value={project.assignedEmployee?._id || project.assignedEmployee || ''}
              onChange={(e) => assignEmployee(project._id, e.target.value)}
              className="w-full p-3 border border-slate-300 rounded-lg bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500 font-medium"
            >
              <option value="">-- Unassigned --</option>
              {employees.map(e => <option key={e._id} value={e._id}>{e.name} ({e.email})</option>)}
            </select>
          </div>
          {/* Add Task/Subtask UI can be added here as needed */}
        </div>
      </div>
    );
  };

  const UsersView = () => (
    <div className="animate-in fade-in zoom-in duration-300">
      <div className="flex justify-between items-center mb-6 text-left">
        <div><h2 className="text-2xl font-bold text-slate-800">Users & Clients</h2><p className="text-slate-500">Manage registration records.</p></div>
      </div>
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden text-left">
        <table className="w-full text-left">
          <thead className="bg-slate-50 border-b border-slate-200 text-xs font-bold text-slate-500 uppercase">
            <tr><th className="px-6 py-4">Name</th><th className="px-6 py-4">Email</th><th className="px-6 py-4">Role</th><th className="px-6 py-4">Action</th></tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {users.map(user => (
              <tr key={user._id} className="hover:bg-slate-50">
                <td className="px-6 py-4 text-sm font-bold text-slate-700">{user.name}</td>
                <td className="px-6 py-4 text-sm text-slate-600">{user.email}</td>
                <td className="px-6 py-4"><span className={`px-2 py-1 rounded text-xs font-bold uppercase ${user.role === 'admin' ? 'bg-indigo-100 text-indigo-700' : 'bg-emerald-100 text-emerald-700'}`}>{user.role}</span></td>
                <td className="px-6 py-4"><MoreVertical size={16} className="text-slate-400 cursor-pointer" /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  return (
    <div className="flex h-screen bg-slate-50 font-sans text-slate-800 overflow-hidden">
      <aside className={`${sidebarCollapsed ? 'w-20' : 'w-64'} bg-white h-full border-r border-slate-200 flex flex-col py-6 transition-all duration-300 z-20 shadow-xl`} onMouseEnter={() => setSidebarCollapsed(false)} onMouseLeave={() => setSidebarCollapsed(true)}>
        <div className="flex items-center justify-center mb-8 px-4 h-12 overflow-hidden">
          <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center text-white font-bold text-lg shrink-0">VR</div>
          {!sidebarCollapsed && <span className="ml-3 font-bold text-xl tracking-tight">Admin <span className="text-indigo-600">Panel</span></span>}
        </div>
        <div className="space-y-1 flex-1 px-3 overflow-y-auto">
          <SidebarItem icon={LayoutDashboard} label="Dashboard" active={activeTab === 'Dashboard'} onClick={() => setActiveTab('Dashboard')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={Users} label="Users" active={activeTab === 'Users'} onClick={() => setActiveTab('Users')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={Layers} label="Orders" active={activeTab === 'Projects'} onClick={() => { setActiveTab('Projects'); setCurrentView('list'); }} collapsed={sidebarCollapsed} />
          <SidebarItem icon={CheckSquare} label="To Do" active={activeTab === 'ToDo'} onClick={() => setActiveTab('ToDo')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={DollarSign} label="Finance" active={activeTab === 'Finance'} onClick={() => setActiveTab('Finance')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={BarChart} label="Reports" active={activeTab === 'Reports'} onClick={() => setActiveTab('Reports')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={ServiceIcon} label="Services master" active={activeTab === 'Services' || activeTab === 'Quotation'} onClick={() => setActiveTab('Services')} collapsed={sidebarCollapsed} />
        </div>
        <div className="p-4 border-t border-slate-100">
          <button onClick={handleLogout} className="flex items-center w-full p-2 rounded-lg text-rose-500 hover:bg-rose-50"><LogOut size={20} /><span className={`ml-3 text-sm ${sidebarCollapsed ? 'opacity-0' : 'opacity-100'}`}>Logout</span></button>
        </div>
      </aside>
      <main className="flex-1 flex flex-col h-full overflow-hidden">
        <header className="h-16 bg-white border-b border-slate-200 flex items-center justify-between px-8 text-left">
          <h1 className="text-xl font-bold text-slate-800">{activeTab}</h1>
          <div className="w-8 h-8 rounded-full bg-indigo-100 text-indigo-700 flex items-center justify-center font-bold text-xs">{userInfo?.name?.charAt(0)}</div>
        </header>
        <div className="flex-1 overflow-y-auto p-8 bg-slate-50/50">
          {activeTab === 'Dashboard' && <DashboardView />}
          {activeTab === 'Users' && <UsersView />}
          {activeTab === 'Projects' && currentView === 'list' && <ProjectListView />}
          {activeTab === 'Projects' && currentView === 'detail' && <ProjectDetailView project={selectedProject} onBack={() => setCurrentView('list')} employees={employees} assignEmployee={assignEmployee} />}
          {activeTab === 'ToDo' && <GenericListView title="Task List" sub="Ad-hoc Compliance Tasks" data={INITIAL_TODO} columns={['Task', 'Due Date', 'Priority', 'Assignee']} />}
          {activeTab === 'Finance' && <GenericListView title="Invoices" sub="Billing & Receivables" data={INITIAL_INVOICES} columns={['Client', 'Date', 'Amount', 'Status']} />}
          {activeTab === 'Reports' && <ReportsView />}
          {activeTab === 'Services' && <ServicesMasterView token={userInfo?.token} />}
        </div>
      </main>
    </div>
  );
}

export default App;
