import React, { useState, useEffect } from 'react';
import {
  LayoutDashboard, Users, User, FileText, CheckSquare, Settings, Bell,
  Menu, ChevronDown, MoreVertical, LogOut, Plus, Download,
  Building2, ChevronRight, Layers, MessageSquare, Briefcase,
  BookOpen, Anchor, Globe, Factory, Stamp, Receipt, Scale, FileSpreadsheet
} from 'lucide-react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const StatusBadge = ({ status }) => {
  const styles = {
    'Pending Documents': 'bg-amber-100 text-amber-700',
    'Documents Verified': 'bg-blue-100 text-blue-700',
    'Processing at Portal': 'bg-indigo-100 text-indigo-700',
    'Waiting for Clarification': 'bg-purple-100 text-purple-700',
    'Completed': 'bg-emerald-100 text-emerald-700'
  };
  return <span className={`px-2 py-1 rounded text-xs font-bold ${styles[status] || 'bg-slate-100'}`}>{status}</span>;
};

const SidebarItem = ({ icon: Icon, label, active, onClick, collapsed }) => (
  <button onClick={onClick} className={`flex items-center w-full p-3 mb-1 rounded-xl transition-all duration-200 ${active ? 'bg-indigo-600 text-white shadow-lg' : 'text-slate-500 hover:bg-slate-50 hover:text-indigo-600'}`} title={collapsed ? label : ''}>
    <Icon size={20} className="shrink-0" />
    <span className={`ml-3 font-medium text-sm whitespace-nowrap transition-all duration-300 ${collapsed ? 'opacity-0 w-0 overflow-hidden' : 'opacity-100 w-auto'}`}>{label}</span>
  </button>
);


// --- MAIN APP ---
function App() {
  const [activeTab, setActiveTab] = useState('Dashboard');
  const [currentView, setCurrentView] = useState('list');
  const [selectedProject, setSelectedProject] = useState(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true);
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
      if (selectedProject && selectedProject._id === orderId) {
        setSelectedProject(prev => ({ ...prev, assignedEmployee: employeeId }));
      }
    } catch (e) {
      alert("Error assigning employee.");
    }
  };

  const addTask = async (orderId, title, description) => {
    try {
      const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
      await axios.post(`/api/orders/${orderId}/tasks`, { title, description }, config);
      fetchData();
      alert("Task added!");
    } catch (e) { alert("Error adding task."); }
  };

  const addChecklistItem = async (orderId, title) => {
    try {
      const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
      await axios.post(`/api/orders/${orderId}/checklists`, { title }, config);
      fetchData();
      alert("Checklist item added!");
    } catch (e) { alert("Error adding checklist item."); }
  };

  const updateTask = async (orderId, taskId, updates) => {
    try {
      const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
      await axios.put(`/api/orders/${orderId}/tasks/${taskId}`, updates, config);
      fetchData();
    } catch (e) { alert("Error updating task."); }
  };

  const addInvoice = async (orderId, invoiceNumber, amount) => {
    try {
      const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
      await axios.post(`/api/orders/${orderId}/invoices`, { invoiceNumber, amount }, config);
      fetchData();
      alert("Invoice added!");
    } catch (e) { alert("Error adding invoice."); }
  };

  const updateInvoiceStatus = async (orderId, invoiceId, status) => {
    try {
      const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
      await axios.put(`/api/orders/${orderId}/invoices/${invoiceId}/status`, { status }, config);
      fetchData();
      alert(`Invoice marked as ${status}`);
    } catch (e) { alert("Error updating invoice status."); }
  };

  const toggleChecklist = async (orderId, itemId) => {
    try {
      const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
      await axios.put(`/api/orders/${orderId}/checklists/${itemId}/toggle`, {}, config);
      fetchData();
    } catch (e) { alert("Error toggling checklist."); }
  };


  if (!isLoggedIn) return <div className="min-h-screen flex items-center justify-center bg-slate-900 text-white font-bold">Verifying Access...</div>;

  // DASHBOARD VIEW
  const DashboardView = () => (
    <div className="animate-in fade-in zoom-in duration-300">
      <div className="mb-8"><h1 className="text-2xl font-bold text-slate-800">Admin Overview</h1><p className="text-slate-500">Practice Performance & Active Projects</p></div>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        {[
          { label: 'Total Revenue', val: `₹ ${orders.reduce((acc, curr) => acc + curr.price, 0).toLocaleString()}`, icon: Receipt, color: 'text-emerald-600', bg: 'bg-emerald-50' },
          { label: 'Total Orders', val: orders.length, icon: Layers, color: 'text-indigo-600', bg: 'bg-indigo-50' },
          { label: 'Pending Assignment', val: orders.filter(o => !o.assignedEmployee).length, icon: Users, color: 'text-amber-600', bg: 'bg-amber-50' },
          { label: 'Completed Orders', val: orders.filter(o => o.status === 'Completed').length, icon: CheckSquare, color: 'text-blue-600', bg: 'bg-blue-50' }
        ].map((stat, i) => (
          <div key={i} className="bg-white p-6 rounded-2xl border border-slate-100 shadow-sm flex items-start justify-between">
            <div><p className="text-slate-500 text-sm font-medium mb-1">{stat.label}</p><h3 className="text-2xl font-bold text-slate-800">{stat.val}</h3></div>
            <div className={`p-3 rounded-xl ${stat.bg} ${stat.color}`}><stat.icon size={20} /></div>
          </div>
        ))}
      </div>


      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
        <div className="p-5 border-b border-slate-100 flex justify-between items-center"><h3 className="font-bold text-slate-800">Recent Orders (All Users)</h3></div>
        <table className="w-full text-left">
          <thead className="bg-slate-50 text-xs uppercase font-bold text-slate-500">
            <tr>
              <th className="p-4">Client</th>
              <th className="p-4">Service</th>
              <th className="p-4">Date</th>
              <th className="p-4">Status</th>
              <th className="p-4">Assigned To</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 text-sm">
            {orders.slice(0, 5).map(order => {
              const empId = order.assignedEmployee?._id || order.assignedEmployee;
              const emp = employees.find(e => e._id === empId);
              return (
                <tr key={order._id} className="hover:bg-slate-50 transition">
                  <td className="p-4 font-bold text-slate-700">{order.user?.name || 'Unknown'}</td>
                  <td className="p-4 text-slate-600">{order.serviceName}</td>
                  <td className="p-4 text-slate-500">{new Date(order.createdAt).toLocaleDateString()}</td>
                  <td className="p-4"><StatusBadge status={order.status} /></td>
                  <td className="p-4 font-bold text-indigo-600">{emp ? emp.name : 'Unassigned'}</td>
                </tr>
              );
            })}
          </tbody>
        </table>

      </div>
    </div>
  );

  // PROJECT LIST VIEW
  const ProjectListView = () => (
    <div className="animate-in fade-in zoom-in duration-300 h-full flex flex-col">
      <div className="flex justify-between items-center mb-6">
        <div><h2 className="text-2xl font-bold text-slate-800">All Engagements / Orders</h2><p className="text-slate-500">Manage all client orders and assign staff.</p></div>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {orders.map(proj => {
          const empId = proj.assignedEmployee?._id || proj.assignedEmployee;
          const emp = employees.find(e => e._id === empId);
          return (
            <div key={proj._id} onClick={() => { setSelectedProject(proj); setCurrentView('detail'); }} className="bg-white p-5 rounded-2xl border border-slate-200 shadow-sm hover:shadow-md cursor-pointer group flex flex-col justify-between">
              <div>
                <div className="flex justify-between items-start mb-3">
                  <div className="p-2 bg-indigo-50 text-indigo-600 rounded-lg"><Briefcase size={20} /></div>
                  <StatusBadge status={proj.status} />
                </div>
                <h3 className="font-bold text-lg text-slate-800 mb-1 group-hover:text-indigo-600">{proj.serviceName}</h3>
                <p className="text-sm text-slate-500 mb-2">Client: {proj.user?.name}</p>
                <p className="text-xs text-slate-400 mb-4">Value: â‚¹{proj.price.toLocaleString()}</p>
              </div>
              <div className="pt-3 border-t border-slate-100">
                <p className="text-xs font-bold text-slate-600">Assigned: <span className={emp ? "text-indigo-600" : "text-amber-500"}>{emp ? emp.name : 'None'}</span></p>
              </div>
            </div>
          );
        })}

      </div>
    </div>
  );


  // GENERIC LIST VIEW COMPONENT (Reusable for ToDo, Quotation, Finance, etc.)
  const GenericListView = ({ title, sub, data, columns }) => (
    <div className="animate-in fade-in zoom-in duration-300">
      <div className="flex justify-between items-center mb-6">
        <div><h2 className="text-2xl font-bold text-slate-800">{title}</h2><p className="text-slate-500">{sub}</p></div>
        <button className="bg-indigo-600 text-white px-4 py-2 rounded-xl text-sm font-medium flex items-center shadow-lg"><Plus size={18} className="mr-2" /> Create New</button>
      </div>
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
        <table className="w-full text-left">
          <thead className="bg-slate-50 border-b border-slate-200 text-xs font-bold text-slate-500 uppercase">
            <tr>{columns.map((col, i) => <th key={i} className="px-6 py-4">{col}</th>)}<th className="px-6 py-4">Action</th></tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {data.map((item, i) => (
              <tr key={i} className="hover:bg-slate-50">
                {Object.values(item).slice(1).map((val, j) => ( // Skip ID
                  <td key={j} className="px-6 py-4 text-sm text-slate-700 font-medium">
                    {['High', 'Medium', 'Low', 'Sent', 'Draft', 'Paid', 'Overdue', 'Processed', 'Pending', 'New', 'Assigned', 'In Progress'].includes(val) ? <StatusBadge status={val} /> : val}
                  </td>
                ))}
                <td className="px-6 py-4"><MoreVertical size={16} className="text-slate-400 cursor-pointer hover:text-indigo-600" /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  // SERVICES CATALOG VIEW
  const ServicesView = () => (
    <div className="animate-in fade-in zoom-in duration-300">
      <div className="mb-6"><h2 className="text-2xl font-bold text-slate-800">Service Catalog</h2><p className="text-slate-500">Master List of Offerings</p></div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {Object.entries(SERVICE_CATALOG).map(([cat, services]) => (
          <div key={cat} className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
            <div className="flex items-center gap-3 mb-4 text-indigo-600">
              {cat.includes('Industrial') ? <Factory /> : cat.includes('ISO') ? <Stamp /> : cat.includes('Tax') ? <Receipt /> : cat.includes('Registration') ? <Globe /> : <Briefcase />}
              <h3 className="font-bold text-lg text-slate-800">{cat}</h3>
            </div>
            <ul className="space-y-2">
              {services.map(s => <li key={s} className="text-sm text-slate-600 flex items-center"><div className="w-1.5 h-1.5 rounded-full bg-slate-300 mr-2"></div>{s}</li>)}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );

  // REPORTS VIEW (Mock)
  const ReportsView = () => (
    <div className="animate-in fade-in zoom-in duration-300">
      <div className="mb-6"><h2 className="text-2xl font-bold text-slate-800">Reports Center</h2><p className="text-slate-500">Generated Compliance & MIS Reports</p></div>
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
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
  // PROJECT DEEP DIVE
  const ProjectDetailView = ({ project, onBack }) => {
    const empId = project.assignedEmployee?._id || project.assignedEmployee;
    const emp = employees.find(e => e._id === empId);

    return (
      <div className="h-full flex flex-col animate-in slide-in-from-right duration-300">
        <div className="bg-white p-6 border-b border-slate-200 flex justify-between items-center sticky top-0 z-10">
          <div className="flex items-center gap-4">
            <button onClick={onBack} className="p-2 hover:bg-slate-100 rounded-full text-slate-500 transition-colors"><ChevronRight className="rotate-180" size={24} /></button>
            <div>
              <h1 className="text-2xl font-bold text-slate-800">{project.serviceName}</h1>
              <p className="text-slate-500 text-sm flex items-center mt-1"><Building2 size={14} className="mr-1" /> {project.user?.name} <span className="mx-2 text-slate-300">|</span> <span className="text-indigo-600 font-medium">Value: â‚¹ {project.price.toLocaleString()}</span></p>
            </div>
          </div>
        </div>
        <div className="bg-white border-b border-slate-200 sticky top-16 z-10 transition-all duration-300">
          <div className="flex px-10">
            {['Overview', 'Workflow', 'Checklist', 'Invoicing'].map(tab => (
              <button
                key={tab}
                onClick={() => setDetailTab(tab)}
                className={`px-6 py-4 text-sm font-bold border-b-2 transition-all ${detailTab === tab ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-slate-500 hover:text-indigo-600'}`}
              >
                {tab}
              </button>
            ))}
          </div>
        </div>


        <div className="flex-1 overflow-y-auto p-6 bg-slate-50">
          {detailTab === 'Overview' && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-in fade-in slide-in-from-bottom-4 duration-300">
              {/* Order Details */}
              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <h3 className="font-bold text-lg mb-4 text-slate-800">Order Information</h3>
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between border-b pb-2"><span className="text-slate-500">Service</span><span className="font-bold">{project.serviceName}</span></div>
                  <div className="flex justify-between border-b pb-2"><span className="text-slate-500">Package</span><span className="font-bold">{project.packageName}</span></div>
                  <div className="flex justify-between border-b pb-2"><span className="text-slate-500">Date Ordered</span><span className="font-bold">{new Date(project.createdAt).toLocaleDateString()}</span></div>
                  <div className="flex justify-between border-b pb-2"><span className="text-slate-500">Current Status</span><StatusBadge status={project.status} /></div>
                </div>
              </div>

              {/* Client Details */}
              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <h3 className="font-bold text-lg mb-4 text-slate-800 flex items-center"><User className="mr-2 text-indigo-600" /> Client Information</h3>
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between border-b pb-2"><span className="text-slate-500">Name</span><span className="font-bold">{project.user?.name || 'Loading...'}</span></div>
                  <div className="flex justify-between border-b pb-2"><span className="text-slate-500">Email</span><span className="font-bold">{project.user?.email || 'N/A'}</span></div>
                  <div className="flex justify-between border-b pb-2"><span className="text-slate-500">Phone</span><span className="font-bold">{project.user?.phone || 'N/A'}</span></div>
                </div>
              </div>

              {/* Assignment & Execution */}
              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <h3 className="font-bold text-lg mb-4 text-slate-800 flex items-center"><Users className="mr-2 text-indigo-600" /> Team Assignment</h3>
                <div className="mb-6">
                  <label className="text-sm font-bold text-slate-600 mb-2 block">Assign Employee to Order:</label>
                  <select
                    value={project.assignedEmployee?._id || project.assignedEmployee || ''}
                    onChange={(e) => assignEmployee(project._id, e.target.value)}
                    className="w-full p-3 border border-slate-300 rounded-lg bg-slate-50 text-slate-700 font-medium outline-none focus:ring-2 focus:ring-indigo-500"
                  >
                    <option value="">-- Unassigned --</option>
                    {employees.map(e => <option key={e._id} value={e._id}>{e.name} ({e.email})</option>)}
                  </select>
                </div>
                <div className="p-4 bg-indigo-50 border border-indigo-100 rounded-xl">
                  <p className="text-sm text-indigo-800 font-medium">Once assigned, the employee will see this order in their Employee Dashboard workspace.</p>
                </div>
              </div>

              {/* Documents Overview */}
              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <h3 className="font-bold text-lg mb-4 text-slate-800">Documents Status</h3>
                <div className="space-y-4">
                  <div>
                    <h4 className="text-xs font-bold text-slate-400 uppercase mb-2">Client Documents</h4>
                    <div className="space-y-2">
                      {project.clientDocuments?.slice(0, 3).map(doc => (
                        <div key={doc._id} className="flex justify-between items-center bg-slate-50 p-2 rounded border border-slate-100 italic text-xs">
                          <span className="truncate mr-2">{doc.name}</span>
                          <Download size={12} className="text-indigo-600" />
                        </div>
                      ))}
                      {(!project.clientDocuments || project.clientDocuments.length === 0) && <p className="text-xs text-slate-400">No documents yet.</p>}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {detailTab === 'Workflow' && (
            <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-300">
              <div className="flex justify-between items-center bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <div><h3 className="font-bold text-lg text-slate-800">Project Workflow / Tasks</h3><p className="text-sm text-slate-500">Track and manage service delivery milestones.</p></div>
                <button className="bg-indigo-600 text-white px-4 py-2 rounded-xl text-xs font-bold flex items-center shadow-md"><Plus size={16} className="mr-2" /> Add Task</button>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {['Pending', 'In Progress', 'Completed'].map(col => (
                  <div key={col} className="bg-slate-100 p-4 rounded-2xl min-h-[400px]">
                    <h4 className="font-bold text-slate-500 text-xs uppercase mb-4 flex justify-between items-center">
                      {col} <span className="bg-white px-2 py-0.5 rounded-full text-[10px]">{project.tasks?.filter(t => t.status === col).length || 0}</span>
                    </h4>
                    <div className="space-y-3">
                      {project.tasks?.filter(t => t.status === col).map(task => (
                        <div key={task._id} className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm hover:shadow-md transition cursor-pointer group" onClick={() => {
                          const newStatus = col === 'Pending' ? 'In Progress' : col === 'In Progress' ? 'Completed' : 'Pending';
                          if (window.confirm(`Move task to ${newStatus}?`)) {
                            updateTask(project._id, task._id, { status: newStatus });
                          }
                        }}>
                          <h5 className="font-bold text-sm text-slate-800 mb-1 group-hover:text-indigo-600">{task.title}</h5>
                          <p className="text-xs text-slate-500 mb-3">{task.description}</p>
                          <div className="flex justify-between items-center">
                            <span className="text-[10px] font-bold text-slate-400">{task.subtasks?.length || 0} Subtasks</span>
                            <div className={`w-2 h-2 rounded-full ${col === 'Completed' ? 'bg-emerald-500' : col === 'In Progress' ? 'bg-blue-500' : 'bg-slate-300'}`}></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {detailTab === 'Checklist' && (
            <div className="bg-white p-8 rounded-2xl border border-slate-200 shadow-sm animate-in fade-in slide-in-from-bottom-4 duration-300">
              <div className="flex justify-between items-center mb-8 pb-4 border-b border-slate-100">
                <div><h3 className="font-bold text-lg text-slate-800">Requirement Checklist</h3><p className="text-sm text-slate-500">Manage documents and information required from client.</p></div>
                <button onClick={() => {
                  const items = ['Business PAN', 'Aadhar Card', 'Address Proof', 'Bank Statement'];
                  items.forEach(title => addChecklistItem(project._id, title));
                }} className="text-indigo-600 font-bold text-xs hover:underline flex items-center"><Plus size={14} className="mr-1" /> Import Standard Checklist</button>
              </div>
              <div className="space-y-4">
                {project.checklists?.map((item, i) => (
                  <div key={i} className="flex items-center justify-between p-4 bg-slate-50 rounded-xl border border-slate-100 group">
                    <div className="flex items-center gap-3">
                      <button
                        onClick={() => toggleChecklist(project._id, item._id)}
                        className={`w-5 h-5 rounded border-2 flex items-center justify-center transition-colors ${item.isCompleted ? 'bg-emerald-500 border-emerald-500 text-white' : 'border-slate-300 bg-white hover:border-indigo-400'}`}
                      >
                        {item.isCompleted && <CheckSquare size={14} />}
                      </button>
                      <span className={`font-medium ${item.isCompleted ? 'text-slate-400 line-through' : 'text-slate-700'}`}>{item.title}</span>
                    </div>
                  </div>

                ))}
                {(!project.checklists || project.checklists.length === 0) && (
                  <div className="text-center py-12 border-2 border-dashed border-slate-200 rounded-2xl">
                    <p className="text-slate-400 text-sm">No checklist items defined. Import a standard checklist to begin.</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {detailTab === 'Invoicing' && (
            <div className="bg-white p-8 rounded-2xl border border-slate-200 shadow-sm animate-in fade-in slide-in-from-bottom-4 duration-300">
              <div className="flex justify-between items-center mb-8 pb-4 border-b border-slate-100">
                <div><h3 className="font-bold text-lg text-slate-800">Invoices & Payments</h3><p className="text-sm text-slate-500">Track professional fees and government payments.</p></div>
                <button onClick={() => {
                  const num = `INV-${Math.floor(Math.random() * 10000)}`;
                  const amt = prompt("Enter Invoice Amount:", "1000");
                  if (amt) addInvoice(project._id, num, parseInt(amt));
                }} className="bg-emerald-600 text-white px-4 py-2 rounded-xl text-xs font-bold shadow-md hover:bg-emerald-700 transition">Create New Invoice</button>
              </div>

              <div className="space-y-4">
                <div className="bg-emerald-50 p-6 rounded-2xl border border-emerald-100 flex justify-between items-center">
                  <div><p className="text-xs font-bold text-emerald-600 uppercase mb-1">Total Project Value</p><h4 className="text-2xl font-black text-slate-800">â‚¹ {project.price.toLocaleString()}</h4></div>
                  <div className="text-right">
                    <p className="text-xs font-bold text-slate-400 uppercase mb-1">Initial Payment Recieved</p>
                    <span className="px-3 py-1 bg-emerald-100 text-emerald-700 rounded-full text-[10px] font-black uppercase">PAID</span>
                  </div>
                </div>
                <div className="pt-4"><h5 className="font-bold text-slate-700 mb-4 text-sm">Invoice History</h5><div className="border border-slate-100 rounded-xl overflow-hidden"><table className="w-full text-left text-xs"><thead className="bg-slate-50 font-bold text-slate-400 uppercase border-b border-slate-100"><tr><th className="p-4">Invoice #</th><th className="p-4">Amount</th><th className="p-4">Status</th><th className="p-4">Date</th><th className="p-4 text-right">Action</th></tr></thead><tbody className="divide-y divide-slate-100">{project.invoices?.map(inv => (<tr key={inv.invoiceNumber}><td className="p-4 font-bold text-slate-800">{inv.invoiceNumber}</td><td className="p-4">â‚¹ {inv.amount.toLocaleString()}</td><td className="p-4"><StatusBadge status={inv.status} /></td><td className="p-4 text-slate-500">{new Date(inv.createdAt).toLocaleDateString()}</td><td className="p-4 text-right"><Download size={14} className="inline text-indigo-600 cursor-pointer" /></td></tr>))}</tbody></table>{(!project.invoices || project.invoices.length === 0) && <p className="p-6 text-center text-slate-400 italic">No additional invoices generated.</p>}</div></div>
              </div>
            </div>
          )}
        </div>

      </div>
    );
  };

  return (
    <div className="flex h-screen bg-slate-50 font-sans text-slate-800 overflow-hidden">
      <aside className={`${sidebarCollapsed ? 'w-20' : 'w-72'} bg-white h-full border-r border-slate-200 flex flex-col py-6 z-20 shadow-xl transition-all duration-300`} onMouseEnter={() => setSidebarCollapsed(false)} onMouseLeave={() => setSidebarCollapsed(true)}>
        <div className="flex items-center justify-center mb-8 px-4 h-12 overflow-hidden whitespace-nowrap">
          <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center text-white font-bold text-lg shadow-lg shrink-0">VR</div>
          <span className={`ml-3 font-bold text-xl tracking-tight text-slate-800 transition-opacity duration-300 ${sidebarCollapsed ? 'opacity-0 w-0' : 'opacity-100'}`}>Admin <span className="text-indigo-600">Panel</span></span>
        </div>
        <div className="space-y-1 flex-1 w-full px-3 overflow-y-auto">
          <SidebarItem icon={LayoutDashboard} label="Dashboard" active={activeTab === 'Dashboard'} onClick={() => setActiveTab('Dashboard')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={Users} label="Users / Clients" active={activeTab === 'Users'} onClick={() => setActiveTab('Users')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={Layers} label="Orders (Active)" active={activeTab === 'Projects'} onClick={() => { setActiveTab('Projects'); setCurrentView('list'); }} collapsed={sidebarCollapsed} />
          <SidebarItem icon={FileText} label="Documents" active={activeTab === 'Documents'} onClick={() => setActiveTab('Documents')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={Receipt} label="Finance" active={activeTab === 'Finance'} onClick={() => setActiveTab('Finance')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={Settings} label="Settings" active={activeTab === 'Settings'} onClick={() => setActiveTab('Settings')} collapsed={sidebarCollapsed} />
        </div>
        <div className="p-4 border-t border-slate-100"><button onClick={handleLogout} className="flex items-center w-full p-2 rounded-lg text-rose-500 hover:bg-rose-50"><LogOut size={20} /><span className={`ml-3 text-sm transition-all duration-300 ${sidebarCollapsed ? 'opacity-0' : 'opacity-100'}`}>Logout</span></button></div>
      </aside >
      <main className="flex-1 flex flex-col h-full overflow-hidden relative">
        <header className="h-16 bg-white/80 backdrop-blur-md border-b border-slate-200 flex items-center justify-between px-8 sticky top-0 z-10">
          <h1 className="text-xl font-bold text-slate-800">{activeTab}</h1>
          <div className="flex items-center gap-4">
            <div className="w-8 h-8 rounded-full bg-indigo-100 text-indigo-700 flex items-center justify-center font-bold text-xs">{userInfo?.name?.charAt(0) || 'A'}</div>
          </div>
        </header>
        <div className="flex-1 overflow-y-auto p-8">
          {activeTab === 'Dashboard' && <DashboardView />}
          {activeTab === 'Projects' && currentView === 'list' && <ProjectListView />}
          {activeTab === 'Projects' && currentView === 'detail' && <ProjectDetailView project={selectedProject} onBack={() => setCurrentView('list')} />}
          {activeTab === 'Users' && (
            <div className="animate-in fade-in zoom-in duration-300">
              <div className="flex justify-between items-center mb-6">
                <div><h2 className="text-2xl font-bold text-slate-800">Users & Clients</h2><p className="text-slate-500">Manage all registered stakeholders.</p></div>
              </div>
              <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
                <table className="w-full text-left">
                  <thead className="bg-slate-50 border-b border-slate-200 text-xs font-bold text-slate-500 uppercase">
                    <tr><th className="px-6 py-4">Name</th><th className="px-6 py-4">Email</th><th className="px-6 py-4">Role</th><th className="px-6 py-4">Phone</th><th className="px-6 py-4">Joined</th><th className="px-6 py-4">Action</th></tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {users.map(user => (
                      <tr key={user._id} className="hover:bg-slate-50">
                        <td className="px-6 py-4 text-sm font-bold text-slate-700">{user.name}</td>
                        <td className="px-6 py-4 text-sm text-slate-600">{user.email}</td>
                        <td className="px-6 py-4"><span className={`px-2 py-1 rounded text-xs font-bold uppercase tracking-wider ${user.role === 'admin' ? 'bg-indigo-100 text-indigo-700' : user.role === 'employee' ? 'bg-amber-100 text-amber-700' : 'bg-green-100 text-green-700'}`}>{user.role}</span></td>
                        <td className="px-6 py-4 text-sm text-slate-500">{user.phone || 'N/A'}</td>
                        <td className="px-6 py-4 text-sm text-slate-500">{new Date(user.createdAt).toLocaleDateString()}</td>
                        <td className="px-6 py-4"><MoreVertical size={16} className="text-slate-400 cursor-pointer" /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          {activeTab === 'Documents' && <div className="p-8 text-center text-slate-500">Document Management View (Placeholder)</div>}
          {activeTab === 'Finance' && <div className="p-8 text-center text-slate-500">Finance & Revenue View (Placeholder)</div>}
          {activeTab === 'Settings' && <div className="p-8 text-center text-slate-500">Admin Settings View (Placeholder)</div>}
        </div >
      </main >
    </div >
  );
}

export default App;
