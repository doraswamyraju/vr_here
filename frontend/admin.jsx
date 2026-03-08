import React, { useEffect, useMemo, useState } from 'react';
import {
  LayoutDashboard,
  Users,
  Layers,
  FileText,
  CheckSquare,
  DollarSign,
  BarChart3,
  Bell,
  Settings,
  List,
  Kanban,
  LogOut,
  Building2,
  Sparkles,
  TrendingUp,
  Clock3,
  ChevronRight
} from 'lucide-react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import ServicesMasterView from './components/admin/ServicesMasterView';

const ORDER_STATUSES = ['Pending Documents', 'Documents Verified', 'Processing at Portal', 'Waiting for Clarification', 'Completed'];
const TASK_STATUSES = ['Pending', 'In Progress', 'Completed'];
const INVOICE_STATUSES = ['Draft', 'Sent', 'Paid', 'Overdue'];

const DUMMY_TODO = [
  { title: 'GSTR-3B filing review', assignee: 'Priya', due: 'Today', priority: 'High' },
  { title: 'Update startup agreement draft', assignee: 'Aman', due: 'Tomorrow', priority: 'Medium' },
  { title: 'Reconcile February invoices', assignee: 'Kiran', due: 'Mar 12', priority: 'Low' }
];

const DUMMY_FINANCE = [
  { id: 'INV-2026-101', client: 'Apex Foods', amount: 18000, status: 'Paid' },
  { id: 'INV-2026-102', client: 'Nova Tech', amount: 32000, status: 'Sent' },
  { id: 'INV-2026-103', client: 'Craftline LLP', amount: 14000, status: 'Overdue' }
];

const DUMMY_REPORTS = [
  { name: 'Monthly Collections', value: 'Rs. 4,82,000', trend: '+12%' },
  { name: 'Active Engagements', value: '58', trend: '+6%' },
  { name: 'Avg Delivery Time', value: '5.8 days', trend: '-9%' }
];

const DUMMY_NOTIFICATIONS = [
  '7 orders awaiting assignment',
  '4 clients uploaded new documents',
  '2 invoices are overdue by more than 10 days'
];

const StatusBadge = ({ status }) => {
  const styles = {
    'Pending Documents': 'bg-amber-100 text-amber-800',
    'Documents Verified': 'bg-blue-100 text-blue-800',
    'Processing at Portal': 'bg-indigo-100 text-indigo-800',
    'Waiting for Clarification': 'bg-purple-100 text-purple-800',
    Completed: 'bg-emerald-100 text-emerald-800',
    Pending: 'bg-amber-100 text-amber-800',
    'In Progress': 'bg-blue-100 text-blue-800',
    Draft: 'bg-slate-100 text-slate-700',
    Sent: 'bg-sky-100 text-sky-800',
    Paid: 'bg-emerald-100 text-emerald-800',
    Overdue: 'bg-rose-100 text-rose-800',
    Received: 'bg-blue-100 text-blue-800',
    Verified: 'bg-emerald-100 text-emerald-800'
  };

  return <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${styles[status] || 'bg-slate-100 text-slate-700'}`}>{status}</span>;
};

const GlassCard = ({ children, className = '' }) => (
  <div className={`rounded-2xl border border-white/70 bg-white/80 backdrop-blur-sm shadow-[0_10px_30px_rgba(15,23,42,0.08)] ${className}`}>
    {children}
  </div>
);

const DummyPanel = ({ title, subtitle, children }) => (
  <GlassCard className="p-6">
    <h3 className="text-lg font-bold text-slate-900">{title}</h3>
    <p className="text-sm text-slate-500 mt-1">{subtitle}</p>
    <div className="mt-5">{children}</div>
  </GlassCard>
);

function AdminApp() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('Dashboard');
  const [ordersViewMode, setOrdersViewMode] = useState('list');
  const [selectedOrderId, setSelectedOrderId] = useState(null);
  const [orderDetailTab, setOrderDetailTab] = useState('Overview');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [userInfo, setUserInfo] = useState(null);
  const [orders, setOrders] = useState([]);
  const [employees, setEmployees] = useState([]);
  const [users, setUsers] = useState([]);
  const [taskImportText, setTaskImportText] = useState('');
  const [requirementsImportText, setRequirementsImportText] = useState('');
  const [timeLogDrafts, setTimeLogDrafts] = useState({});
  const [invoiceForm, setInvoiceForm] = useState({ invoiceNumber: '', amount: '', status: 'Draft', dueDate: '', notes: '' });

  useEffect(() => {
    const user = localStorage.getItem('userInfo');
    if (!user) return navigate('/');
    const parsed = JSON.parse(user);
    if (parsed.role !== 'admin') {
      alert('Access Denied. Admin only.');
      return navigate('/');
    }
    setUserInfo(parsed);
    setIsLoggedIn(true);
  }, [navigate]);

  const config = useMemo(() => (
    userInfo?.token ? { headers: { Authorization: `Bearer ${userInfo.token}` } } : null
  ), [userInfo]);

  const fetchData = async () => {
    if (!config) return;
    try {
      const [ordersRes, employeesRes, usersRes] = await Promise.all([
        axios.get('/api/orders', config),
        axios.get('/api/auth/employees', config),
        axios.get('/api/auth/users', config)
      ]);
      setOrders(ordersRes.data || []);
      setEmployees(employeesRes.data || []);
      setUsers(usersRes.data || []);
    } catch (error) {
      console.error('Failed to fetch admin data', error);
    }
  };

  useEffect(() => {
    fetchData();
  }, [config]);

  const selectedOrder = useMemo(() => orders.find((o) => o._id === selectedOrderId) || null, [orders, selectedOrderId]);

  const handleLogout = () => {
    localStorage.removeItem('userInfo');
    navigate('/login');
  };

  const assignOrder = async (orderId, employeeId) => {
    await axios.put(`/api/orders/${orderId}/assign`, { employeeId: employeeId || null }, config);
    fetchData();
  };

  const updateOrderStatus = async (orderId, status) => {
    await axios.put(`/api/orders/${orderId}/status`, { status }, config);
    fetchData();
  };

  const importTasks = async () => {
    if (!selectedOrder || !taskImportText.trim()) return;
    await axios.post(`/api/orders/${selectedOrder._id}/tasks/import`, { tasksText: taskImportText }, config);
    setTaskImportText('');
    fetchData();
  };

  const importRequirements = async () => {
    if (!selectedOrder || !requirementsImportText.trim()) return;
    await axios.post(`/api/orders/${selectedOrder._id}/requirements/import`, { requirementsText: requirementsImportText }, config);
    setRequirementsImportText('');
    fetchData();
  };

  const assignTask = async (taskId, employeeId) => {
    if (!selectedOrder) return;
    await axios.put(`/api/orders/${selectedOrder._id}/tasks/${taskId}/assign`, { employeeId: employeeId || null }, config);
    fetchData();
  };

  const updateTaskStatus = async (taskId, status) => {
    if (!selectedOrder) return;
    await axios.put(`/api/orders/${selectedOrder._id}/tasks/${taskId}`, { status }, config);
    fetchData();
  };

  const addTimeLog = async (taskId) => {
    const draft = timeLogDrafts[taskId] || {};
    const minutes = Number(draft.minutes);
    if (!minutes || minutes <= 0) return alert('Enter valid minutes for time tracking.');
    await axios.post(`/api/orders/${selectedOrder._id}/tasks/${taskId}/time-log`, { minutes, notes: draft.notes || '' }, config);
    setTimeLogDrafts((prev) => ({ ...prev, [taskId]: { minutes: '', notes: '' } }));
    fetchData();
  };

  const addInvoice = async () => {
    if (!selectedOrder || !invoiceForm.invoiceNumber || !invoiceForm.amount) return alert('Invoice number and amount are required.');
    await axios.post(`/api/orders/${selectedOrder._id}/invoices`, {
      invoiceNumber: invoiceForm.invoiceNumber,
      amount: Number(invoiceForm.amount),
      status: invoiceForm.status,
      dueDate: invoiceForm.dueDate || null,
      notes: invoiceForm.notes
    }, config);
    setInvoiceForm({ invoiceNumber: '', amount: '', status: 'Draft', dueDate: '', notes: '' });
    fetchData();
  };

  const updateInvoiceStatus = async (invoiceId, status) => {
    await axios.put(`/api/orders/${selectedOrder._id}/invoices/${invoiceId}/status`, { status }, config);
    fetchData();
  };

  if (!isLoggedIn) return <div className="min-h-screen flex items-center justify-center bg-slate-900 text-white font-semibold">Verifying Access...</div>;

  const totalRevenue = orders.reduce((sum, order) => sum + Number(order.price || 0), 0);
  const pendingOrders = orders.filter((o) => o.status !== 'Completed').length;
  const completedOrders = orders.filter((o) => o.status === 'Completed').length;

  const DashboardView = () => (
    <div className="space-y-6">
      <div className="rounded-3xl p-6 md:p-8 bg-gradient-to-r from-slate-900 via-blue-900 to-indigo-900 text-white relative overflow-hidden">
        <div className="absolute -right-10 -top-10 w-48 h-48 rounded-full bg-cyan-400/20 blur-2xl" />
        <div className="absolute right-32 -bottom-14 w-56 h-56 rounded-full bg-fuchsia-400/20 blur-2xl" />
        <div className="relative z-10 flex flex-wrap items-center justify-between gap-6">
          <div>
            <p className="text-cyan-200 text-sm">Admin Control Center</p>
            <h2 className="text-2xl md:text-4xl font-black mt-1">Operations Pulse</h2>
            <p className="mt-2 text-slate-200 max-w-xl">Track assignments, revenue, delivery speed, and team workload from one live workspace.</p>
          </div>
          <div className="rounded-xl border border-white/20 bg-white/10 px-4 py-3">
            <p className="text-xs text-cyan-100">Today Momentum</p>
            <p className="text-2xl font-bold mt-1 flex items-center gap-1"><TrendingUp size={18} /> +14%</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        {[
          { label: 'Total Orders', value: orders.length, accent: 'from-indigo-500 to-blue-500' },
          { label: 'Pending Orders', value: pendingOrders, accent: 'from-amber-500 to-orange-500' },
          { label: 'Completed Orders', value: completedOrders, accent: 'from-emerald-500 to-teal-500' },
          { label: 'Order Value', value: `Rs. ${totalRevenue.toLocaleString()}`, accent: 'from-pink-500 to-rose-500' }
        ].map((card) => (
          <GlassCard key={card.label} className="p-5 transition-all duration-300 hover:-translate-y-1 hover:shadow-2xl">
            <div className={`h-1.5 w-full rounded-full bg-gradient-to-r ${card.accent}`} />
            <p className="text-xs text-slate-500 mt-3">{card.label}</p>
            <p className="text-2xl font-extrabold text-slate-900 mt-1">{card.value}</p>
          </GlassCard>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <DummyPanel title="Team Queue" subtitle="Dummy data - quick workload scan">
          <div className="space-y-3">
            {DUMMY_TODO.map((item) => (
              <div key={item.title} className="rounded-xl border border-slate-200 bg-white p-3 hover:border-indigo-300 transition">
                <div className="flex justify-between items-center">
                  <p className="font-semibold text-slate-800 text-sm">{item.title}</p>
                  <span className="text-xs px-2 py-1 rounded-md bg-slate-100">{item.priority}</span>
                </div>
                <p className="text-xs text-slate-500 mt-1">Assignee: {item.assignee} | Due: {item.due}</p>
              </div>
            ))}
          </div>
        </DummyPanel>

        <DummyPanel title="Alerts" subtitle="Dummy data - notification feed">
          <div className="space-y-2">
            {DUMMY_NOTIFICATIONS.map((text) => (
              <div key={text} className="flex items-start gap-2 rounded-lg bg-slate-50 border border-slate-200 p-3">
                <Bell size={14} className="text-indigo-600 mt-0.5" />
                <p className="text-sm text-slate-700">{text}</p>
              </div>
            ))}
          </div>
        </DummyPanel>

        <DummyPanel title="Performance" subtitle="Dummy data - key business indicators">
          <div className="space-y-3">
            {DUMMY_REPORTS.map((row) => (
              <div key={row.name} className="rounded-lg border border-slate-200 p-3 bg-white">
                <p className="text-xs text-slate-500">{row.name}</p>
                <div className="flex justify-between items-center mt-1">
                  <p className="font-bold text-slate-900">{row.value}</p>
                  <span className="text-xs text-emerald-600 font-semibold">{row.trend}</span>
                </div>
              </div>
            ))}
          </div>
        </DummyPanel>
      </div>
    </div>
  );

  const OrdersListView = () => (
    <GlassCard className="overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-slate-900 text-slate-200 text-xs uppercase">
          <tr>
            <th className="text-left px-5 py-3">Order</th>
            <th className="text-left px-5 py-3">Client</th>
            <th className="text-left px-5 py-3">Assigned Staff</th>
            <th className="text-left px-5 py-3">Status</th>
            <th className="text-left px-5 py-3">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {orders.map((order) => (
            <tr key={order._id} className="hover:bg-indigo-50/50 transition">
              <td className="px-5 py-3"><p className="font-semibold text-slate-800">{order.serviceName}</p><p className="text-xs text-slate-500">{order.packageName}</p></td>
              <td className="px-5 py-3">{order.user?.name || 'Unknown'}</td>
              <td className="px-5 py-3">{order.assignedEmployee?.name || 'Unassigned'}</td>
              <td className="px-5 py-3"><StatusBadge status={order.status} /></td>
              <td className="px-5 py-3">
                <button
                  onClick={() => { setSelectedOrderId(order._id); setOrderDetailTab('Overview'); }}
                  className="px-3 py-1.5 rounded-lg bg-slate-900 text-white text-xs font-semibold hover:bg-indigo-700 transition"
                >
                  Open
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </GlassCard>
  );

  const OrdersBoardView = () => (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {orders.map((order) => (
        <GlassCard key={order._id} className="p-4 hover:-translate-y-1 transition-all duration-300">
          <div className="flex items-start justify-between mb-2">
            <h3 className="font-semibold text-slate-800">{order.serviceName}</h3>
            <StatusBadge status={order.status} />
          </div>
          <p className="text-sm text-slate-600">Client: {order.user?.name || 'Unknown'}</p>
          <p className="text-sm text-slate-600">Staff: {order.assignedEmployee?.name || 'Unassigned'}</p>
          <button
            onClick={() => { setSelectedOrderId(order._id); setOrderDetailTab('Overview'); }}
            className="mt-3 px-3 py-1.5 rounded-lg bg-indigo-600 text-white text-xs font-semibold hover:bg-indigo-700 transition"
          >
            Open
          </button>
        </GlassCard>
      ))}
    </div>
  );

  const OrdersDetailView = () => (
    <div className="space-y-4">
      <GlassCard className="p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-xl font-bold text-slate-800">{selectedOrder.serviceName}</h2>
            <p className="text-sm text-slate-500 flex items-center gap-2 mt-1"><Building2 size={14} /> {selectedOrder.user?.name || 'Unknown'} <span className="text-slate-300">|</span> <DollarSign size={14} /> Rs. {Number(selectedOrder.price || 0).toLocaleString()}</p>
          </div>
          <button onClick={() => setSelectedOrderId(null)} className="px-3 py-2 rounded-lg bg-slate-100 text-slate-700 text-sm font-medium hover:bg-slate-200">Back to Orders</button>
        </div>

        <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="text-xs text-slate-500">Order Status</label>
            <select value={selectedOrder.status} onChange={(e) => updateOrderStatus(selectedOrder._id, e.target.value)} className="w-full mt-1 p-2.5 border rounded-lg border-slate-300 bg-white">
              {ORDER_STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs text-slate-500">Assign Order Owner</label>
            <select value={selectedOrder.assignedEmployee?._id || ''} onChange={(e) => assignOrder(selectedOrder._id, e.target.value)} className="w-full mt-1 p-2.5 border rounded-lg border-slate-300 bg-white">
              <option value="">Unassigned</option>
              {employees.map((employee) => <option key={employee._id} value={employee._id}>{employee.name}</option>)}
            </select>
          </div>
          <div className="rounded-lg border border-slate-200 p-3 bg-slate-50 text-sm"><p className="text-slate-500">Created</p><p className="font-medium text-slate-700">{new Date(selectedOrder.createdAt).toLocaleDateString()}</p></div>
        </div>
      </GlassCard>

      <GlassCard>
        <div className="px-4 border-b border-slate-100 flex flex-wrap gap-2">
          {['Overview', 'Tasks', 'Requirements', 'Time Logs', 'Invoices'].map((tab) => (
            <button key={tab} onClick={() => setOrderDetailTab(tab)} className={`px-4 py-3 text-sm font-medium border-b-2 transition ${orderDetailTab === tab ? 'border-indigo-600 text-indigo-700' : 'border-transparent text-slate-500 hover:text-indigo-600'}`}>{tab}</button>
          ))}
        </div>

        <div className="p-5">
          {orderDetailTab === 'Overview' && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <GlassCard className="p-4"><p className="text-xs text-slate-500 mb-1">Total Tasks</p><p className="text-2xl font-semibold">{selectedOrder.tasks?.length || 0}</p></GlassCard>
              <GlassCard className="p-4"><p className="text-xs text-slate-500 mb-1">Requirements</p><p className="text-2xl font-semibold">{selectedOrder.customerRequirements?.length || 0}</p></GlassCard>
              <GlassCard className="p-4"><p className="text-xs text-slate-500 mb-1">Invoices Raised</p><p className="text-2xl font-semibold">{selectedOrder.invoices?.length || 0}</p></GlassCard>
            </div>
          )}

          {orderDetailTab === 'Tasks' && (
            <div className="space-y-4">
              <div className="rounded-xl border border-slate-200 p-4 bg-slate-50">
                <p className="font-semibold text-slate-700 mb-1">Import Tasks & Subtasks</p>
                <p className="text-xs text-slate-500 mb-3">Format: Task Title &gt; Subtask 1 | Subtask 2 (one task per line)</p>
                <textarea value={taskImportText} onChange={(e) => setTaskImportText(e.target.value)} rows={4} className="w-full p-3 border border-slate-300 rounded-lg text-sm" placeholder={'Collect Documents > PAN | Aadhaar\nFile Form > Validate details | Submit'} />
                <button onClick={importTasks} className="mt-3 px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-semibold hover:bg-indigo-700">Import Tasks</button>
              </div>

              <table className="w-full text-sm border border-slate-200 rounded-xl overflow-hidden">
                <thead className="bg-slate-50 text-xs uppercase text-slate-500">
                  <tr><th className="text-left px-4 py-3">Task</th><th className="text-left px-4 py-3">Subtasks</th><th className="text-left px-4 py-3">Assigned Staff</th><th className="text-left px-4 py-3">Status</th></tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {(selectedOrder.tasks || []).map((task) => (
                    <tr key={task._id}>
                      <td className="px-4 py-3 font-medium text-slate-700">{task.title}</td>
                      <td className="px-4 py-3">{(task.subtasks || []).length ? <div className="flex flex-wrap gap-1">{task.subtasks.map((subtask, idx) => <span key={`${task._id}-${idx}`} className="text-xs px-2 py-1 bg-slate-100 rounded-md text-slate-600">{subtask.title}</span>)}</div> : <span className="text-xs text-slate-400">No subtasks</span>}</td>
                      <td className="px-4 py-3">
                        <select value={task.assignedTo?._id || task.assignedTo || ''} onChange={(e) => assignTask(task._id, e.target.value)} className="w-full p-2 border rounded-lg border-slate-300 bg-white">
                          <option value="">Unassigned</option>
                          {employees.map((employee) => <option key={employee._id} value={employee._id}>{employee.name}</option>)}
                        </select>
                      </td>
                      <td className="px-4 py-3">
                        <select value={task.status} onChange={(e) => updateTaskStatus(task._id, e.target.value)} className="w-full p-2 border rounded-lg border-slate-300 bg-white">
                          {TASK_STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}
                        </select>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {orderDetailTab === 'Requirements' && (
            <div className="space-y-4">
              <div className="rounded-xl border border-slate-200 p-4 bg-slate-50">
                <p className="font-semibold text-slate-700 mb-1">Import Required Details & Documents</p>
                <p className="text-xs text-slate-500 mb-3">Format: Document: PAN Card | Upload clear copy, Detail: Business Address | Full registered address</p>
                <textarea value={requirementsImportText} onChange={(e) => setRequirementsImportText(e.target.value)} rows={4} className="w-full p-3 border border-slate-300 rounded-lg text-sm" placeholder={'Document: PAN Card | Upload clear copy\nDetail: Registered Address | Full address with pincode'} />
                <button onClick={importRequirements} className="mt-3 px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-semibold hover:bg-indigo-700">Import Requirements</button>
              </div>
              <div className="space-y-2">
                {(selectedOrder.customerRequirements || []).map((item) => (
                  <div key={item._id} className="rounded-lg border border-slate-200 p-3 flex flex-wrap gap-2 items-center justify-between">
                    <div><p className="font-medium text-slate-800">{item.title}</p><p className="text-xs text-slate-500">{item.type} {item.description ? `- ${item.description}` : ''}</p></div>
                    <StatusBadge status={item.status} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {orderDetailTab === 'Time Logs' && (
            <div className="space-y-4">
              {(selectedOrder.tasks || []).map((task) => (
                <div key={task._id} className="rounded-xl border border-slate-200 p-4">
                  <div className="flex items-center justify-between gap-2">
                    <div><p className="font-semibold text-slate-800">{task.title}</p><p className="text-xs text-slate-500">Assigned: {task.assignedTo?.name || 'Unassigned'}</p></div>
                    <span className="text-sm font-semibold text-indigo-700">Total: {task.totalMinutes || 0} min</span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2 mt-3">
                    <input type="number" min="1" placeholder="Minutes" value={timeLogDrafts[task._id]?.minutes || ''} onChange={(e) => setTimeLogDrafts((prev) => ({ ...prev, [task._id]: { ...(prev[task._id] || {}), minutes: e.target.value } }))} className="p-2.5 border border-slate-300 rounded-lg text-sm" />
                    <input placeholder="Work note" value={timeLogDrafts[task._id]?.notes || ''} onChange={(e) => setTimeLogDrafts((prev) => ({ ...prev, [task._id]: { ...(prev[task._id] || {}), notes: e.target.value } }))} className="p-2.5 border border-slate-300 rounded-lg text-sm md:col-span-2" />
                  </div>
                  <button onClick={() => addTimeLog(task._id)} className="mt-2 px-3 py-1.5 rounded-lg bg-indigo-600 text-white text-xs font-semibold hover:bg-indigo-700">Log Time</button>
                  <div className="mt-3 space-y-2">
                    {(task.timeLogs || []).map((log, idx) => <div key={`${task._id}-${idx}`} className="text-xs rounded-lg bg-slate-50 border border-slate-200 px-3 py-2 flex justify-between gap-2"><span>{log.employee?.name || 'Staff'} - {log.minutes} min {log.notes ? `(${log.notes})` : ''}</span><span className="text-slate-500">{new Date(log.loggedAt).toLocaleDateString()}</span></div>)}
                    {(task.timeLogs || []).length === 0 && <p className="text-xs text-slate-500">No time logs yet.</p>}
                  </div>
                </div>
              ))}
            </div>
          )}

          {orderDetailTab === 'Invoices' && (
            <div className="space-y-4">
              <div className="rounded-xl border border-slate-200 p-4 bg-slate-50">
                <p className="font-semibold text-slate-700 mb-3">Raise New Invoice</p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <input value={invoiceForm.invoiceNumber} onChange={(e) => setInvoiceForm((prev) => ({ ...prev, invoiceNumber: e.target.value }))} placeholder="Invoice Number" className="p-2.5 border border-slate-300 rounded-lg text-sm" />
                  <input type="number" min="1" value={invoiceForm.amount} onChange={(e) => setInvoiceForm((prev) => ({ ...prev, amount: e.target.value }))} placeholder="Amount" className="p-2.5 border border-slate-300 rounded-lg text-sm" />
                  <select value={invoiceForm.status} onChange={(e) => setInvoiceForm((prev) => ({ ...prev, status: e.target.value }))} className="p-2.5 border border-slate-300 rounded-lg text-sm">{INVOICE_STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}</select>
                  <input type="date" value={invoiceForm.dueDate} onChange={(e) => setInvoiceForm((prev) => ({ ...prev, dueDate: e.target.value }))} className="p-2.5 border border-slate-300 rounded-lg text-sm" />
                  <input value={invoiceForm.notes} onChange={(e) => setInvoiceForm((prev) => ({ ...prev, notes: e.target.value }))} placeholder="Notes" className="p-2.5 border border-slate-300 rounded-lg text-sm md:col-span-2" />
                </div>
                <button onClick={addInvoice} className="mt-3 px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-semibold hover:bg-indigo-700">Add Invoice</button>
              </div>

              <table className="w-full text-sm border border-slate-200 rounded-xl overflow-hidden">
                <thead className="bg-slate-50 text-xs uppercase text-slate-500">
                  <tr><th className="text-left px-4 py-3">Invoice</th><th className="text-left px-4 py-3">Amount</th><th className="text-left px-4 py-3">Created</th><th className="text-left px-4 py-3">Status</th></tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {(selectedOrder.invoices || []).map((invoice) => (
                    <tr key={invoice._id}>
                      <td className="px-4 py-3 font-medium">{invoice.invoiceNumber}</td>
                      <td className="px-4 py-3">Rs. {Number(invoice.amount || 0).toLocaleString()}</td>
                      <td className="px-4 py-3">{invoice.createdAt ? new Date(invoice.createdAt).toLocaleDateString() : '-'}</td>
                      <td className="px-4 py-3">
                        <select value={invoice.status} onChange={(e) => updateInvoiceStatus(invoice._id, e.target.value)} className="p-2 border rounded-lg border-slate-300">
                          {INVOICE_STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}
                        </select>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </GlassCard>
    </div>
  );

  const OrdersView = () => (
    <div className="space-y-4">
      {!selectedOrder && (
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold text-slate-800">Orders</h2>
            <p className="text-sm text-slate-500">List view is enabled by default.</p>
          </div>
          <div className="inline-flex rounded-lg border border-slate-200 bg-white overflow-hidden">
            <button onClick={() => setOrdersViewMode('list')} className={`px-3 py-2 text-sm flex items-center gap-1 ${ordersViewMode === 'list' ? 'bg-indigo-50 text-indigo-700' : 'text-slate-600'}`}><List size={14} /> List</button>
            <button onClick={() => setOrdersViewMode('board')} className={`px-3 py-2 text-sm flex items-center gap-1 ${ordersViewMode === 'board' ? 'bg-indigo-50 text-indigo-700' : 'text-slate-600'}`}><Kanban size={14} /> Board</button>
          </div>
        </div>
      )}
      {!selectedOrder && ordersViewMode === 'list' && <OrdersListView />}
      {!selectedOrder && ordersViewMode === 'board' && <OrdersBoardView />}
      {selectedOrder && <OrdersDetailView />}
    </div>
  );

  const UsersView = () => (
    <GlassCard className="overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-slate-900 text-slate-200 text-xs uppercase">
          <tr><th className="text-left px-5 py-3">Name</th><th className="text-left px-5 py-3">Email</th><th className="text-left px-5 py-3">Role</th></tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {users.map((user) => <tr key={user._id}><td className="px-5 py-3 font-medium">{user.name}</td><td className="px-5 py-3">{user.email}</td><td className="px-5 py-3 capitalize">{user.role}</td></tr>)}
        </tbody>
      </table>
    </GlassCard>
  );

  const ToDoView = () => (
    <DummyPanel title="To Do Board" subtitle="Dummy data; to be connected to live workflow module">
      <div className="space-y-3">
        {DUMMY_TODO.map((item) => (
          <div key={item.title} className="rounded-xl border border-slate-200 bg-white p-4 flex items-center justify-between">
            <div>
              <p className="font-semibold text-slate-800">{item.title}</p>
              <p className="text-xs text-slate-500">Assignee: {item.assignee} | Due: {item.due}</p>
            </div>
            <span className="text-xs px-2 py-1 rounded-md bg-indigo-100 text-indigo-700">{item.priority}</span>
          </div>
        ))}
      </div>
    </DummyPanel>
  );

  const FinanceView = () => (
    <DummyPanel title="Finance Snapshot" subtitle="Dummy billing records">
      <div className="space-y-2">
        {DUMMY_FINANCE.map((row) => (
          <div key={row.id} className="rounded-lg border border-slate-200 p-3 bg-white flex justify-between items-center">
            <div>
              <p className="font-semibold text-slate-800">{row.id}</p>
              <p className="text-xs text-slate-500">{row.client}</p>
            </div>
            <div className="text-right">
              <p className="text-sm font-semibold text-slate-900">Rs. {row.amount.toLocaleString()}</p>
              <StatusBadge status={row.status} />
            </div>
          </div>
        ))}
      </div>
    </DummyPanel>
  );

  const ReportsView = () => (
    <DummyPanel title="Reports Hub" subtitle="Dummy summary cards">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {DUMMY_REPORTS.map((row) => (
          <div key={row.name} className="rounded-xl border border-slate-200 bg-white p-4">
            <p className="text-xs text-slate-500">{row.name}</p>
            <p className="text-lg font-bold mt-1">{row.value}</p>
            <p className="text-xs text-emerald-600 mt-1">{row.trend}</p>
          </div>
        ))}
      </div>
    </DummyPanel>
  );

  const NotificationsView = () => (
    <DummyPanel title="Notification Center" subtitle="Dummy feed; connect to real events later">
      <div className="space-y-2">
        {DUMMY_NOTIFICATIONS.map((text) => (
          <div key={text} className="rounded-lg border border-slate-200 bg-white p-3 flex items-center justify-between">
            <span className="text-sm text-slate-700">{text}</span>
            <ChevronRight size={15} className="text-slate-400" />
          </div>
        ))}
      </div>
    </DummyPanel>
  );

  const SettingsView = () => (
    <DummyPanel title="Settings" subtitle="Dummy controls for UI completeness">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {['Email Alerts', 'Auto Assignment', 'Invoice Reminders', 'Escalation Policy'].map((label) => (
          <div key={label} className="rounded-lg border border-slate-200 bg-white p-4 flex items-center justify-between">
            <p className="text-sm font-medium text-slate-700">{label}</p>
            <span className="text-xs px-2 py-1 rounded-md bg-emerald-100 text-emerald-700">Enabled</span>
          </div>
        ))}
      </div>
    </DummyPanel>
  );

  const sidebarItems = [
    { key: 'Dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { key: 'Orders', label: 'Orders', icon: Layers },
    { key: 'Users', label: 'Users', icon: Users },
    { key: 'ToDo', label: 'To Do', icon: CheckSquare },
    { key: 'Finance', label: 'Finance', icon: DollarSign },
    { key: 'Reports', label: 'Reports', icon: BarChart3 },
    { key: 'Notifications', label: 'Notifications', icon: Bell },
    { key: 'Services', label: 'Services Master', icon: FileText },
    { key: 'Settings', label: 'Settings', icon: Settings }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-100 via-blue-50 to-indigo-100 text-slate-800">
      <div className="flex h-screen">
        <aside className="w-72 border-r border-slate-200/70 bg-white/70 backdrop-blur-md flex flex-col">
          <div className="h-20 px-5 flex items-center justify-between border-b border-slate-200/70">
            <div>
              <p className="text-xs uppercase tracking-widest text-indigo-500 font-bold">VR Here</p>
              <p className="text-xl font-black text-slate-900">Admin Studio</p>
            </div>
            <Sparkles size={18} className="text-indigo-600" />
          </div>

          <div className="p-3 space-y-1 flex-1 overflow-y-auto">
            {sidebarItems.map((item) => {
              const Icon = item.icon;
              const active = activeTab === item.key;
              return (
                <button
                  key={item.key}
                  onClick={() => {
                    setActiveTab(item.key);
                    if (item.key !== 'Orders') setSelectedOrderId(null);
                  }}
                  className={`w-full px-3.5 py-2.5 rounded-xl text-sm font-medium flex items-center gap-2 transition ${active ? 'bg-gradient-to-r from-indigo-600 to-blue-600 text-white shadow-lg' : 'text-slate-700 hover:bg-indigo-50'}`}
                >
                  <Icon size={16} /> {item.label}
                </button>
              );
            })}
          </div>

          <div className="p-3 border-t border-slate-200/70">
            <button onClick={handleLogout} className="w-full px-3 py-2.5 rounded-lg text-sm font-medium flex items-center gap-2 text-rose-600 hover:bg-rose-50"><LogOut size={16} /> Logout</button>
          </div>
        </aside>

        <main className="flex-1 flex flex-col overflow-hidden">
          <header className="h-20 px-6 flex items-center justify-between border-b border-slate-200/70 bg-white/60 backdrop-blur-md">
            <div>
              <p className="text-xs text-slate-500">VR Here Admin Panel</p>
              <h1 className="font-bold text-2xl text-slate-900">{activeTab}</h1>
            </div>
            <div className="flex items-center gap-3">
              <div className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs text-slate-600 flex items-center gap-1"><Clock3 size={14} /> Live</div>
              <div className="w-10 h-10 rounded-full bg-gradient-to-br from-indigo-600 to-blue-500 text-white flex items-center justify-center text-xs font-semibold">{userInfo?.name?.charAt(0) || 'A'}</div>
            </div>
          </header>

          <div className="flex-1 overflow-y-auto p-6">
            {activeTab === 'Dashboard' && <DashboardView />}
            {activeTab === 'Orders' && <OrdersView />}
            {activeTab === 'Users' && <UsersView />}
            {activeTab === 'ToDo' && <ToDoView />}
            {activeTab === 'Finance' && <FinanceView />}
            {activeTab === 'Reports' && <ReportsView />}
            {activeTab === 'Notifications' && <NotificationsView />}
            {activeTab === 'Services' && <ServicesMasterView token={userInfo?.token} />}
            {activeTab === 'Settings' && <SettingsView />}
          </div>
        </main>
      </div>
    </div>
  );
}

export default AdminApp;
