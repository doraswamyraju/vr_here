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
  TrendingUp,
  Clock3,
  ChevronRight,
  Menu,
  X,
  Briefcase,
  BookOpen,
  MessageSquare
} from 'lucide-react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import ServicesMasterView from './components/admin/ServicesMasterView';

const ORDER_STATUSES = ['Pending Documents', 'Documents Verified', 'Processing at Portal', 'Waiting for Clarification', 'Completed'];
const TASK_STATUSES = ['Pending', 'In Progress', 'Completed'];
const INVOICE_STATUSES = ['Draft', 'Sent', 'Paid', 'Overdue'];
const PACKAGE_OPTIONS = ['Basic Package', 'Standard Package', 'Premium Package'];

const getOrderClientLabel = (order) => order?.user?.name || order?.clientName || order?.email || order?.phone || 'Guest';

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
    Overdue: 'bg-rose-100 text-rose-800'
  };
  return <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${styles[status] || 'bg-slate-100 text-slate-700'}`}>{status}</span>;
};

const Card = ({ children, className = '' }) => <div className={`rounded-2xl border border-white/70 bg-white/85 backdrop-blur-sm shadow-[0_10px_30px_rgba(15,23,42,0.08)] ${className}`}>{children}</div>;

function AdminApp() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('Dashboard');
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [sidebarExpanded, setSidebarExpanded] = useState(false);
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
  const [quickRequirementText, setQuickRequirementText] = useState('');
  const [timeLogDrafts, setTimeLogDrafts] = useState({});
  const [invoiceForm, setInvoiceForm] = useState({ invoiceNumber: '', amount: '', status: 'Draft', dueDate: '', notes: '' });
  const [commercialDraft, setCommercialDraft] = useState({ packageName: '', price: '' });

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

  const config = useMemo(() => (userInfo?.token ? { headers: { Authorization: `Bearer ${userInfo.token}` } } : null), [userInfo]);

  const fetchData = async () => {
    if (!config) return;
    const [ordersRes, employeesRes, usersRes] = await Promise.all([
      axios.get('/api/orders', config),
      axios.get('/api/auth/employees', config),
      axios.get('/api/auth/users', config)
    ]);
    setOrders(ordersRes.data || []);
    setEmployees(employeesRes.data || []);
    setUsers(usersRes.data || []);
  };

  useEffect(() => {
    fetchData().catch((e) => console.error(e));
  }, [config]);

  const selectedOrder = useMemo(() => orders.find((o) => o._id === selectedOrderId) || null, [orders, selectedOrderId]);

  useEffect(() => {
    if (selectedOrder) {
      setCommercialDraft({ packageName: selectedOrder.packageName || '', price: String(selectedOrder.price || '') });
    }
  }, [selectedOrder]);

  const isConsultationOrder = (order) => {
    if (!order) return false;
    const pkg = (order.packageName || '').toLowerCase();
    return pkg.includes('consultation') || Number(order.price) === 499;
  };

  const handleLogout = () => {
    localStorage.removeItem('userInfo');
    navigate('/login');
  };

  const updateOrderStatus = async (orderId, status) => {
    await axios.put(`/api/orders/${orderId}/status`, { status }, config);
    fetchData();
  };

  const assignOrder = async (orderId, employeeId) => {
    await axios.put(`/api/orders/${orderId}/assign`, { employeeId: employeeId || null }, config);
    fetchData();
  };

  const saveCommercials = async () => {
    if (!selectedOrder) return;
    await axios.put(`/api/orders/${selectedOrder._id}/commercials`, {
      packageName: commercialDraft.packageName,
      price: Number(commercialDraft.price || 0)
    }, config);
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

  const raiseAdditionalRequirement = async () => {
    if (!selectedOrder || !quickRequirementText.trim()) return;
    await axios.post(`/api/orders/${selectedOrder._id}/requirements/import`, { requirementsText: `Detail: ${quickRequirementText}` }, config);
    setQuickRequirementText('');
    fetchData();
  };

  const addInvoice = async () => {
    if (!selectedOrder || !invoiceForm.invoiceNumber || !invoiceForm.amount) return;
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

  const updateTaskStatus = async (taskId, status) => {
    await axios.put(`/api/orders/${selectedOrder._id}/tasks/${taskId}`, { status }, config);
    fetchData();
  };

  const addTimeLog = async (taskId) => {
    const draft = timeLogDrafts[taskId] || {};
    const minutes = Number(draft.minutes);
    if (!minutes || minutes <= 0) return;
    await axios.post(`/api/orders/${selectedOrder._id}/tasks/${taskId}/time-log`, { minutes, notes: draft.notes || '' }, config);
    setTimeLogDrafts((prev) => ({ ...prev, [taskId]: { minutes: '', notes: '' } }));
    fetchData();
  };

  const DashboardView = () => (
    <div className="space-y-6">
      <Card className="p-6 bg-gradient-to-r from-slate-900 via-blue-900 to-indigo-900 text-white">
        <p className="text-cyan-200 text-sm">Admin Command Center</p>
        <h2 className="text-3xl font-black mt-1">Operations Pulse</h2>
        <p className="text-slate-200 mt-2">Service delivery, consultation conversion, and execution status in one place.</p>
      </Card>
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {[{ l: 'Total Orders', v: orders.length }, { l: 'Pending', v: orders.filter(o => o.status !== 'Completed').length }, { l: 'Completed', v: orders.filter(o => o.status === 'Completed').length }, { l: 'Order Value', v: `Rs. ${orders.reduce((s, o) => s + Number(o.price || 0), 0).toLocaleString()}` }].map((x) => <Card key={x.l} className="p-4"><p className="text-xs text-slate-500">{x.l}</p><p className="text-2xl font-bold mt-1">{x.v}</p></Card>)}
      </div>
    </div>
  );

  const OrdersListView = () => (
    <Card className="overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm min-w-[760px]">
          <thead className="bg-slate-900 text-slate-200 text-xs uppercase">
            <tr><th className="text-left px-5 py-3">Order</th><th className="text-left px-5 py-3">Client</th><th className="text-left px-5 py-3">Assigned</th><th className="text-left px-5 py-3">Status</th><th className="text-left px-5 py-3">Amount</th></tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {orders.map((order) => (
              <tr key={order._id} onClick={() => { setSelectedOrderId(order._id); setOrderDetailTab('Overview'); }} className="cursor-pointer hover:bg-indigo-50 transition">
                <td className="px-5 py-3"><p className="font-semibold text-slate-800">{order.serviceName}</p><p className="text-xs text-slate-500">{order.packageName}</p></td>
                <td className="px-5 py-3">{getOrderClientLabel(order)}</td>
                <td className="px-5 py-3">{order.assignedEmployee?.name || 'Unassigned'}</td>
                <td className="px-5 py-3"><StatusBadge status={order.status} /></td>
                <td className="px-5 py-3 font-semibold">Rs. {Number(order.price || 0).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );

  const OrdersBoardView = () => (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
      {orders.map((order) => (
        <Card key={order._id} className="p-4 cursor-pointer hover:-translate-y-1 transition-all" onClick={() => { setSelectedOrderId(order._id); setOrderDetailTab('Overview'); }}>
          <div className="flex justify-between items-start"><h3 className="font-semibold">{order.serviceName}</h3><StatusBadge status={order.status} /></div>
          <p className="text-sm text-slate-600 mt-2">{getOrderClientLabel(order)}</p>
          <p className="text-sm text-slate-600">{order.packageName}</p>
        </Card>
      ))}
    </div>
  );

  const OrderFlowTimeline = () => (
    <Card className="p-4">
      <p className="text-sm font-semibold text-slate-800 mb-3">Order Flow Snapshot</p>
      <div className="grid grid-cols-1 md:grid-cols-5 gap-2 text-xs">
        {['Package/Consultation', 'Package Finalization', 'Tasks + Requirements Import', 'Client Upload', 'Employee Validation + Additional Requests'].map((step, idx) => (
          <div key={step} className="rounded-lg border border-slate-200 p-3 bg-slate-50">
            <p className="text-indigo-600 font-bold">Step {idx + 1}</p>
            <p className="mt-1 text-slate-700">{step}</p>
          </div>
        ))}
      </div>
    </Card>
  );

  const OrderDetailsView = () => (
    <div className="space-y-4">
      <Card className="p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-xl font-black text-slate-900">{selectedOrder.serviceName}</h2>
            <p className="text-sm text-slate-500 flex items-center gap-2 mt-1"><Building2 size={14} /> {getOrderClientLabel(selectedOrder)} <span className="text-slate-300">|</span> Rs. {Number(selectedOrder.price || 0).toLocaleString()}</p>
          </div>
          <button onClick={() => setSelectedOrderId(null)} className="px-3 py-2 rounded-lg bg-slate-100 text-slate-700 text-sm font-medium hover:bg-slate-200">Back to Orders</button>
        </div>

        <div className="mt-4 grid grid-cols-1 md:grid-cols-4 gap-3">
          <div><label className="text-xs text-slate-500">Status</label><select value={selectedOrder.status} onChange={(e) => updateOrderStatus(selectedOrder._id, e.target.value)} className="w-full mt-1 p-2.5 border rounded-lg border-slate-300 bg-white">{ORDER_STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}</select></div>
          <div><label className="text-xs text-slate-500">Assign Owner</label><select value={selectedOrder.assignedEmployee?._id || ''} onChange={(e) => assignOrder(selectedOrder._id, e.target.value)} className="w-full mt-1 p-2.5 border rounded-lg border-slate-300 bg-white"><option value="">Unassigned</option>{employees.map((employee) => <option key={employee._id} value={employee._id}>{employee.name}</option>)}</select></div>
          <div><label className="text-xs text-slate-500">Package</label><select value={commercialDraft.packageName} onChange={(e) => setCommercialDraft((p) => ({ ...p, packageName: e.target.value }))} className="w-full mt-1 p-2.5 border rounded-lg border-slate-300 bg-white"><option value="">Select Package</option>{PACKAGE_OPTIONS.map((p) => <option key={p} value={p}>{p}</option>)}</select></div>
          <div><label className="text-xs text-slate-500">Price</label><input value={commercialDraft.price} onChange={(e) => setCommercialDraft((p) => ({ ...p, price: e.target.value }))} className="w-full mt-1 p-2.5 border rounded-lg border-slate-300" /></div>
        </div>

        <div className="mt-3 flex flex-wrap gap-2 items-center">
          {isConsultationOrder(selectedOrder) && <span className="px-2 py-1 rounded-md text-xs font-semibold bg-amber-100 text-amber-800">Consultation Order</span>}
          <button onClick={saveCommercials} className="px-3 py-2 rounded-lg bg-indigo-600 text-white text-sm font-semibold hover:bg-indigo-700">Save Package Assignment</button>
        </div>
      </Card>

      <OrderFlowTimeline />

      <Card>
        <div className="px-4 border-b border-slate-100 flex flex-wrap gap-2">
          {['Overview', 'Tasks', 'Requirements', 'Time Logs', 'Invoices'].map((tab) => (
            <button key={tab} onClick={() => setOrderDetailTab(tab)} className={`px-4 py-3 text-sm font-medium border-b-2 transition ${orderDetailTab === tab ? 'border-indigo-600 text-indigo-700' : 'border-transparent text-slate-500 hover:text-indigo-600'}`}>{tab}</button>
          ))}
        </div>
        <div className="p-5 space-y-4">
          {orderDetailTab === 'Overview' && <div className="grid grid-cols-1 md:grid-cols-4 gap-4"><Card className="p-4"><p className="text-xs text-slate-500">Tasks</p><p className="text-2xl font-bold">{selectedOrder.tasks?.length || 0}</p></Card><Card className="p-4"><p className="text-xs text-slate-500">Requirements</p><p className="text-2xl font-bold">{selectedOrder.customerRequirements?.length || 0}</p></Card><Card className="p-4"><p className="text-xs text-slate-500">Invoices</p><p className="text-2xl font-bold">{selectedOrder.invoices?.length || 0}</p></Card><Card className="p-4"><p className="text-xs text-slate-500">Package</p><p className="text-base font-semibold">{selectedOrder.packageName || '-'}</p></Card></div>}

          {orderDetailTab === 'Tasks' && <div className="space-y-4"><div className="rounded-xl border border-slate-200 p-4 bg-slate-50"><p className="font-semibold text-slate-700 mb-1">Import Tasks & Subtasks</p><textarea value={taskImportText} onChange={(e) => setTaskImportText(e.target.value)} rows={4} className="w-full p-3 border border-slate-300 rounded-lg text-sm" placeholder={'Task A > Subtask 1 | Subtask 2'} /><button onClick={importTasks} className="mt-3 px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-semibold hover:bg-indigo-700">Import Tasks</button></div><div className="space-y-2">{(selectedOrder.tasks || []).map((task) => <div key={task._id} className="rounded-lg border border-slate-200 p-3"><div className="flex justify-between items-center"><p className="font-semibold text-slate-800">{task.title}</p><select value={task.status} onChange={(e) => updateTaskStatus(task._id, e.target.value)} className="p-2 border rounded-lg border-slate-300 bg-white text-xs">{TASK_STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}</select></div><div className="mt-2 grid grid-cols-1 md:grid-cols-3 gap-2"><input type="number" placeholder="Minutes" value={timeLogDrafts[task._id]?.minutes || ''} onChange={(e) => setTimeLogDrafts((p) => ({ ...p, [task._id]: { ...(p[task._id] || {}), minutes: e.target.value } }))} className="p-2 border rounded-lg border-slate-300 text-sm" /><input placeholder="Work note" value={timeLogDrafts[task._id]?.notes || ''} onChange={(e) => setTimeLogDrafts((p) => ({ ...p, [task._id]: { ...(p[task._id] || {}), notes: e.target.value } }))} className="p-2 border rounded-lg border-slate-300 text-sm md:col-span-2" /></div><button onClick={() => addTimeLog(task._id)} className="mt-2 px-3 py-1.5 rounded bg-slate-900 text-white text-xs">Log Time</button></div>)}</div></div>}

          {orderDetailTab === 'Requirements' && <div className="space-y-4"><div className="rounded-xl border border-slate-200 p-4 bg-slate-50"><p className="font-semibold text-slate-700 mb-1">Import Required Details & Documents</p><textarea value={requirementsImportText} onChange={(e) => setRequirementsImportText(e.target.value)} rows={3} className="w-full p-3 border border-slate-300 rounded-lg text-sm" placeholder={'Document: PAN Card | clear copy'} /><button onClick={importRequirements} className="mt-3 px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-semibold hover:bg-indigo-700">Import Requirements</button></div><div className="rounded-xl border border-rose-200 p-4 bg-rose-50"><p className="text-sm font-semibold text-rose-800">Raise Additional Requirement (for insufficient details/documents)</p><div className="mt-2 flex gap-2"><input value={quickRequirementText} onChange={(e) => setQuickRequirementText(e.target.value)} className="flex-1 p-2 border border-rose-300 rounded-lg text-sm" placeholder="Example: Upload clearer GST certificate copy" /><button onClick={raiseAdditionalRequirement} className="px-3 py-2 rounded bg-rose-600 text-white text-sm">Raise</button></div></div><div className="space-y-2">{(selectedOrder.customerRequirements || []).map((item) => <div key={item._id} className="rounded-lg border border-slate-200 p-3 flex flex-wrap items-center justify-between gap-2"><div><p className="font-medium text-slate-800">{item.title}</p><p className="text-xs text-slate-500">{item.type} {item.description ? `- ${item.description}` : ''}</p></div><StatusBadge status={item.status} /></div>)}</div></div>}

          {orderDetailTab === 'Time Logs' && <div className="space-y-2">{(selectedOrder.tasks || []).map((task) => <div key={task._id} className="rounded-lg border border-slate-200 p-3"><p className="font-semibold">{task.title}</p><p className="text-xs text-slate-500 mt-1">Total Minutes: {task.totalMinutes || 0}</p></div>)}</div>}

          {orderDetailTab === 'Invoices' && <div className="space-y-4"><div className="rounded-xl border border-slate-200 p-4 bg-slate-50"><p className="font-semibold text-slate-700 mb-3">Raise Additional Invoice</p><div className="grid grid-cols-1 md:grid-cols-2 gap-3"><input value={invoiceForm.invoiceNumber} onChange={(e) => setInvoiceForm((p) => ({ ...p, invoiceNumber: e.target.value }))} placeholder="Invoice Number" className="p-2.5 border border-slate-300 rounded-lg text-sm" /><input type="number" value={invoiceForm.amount} onChange={(e) => setInvoiceForm((p) => ({ ...p, amount: e.target.value }))} placeholder="Amount" className="p-2.5 border border-slate-300 rounded-lg text-sm" /><select value={invoiceForm.status} onChange={(e) => setInvoiceForm((p) => ({ ...p, status: e.target.value }))} className="p-2.5 border border-slate-300 rounded-lg text-sm">{INVOICE_STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}</select><input type="date" value={invoiceForm.dueDate} onChange={(e) => setInvoiceForm((p) => ({ ...p, dueDate: e.target.value }))} className="p-2.5 border border-slate-300 rounded-lg text-sm" /></div><button onClick={addInvoice} className="mt-3 px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-semibold">Add Invoice</button></div><div className="space-y-2">{(selectedOrder.invoices || []).map((inv) => <div key={inv._id} className="rounded-lg border border-slate-200 p-3 flex items-center justify-between"><div><p className="font-medium">{inv.invoiceNumber}</p><p className="text-xs text-slate-500">Rs. {Number(inv.amount || 0).toLocaleString()}</p></div><select value={inv.status} onChange={(e) => updateInvoiceStatus(inv._id, e.target.value)} className="p-2 border rounded-lg border-slate-300 text-xs">{INVOICE_STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}</select></div>)}</div></div>}
        </div>
      </Card>
    </div>
  );

  const OrdersView = () => (
    <div className="space-y-4">
      {!selectedOrder && <div className="flex items-center justify-between gap-3"><div><h2 className="text-2xl font-bold text-slate-800">Orders</h2><p className="text-sm text-slate-500">Click any row to open order details.</p></div><div className="inline-flex rounded-lg border border-slate-200 bg-white overflow-hidden"><button onClick={() => setOrdersViewMode('list')} className={`px-3 py-2 text-sm flex items-center gap-1 ${ordersViewMode === 'list' ? 'bg-indigo-50 text-indigo-700' : 'text-slate-600'}`}><List size={14} /> List</button><button onClick={() => setOrdersViewMode('board')} className={`px-3 py-2 text-sm flex items-center gap-1 ${ordersViewMode === 'board' ? 'bg-indigo-50 text-indigo-700' : 'text-slate-600'}`}><Kanban size={14} /> Board</button></div></div>}
      {!selectedOrder && ordersViewMode === 'list' && <OrdersListView />}
      {!selectedOrder && ordersViewMode === 'board' && <OrdersBoardView />}
      {selectedOrder && <OrderDetailsView />}
    </div>
  );

  const DummyView = ({ title }) => <Card className="p-6"><p className="text-lg font-bold text-slate-900">{title}</p><p className="text-sm text-slate-500 mt-1">Dummy content for now.</p></Card>;

  const sidebarItems = [
    { key: 'Dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { key: 'Orders', label: 'Orders', icon: Layers },
    { key: 'Users', label: 'Users', icon: Users },
    { key: 'ToDo', label: 'To Do', icon: CheckSquare },
    { key: 'Finance', label: 'Finance', icon: DollarSign },
    { key: 'Reports', label: 'Reports', icon: BarChart3 },
    { key: 'Notifications', label: 'Notifications', icon: Bell },
    { key: 'CRM', label: 'CRM Pipeline', icon: Briefcase },
    { key: 'Knowledge', label: 'Knowledge Base', icon: BookOpen },
    { key: 'Support', label: 'Support Inbox', icon: MessageSquare },
    { key: 'Services', label: 'Services Master', icon: FileText },
    { key: 'Settings', label: 'Settings', icon: Settings }
  ];

  const renderView = () => {
    if (activeTab === 'Dashboard') return <DashboardView />;
    if (activeTab === 'Orders') return <OrdersView />;
    if (activeTab === 'Users') return <DummyView title="Users" />;
    if (activeTab === 'ToDo') return <DummyView title="To Do" />;
    if (activeTab === 'Finance') return <DummyView title="Finance" />;
    if (activeTab === 'Reports') return <DummyView title="Reports" />;
    if (activeTab === 'Notifications') return <DummyView title="Notifications" />;
    if (activeTab === 'CRM') return <DummyView title="CRM Pipeline" />;
    if (activeTab === 'Knowledge') return <DummyView title="Knowledge Base" />;
    if (activeTab === 'Support') return <DummyView title="Support Inbox" />;
    if (activeTab === 'Services') return <ServicesMasterView token={userInfo?.token} />;
    return <DummyView title="Settings" />;
  };

  if (!isLoggedIn) return <div className="min-h-screen flex items-center justify-center bg-slate-900 text-white font-semibold">Verifying Access...</div>;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-100 via-blue-50 to-indigo-100 text-slate-800">
      <div className="flex h-screen">
        <div className={`fixed inset-0 bg-slate-900/35 z-40 lg:hidden ${mobileSidebarOpen ? 'block' : 'hidden'}`} onClick={() => setMobileSidebarOpen(false)} />
        <aside onMouseEnter={() => setSidebarExpanded(true)} onMouseLeave={() => setSidebarExpanded(false)} className={`fixed lg:static z-50 h-screen border-r border-slate-200/70 bg-white/75 backdrop-blur-md flex flex-col transition-all duration-300 ${mobileSidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'} ${sidebarExpanded ? 'w-72' : 'w-20 lg:w-20'}`}>
          <div className="h-20 px-4 flex items-center justify-between border-b border-slate-200/70">
            <div className={`${sidebarExpanded ? 'block' : 'hidden'}`}><p className="text-xs uppercase tracking-widest text-indigo-500 font-bold">VR Here</p><p className="text-xl font-black text-slate-900">Admin Studio</p></div>
            {!sidebarExpanded && <div className="w-8 h-8 rounded-lg bg-indigo-600 text-white flex items-center justify-center font-bold text-xs">VR</div>}
            <button className="lg:hidden text-slate-500" onClick={() => setMobileSidebarOpen(false)}><X size={18} /></button>
          </div>
          <div className="p-3 space-y-1 flex-1 overflow-y-auto">
            {sidebarItems.map((item) => {
              const Icon = item.icon;
              const active = activeTab === item.key;
              return <button key={item.key} onClick={() => { setActiveTab(item.key); setMobileSidebarOpen(false); if (item.key !== 'Orders') setSelectedOrderId(null); }} className={`w-full px-3 py-2.5 rounded-xl text-sm font-medium flex items-center gap-2 transition ${active ? 'bg-gradient-to-r from-indigo-600 to-blue-600 text-white shadow-lg' : 'text-slate-700 hover:bg-indigo-50'}`}><Icon size={16} /> {sidebarExpanded && item.label}</button>;
            })}
          </div>
          <div className="p-3 border-t border-slate-200/70"><button onClick={handleLogout} className="w-full px-3 py-2.5 rounded-lg text-sm font-medium flex items-center gap-2 text-rose-600 hover:bg-rose-50"><LogOut size={16} /> {sidebarExpanded && 'Logout'}</button></div>
        </aside>
        <main className="flex-1 flex flex-col overflow-hidden w-full">
          <header className="h-20 px-4 sm:px-6 flex items-center justify-between border-b border-slate-200/70 bg-white/60 backdrop-blur-md">
            <div className="flex items-center gap-3">
              <button className="lg:hidden p-2 rounded-lg border border-slate-200 bg-white text-slate-600" onClick={() => setMobileSidebarOpen(true)}><Menu size={18} /></button>
              <div><p className="text-xs text-slate-500">VR Here Admin Panel</p><h1 className="font-bold text-xl sm:text-2xl text-slate-900">{activeTab}</h1></div>
            </div>
            <div className="flex items-center gap-3"><div className="hidden sm:flex rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs text-slate-600 items-center gap-1"><Clock3 size={14} /> Live</div><div className="w-10 h-10 rounded-full bg-gradient-to-br from-indigo-600 to-blue-500 text-white flex items-center justify-center text-xs font-semibold">{userInfo?.name?.charAt(0) || 'A'}</div></div>
          </header>
          <div className="flex-1 overflow-y-auto p-4 sm:p-6">{renderView()}</div>
        </main>
      </div>
    </div>
  );
}

export default AdminApp;
