import React, { useEffect, useMemo, useState } from 'react';
import {
  LayoutDashboard,
  User as UsersIcon,
  Layers,
  FileText,
  CheckSquare,
  DollarSign,
  BarChart3,
  Bell,
  Settings,
  LogOut,
  Clock3,
  Menu,
  X,
  Briefcase,
  BookOpen,
  MessageSquare,
  RefreshCcw,
  Trash2,
  TrendingUp
} from 'lucide-react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import ServicesMasterView from './components/admin/ServicesMasterView';
import OrdersModule from './components/admin/orders/OrdersModule';
import UsersModule from './components/admin/users/UsersModule';
import { ORDER_STATUSES } from './components/admin/orders/constants';
import { nextStatus } from './components/admin/orders/helpers';
import { parseRequirementWorkbook, parseTaskWorkbook } from './components/admin/orders/excelParsers';
import QuickActionFAB from './components/admin/QuickActionFAB';
import NewOrderModal from './components/admin/modals/NewOrderModal';
import NewTodoModal from './components/admin/modals/NewTodoModal';
import TodoModule from './components/admin/TodoModule';
import RecurringServicesModule from './components/admin/RecurringServicesModule';
import MakeRecurringModal from './components/admin/modals/MakeRecurringModal';
import ReferralPartnersModule from './components/admin/referrals/ReferralPartnersModule';

const Card = ({ children, className = '' }) => (
  <div className={`rounded-2xl border border-white/70 bg-white/85 backdrop-blur-sm shadow-[0_10px_30px_rgba(15,23,42,0.08)] ${className}`}>
    {children}
  </div>
);

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
  const [invoiceForm, setInvoiceForm] = useState({ invoiceNumber: '', amount: '', status: 'Draft', dueDate: '', notes: '' });
  const [commercialDraft, setCommercialDraft] = useState({ packageName: '', price: '' });
  const [todos, setTodos] = useState([]);
  const [isNewOrderModalOpen, setIsNewOrderModalOpen] = useState(false);
  const [isNewTodoModalOpen, setIsNewTodoModalOpen] = useState(false);
  const [isMakeRecurringModalOpen, setIsMakeRecurringModalOpen] = useState(false);
  const [todoToEdit, setTodoToEdit] = useState(null);
  const [orderToDelete, setOrderToDelete] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  useEffect(() => {
    console.log("VR HERE Admin Dashboard Loaded - v1.1.4 (Manual + Recurring)");
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
    const [ordersRes, employeesRes, usersRes, todosRes] = await Promise.all([
      axios.get('/api/orders', config),
      axios.get('/api/auth/employees', config),
      axios.get('/api/auth/users', config),
      axios.get('/api/todos', config)
    ]);
    setOrders(ordersRes.data || []);
    setEmployees(employeesRes.data || []);
    setUsers(usersRes.data || []);
    setTodos(todosRes.data || []);
  };

  useEffect(() => {
    fetchData().catch((error) => console.error(error));
  }, [config]);

  const selectedOrder = useMemo(() => orders.find((order) => order._id === selectedOrderId) || null, [orders, selectedOrderId]);

  useEffect(() => {
    if (selectedOrder) {
      setCommercialDraft({ packageName: selectedOrder.packageName || '', price: String(selectedOrder.price || '') });
    }
  }, [selectedOrder]);

  const handleLogout = () => {
    localStorage.removeItem('userInfo');
    navigate('/login');
  };

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      await fetchData();
    } finally {
      setTimeout(() => setIsRefreshing(false), 600);
    }
  };

  const updateOrderStatus = async (orderId, status) => {
    await axios.put(`/api/orders/${orderId}/status`, { status }, config);
    fetchData();
  };

  const quickUpdateOrder = async (order) => {
    const status = nextStatus(order.status, ORDER_STATUSES);
    await updateOrderStatus(order._id, status);
  };

  const deleteOrder = async (order) => {
    await axios.delete(`/api/orders/${order._id}`, config);
    if (selectedOrderId === order._id) {
      setSelectedOrderId(null);
    }
    setOrderToDelete(null);
    fetchData();
  };

  const assignOrder = async (orderId, payload) => {
    await axios.put(`/api/orders/${orderId}/assign`, payload, config);
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

  const importTaskWorkbook = async (orderId, file, replaceExisting) => {
    const { parentTasks, subTasks } = await parseTaskWorkbook(file);
    await axios.post(`/api/orders/${orderId}/tasks/import`, {
      parentTasks,
      subTasks,
      replaceExisting
    }, config);
    fetchData();
  };

  const updateTaskStatus = async (orderId, taskId, status) => {
    await axios.put(`/api/orders/${orderId}/tasks/${taskId}`, { status }, config);
    fetchData();
  };

  const assignTask = async (orderId, taskId, payload) => {
    await axios.put(`/api/orders/${orderId}/tasks/${taskId}/assign`, payload, config);
    fetchData();
  };

  const updateSubtask = async (orderId, taskId, subtaskId, payload) => {
    await axios.put(`/api/orders/${orderId}/tasks/${taskId}/subtasks/${subtaskId}`, payload, config);
    fetchData();
  };

  const importRequirementsWorkbook = async (orderId, file, replaceExisting) => {
    const { detailRows, documentRows } = await parseRequirementWorkbook(file);
    await axios.post(`/api/orders/${orderId}/requirements/import`, {
      detailRows,
      documentRows,
      replaceExisting
    }, config);
    fetchData();
  };

  const raiseRequirement = async (orderId, payload) => {
    await axios.post(`/api/orders/${orderId}/requirements`, payload, config);
    fetchData();
  };

  const updateRequirementStatus = async (orderId, requirementId, status) => {
    await axios.put(`/api/orders/${orderId}/requirements/${requirementId}`, { status }, config);
    fetchData();
  };

  const addInvoice = async (orderId) => {
    if (!invoiceForm.invoiceNumber || !invoiceForm.amount) return;
    await axios.post(`/api/orders/${orderId}/invoices`, {
      invoiceNumber: invoiceForm.invoiceNumber,
      amount: Number(invoiceForm.amount),
      status: invoiceForm.status,
      dueDate: invoiceForm.dueDate || null,
      notes: invoiceForm.notes
    }, config);
    setInvoiceForm({ invoiceNumber: '', amount: '', status: 'Draft', dueDate: '', notes: '' });
    fetchData();
  };

  const updateInvoiceStatus = async (orderId, invoiceId, status) => {
    await axios.put(`/api/orders/${orderId}/invoices/${invoiceId}/status`, { status }, config);
    fetchData();
  };

  const DashboardView = () => (
    <div className="space-y-6">
      <Card className="p-6 bg-gradient-to-r from-slate-900 via-blue-900 to-indigo-900 text-white shadow-xl shadow-blue-900/20">
        <p className="text-cyan-200 text-xs font-black uppercase tracking-widest">Admin Command Center (v1.1.7 - Enhanced Controls)</p>
        <h2 className="text-3xl font-black mt-1">Operations Studio</h2>
        <p className="text-slate-200 mt-2">Service delivery, consultation conversion, and execution status in one place.</p>
      </Card>
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {[
          { l: 'Total Orders', v: orders.length, key: 'Orders' },
          { l: 'Pending', v: orders.filter((o) => o.status !== 'Completed').length, key: 'Orders' },
          { l: 'Completed', v: orders.filter((o) => o.status === 'Completed').length, key: 'Orders' },
          { l: 'Order Value', v: `Rs. ${orders.reduce((s, o) => s + Number(o.price || 0), 0).toLocaleString()}`, key: 'Reports' }
        ].map((item) => (
          <Card 
            key={item.l} 
            className="p-5 hover:scale-[1.02] active:scale-[0.98] transition-all cursor-pointer group hover:ring-2 hover:ring-indigo-600/20"
            onClick={() => setActiveTab(item.key)}
          >
            <p className="text-[10px] uppercase font-black text-slate-400 tracking-widest group-hover:text-indigo-600 transition-colors">{item.l}</p>
            <p className="text-3xl font-black mt-1 text-slate-900 tracking-tighter">{item.v}</p>
          </Card>
        ))}
      </div>
    </div>
  );

  const DummyView = ({ title }) => (
    <Card className="p-6">
      <p className="text-lg font-bold text-slate-900">{title}</p>
      <p className="text-sm text-slate-500 mt-1">Dummy content for now.</p>
      {title === 'Users' && (
        <p className="text-xs text-slate-500 mt-3">Total users loaded: {users.length}</p>
      )}
    </Card>
  );

  const sidebarItems = [
    { key: 'Dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { key: 'Orders', label: 'Orders', icon: Layers },
    { key: 'Users', label: 'Users', icon: UsersIcon },
    { key: 'ToDo', label: 'To Do', icon: CheckSquare },
    { key: 'Finance', label: 'Finance', icon: DollarSign },
    { key: 'Reports', label: 'Reports', icon: BarChart3 },
    { key: 'Notifications', label: 'Notifications', icon: Bell },
    { key: 'CRM', label: 'CRM Pipeline', icon: Briefcase },
    { key: 'Knowledge', label: 'Knowledge Base', icon: BookOpen },
    { key: 'Support', label: 'Support Inbox', icon: MessageSquare },
    { key: 'Services', label: 'Services Master', icon: FileText },
    { key: 'Referrals', label: 'Referral Partners', icon: TrendingUp },
    { key: 'Recurring', label: 'Recurring Hub', icon: RefreshCcw },
    { key: 'Settings', label: 'Settings', icon: Settings }
  ];

  const renderView = () => {
    if (activeTab === 'Dashboard') return <DashboardView />;
    if (activeTab === 'Orders') {
      return (
        <OrdersModule
          orders={orders}
          employees={employees}
          selectedOrderId={selectedOrderId}
          setSelectedOrderId={setSelectedOrderId}
          ordersViewMode={ordersViewMode}
          setOrdersViewMode={setOrdersViewMode}
          orderDetailTab={orderDetailTab}
          setOrderDetailTab={setOrderDetailTab}
          commercialDraft={commercialDraft}
          setCommercialDraft={setCommercialDraft}
          invoiceForm={invoiceForm}
          setInvoiceForm={setInvoiceForm}
          onSaveCommercials={saveCommercials}
          onDeleteOrder={(order) => setOrderToDelete(order)}
          onQuickUpdateOrder={quickUpdateOrder}
          onUpdateOrderStatus={updateOrderStatus}
          onAssignOrder={assignOrder}
          onImportTaskWorkbook={importTaskWorkbook}
          onTaskStatusChange={updateTaskStatus}
          onTaskAssign={assignTask}
          onSubtaskUpdate={updateSubtask}
          onAddTask={async (orderId, payload) => {
            await axios.post(`/api/orders/${orderId}/tasks`, payload, config);
            fetchData();
          }}
          onImportRequirementsWorkbook={importRequirementsWorkbook}
          onRaiseRequirement={raiseRequirement}
          onUpdateRequirementStatus={updateRequirementStatus}
          onAddInvoice={addInvoice}
          onUpdateInvoiceStatus={updateInvoiceStatus}
          onOpenRecurringModal={() => setIsMakeRecurringModalOpen(true)}
        />
      );
    }
    if (activeTab === 'Users') return <UsersModule token={userInfo?.token} users={users} orders={orders} onRefresh={fetchData} />;
    if (activeTab === 'ToDo') return (
      <TodoModule 
        todos={todos} 
        employees={employees} 
        token={userInfo?.token} 
        onRefresh={fetchData} 
        onEdit={(todo) => {
          setTodoToEdit(todo);
          setIsNewTodoModalOpen(true);
        }}
      />
    );
    if (activeTab === 'Finance') return <DummyView title="Finance" />;
    if (activeTab === 'Reports') return <DummyView title="Reports" />;
    if (activeTab === 'Notifications') return <DummyView title="Notifications" />;
    if (activeTab === 'CRM') return <DummyView title="CRM Pipeline" />;
    if (activeTab === 'Knowledge') return <DummyView title="Knowledge Base" />;
    if (activeTab === 'Support') return <DummyView title="Support Inbox" />;
    if (activeTab === 'Services') return <ServicesMasterView token={userInfo?.token} />;
    if (activeTab === 'Referrals') return <ReferralPartnersModule config={config} orders={orders} />;
    if (activeTab === 'Recurring') return (
      <RecurringServicesModule 
        token={userInfo?.token} 
        onViewOrder={(orderId) => {
          setSelectedOrderId(orderId);
          setActiveTab('Orders');
          setOrderDetailTab('Overview');
        }}
      />
    );
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
            <div className="flex items-center gap-3">
              <button 
                onClick={() => setActiveTab('Notifications')}
                className="p-2.5 bg-white border border-slate-200 rounded-xl text-slate-500 hover:bg-indigo-50 hover:text-indigo-600 transition-all relative group"
                title="Notifications"
              >
                <Bell size={20} />
                <div className="absolute top-2 right-2 w-2 h-2 bg-rose-500 rounded-full border-2 border-white group-hover:animate-ping"></div>
              </button>
              <button 
                onClick={handleRefresh}
                className={`p-2 rounded-xl border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 transition-all ${isRefreshing ? 'animate-spin' : ''}`}
                title="Refresh Data"
              >
                <RefreshCcw size={16} />
              </button>
              <div className="hidden sm:flex rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs text-slate-600 items-center gap-1">
                <Clock3 size={14} /> Live
              </div>
              <div className="w-10 h-10 rounded-full bg-gradient-to-br from-indigo-600 to-blue-500 text-white flex items-center justify-center text-xs font-semibold">
                {userInfo?.name?.charAt(0) || 'A'}
              </div>
            </div>
          </header>
          <div className="flex-1 overflow-y-auto p-4 sm:p-6">{renderView()}</div>
        </main>
      </div>

      {isMakeRecurringModalOpen && selectedOrder && (
        <MakeRecurringModal 
          isOpen={isMakeRecurringModalOpen} 
          onClose={() => setIsMakeRecurringModalOpen(false)} 
          selectedOrder={selectedOrder} 
          token={userInfo?.token}
          onSuccess={fetchData}
        />
      )}

      {orderToDelete && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-900/60 backdrop-blur-md p-4 animate-fade-in shadow-2xl">
          <div className="bg-white rounded-[2.5rem] p-8 max-w-md w-full shadow-2xl border border-indigo-100/50 space-y-6">
            <div className="w-20 h-20 bg-rose-50 rounded-[2rem] mx-auto flex items-center justify-center text-rose-500 shadow-inner">
               <Trash2 size={40} />
            </div>
            <div className="text-center space-y-2">
               <h3 className="text-2xl font-black text-slate-900">Delete Project?</h3>
               <p className="text-sm text-slate-500 font-medium">Are you sure you want to permanently delete the project for <span className="font-black text-indigo-600">"{orderToDelete.serviceName}"</span>? This action cannot be undone.</p>
            </div>
            <div className="flex flex-col gap-3">
               <button 
                 onClick={() => deleteOrder(orderToDelete)}
                 className="w-full py-4 bg-rose-600 text-white rounded-2xl font-black text-sm shadow-xl shadow-rose-200 hover:bg-rose-700 transition-all active:scale-[0.98]"
               >
                 Yes, Delete Project
               </button>
               <button 
                 onClick={() => setOrderToDelete(null)}
                 className="w-full py-4 bg-slate-100 text-slate-600 rounded-2xl font-black text-sm hover:bg-slate-200 transition-all active:scale-[0.98]"
               >
                 Go Back
               </button>
            </div>
          </div>
        </div>
      )}

      <QuickActionFAB 
        onNewOrder={() => setIsNewOrderModalOpen(true)}
        onNewTodo={() => {
          setTodoToEdit(null);
          setIsNewTodoModalOpen(true);
        }}
        onRefresh={handleRefresh}
        isRefreshing={isRefreshing}
      />

      <NewOrderModal 
        isOpen={isNewOrderModalOpen} 
        onClose={() => setIsNewOrderModalOpen(false)} 
        users={users} 
        employees={employees} 
        token={userInfo?.token} 
        onCreated={fetchData} 
      />

      <NewTodoModal 
        isOpen={isNewTodoModalOpen} 
        onClose={() => {
          setIsNewTodoModalOpen(false);
          setTodoToEdit(null);
        }} 
        orders={orders} 
        employees={employees} 
        token={userInfo?.token} 
        onCreated={fetchData} 
        todoToEdit={todoToEdit}
      />
    </div>
  );
}

export default AdminApp;
