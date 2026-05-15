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
  TrendingUp,
  Plus,
  Activity
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
import FinanceModule from './components/admin/finance/FinanceModule';
import { RevenueChart, ServiceDistributionChart, EmployeeWorkloadChart } from './components/admin/DashboardCharts';
import { AlertCircle, ArrowUpRight, TrendingUp as TrendIcon, Users, CreditCard, ShieldCheck } from 'lucide-react';

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
  const [recurring, setRecurring] = useState([]);
  const [orderFilter, setOrderFilter] = useState('All');

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
    const [ordersRes, employeesRes, usersRes, todosRes, recurringRes] = await Promise.all([
      axios.get('/api/orders', config),
      axios.get('/api/auth/employees', config),
      axios.get('/api/auth/users', config),
      axios.get('/api/todos', config),
      axios.get('/api/recurring', config).catch(() => ({ data: [] }))
    ]);
    setOrders(ordersRes.data || []);
    setEmployees(employeesRes.data || []);
    setUsers(usersRes.data || []);
    setTodos(todosRes.data || []);
    setRecurring(recurringRes.data || []);
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

  const deleteRequirement = async (orderId, requirementId) => {
    if (!window.confirm('Are you sure you want to delete this requirement?')) return;
    await axios.delete(`/api/orders/${orderId}/requirements/${requirementId}`, config);
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

  const DashboardView = () => {
    const recentOrders = [...orders].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 5);
    const statusCounts = orders.reduce((acc, o) => {
      acc[o.status] = (acc[o.status] || 0) + 1;
      return acc;
    }, {});

    const revenueData = useMemo(() => {
      const months = [];
      for (let i = 5; i >= 0; i--) {
        const d = new Date();
        d.setMonth(d.getMonth() - i);
        months.push({ name: d.toLocaleString('default', { month: 'short' }), revenue: 0, month: d.getMonth(), year: d.getFullYear() });
      }
      orders.forEach(o => {
        const d = new Date(o.createdAt);
        const match = months.find(m => m.month === d.getMonth() && m.year === d.getFullYear());
        if (match) match.revenue += Number(o.price || 0);
      });
      return months;
    }, [orders]);

    const serviceDistribution = useMemo(() => {
       const counts = orders.reduce((acc, o) => {
         acc[o.serviceName] = (acc[o.serviceName] || 0) + 1;
         return acc;
       }, {});
       return Object.entries(counts).map(([name, value]) => ({ name, value })).sort((a,b) => b.value - a.value).slice(0, 5);
    }, [orders]);

    const workloadData = useMemo(() => {
      return employees.map(emp => ({
        name: emp.name,
        orders: orders.filter(o => o.assignedEmployee?._id === emp._id && o.status !== 'Completed').length
      })).sort((a,b) => b.orders - a.orders).slice(0, 5);
    }, [employees, orders]);

    const pendingDocsOrders = orders.filter(o => o.status === 'Pending Documents').slice(0, 5);
    
    const financialSummary = useMemo(() => {
       const total = orders.reduce((s, o) => s + Number(o.price || 0), 0);
       const paid = orders.reduce((s, o) => s + (o.paymentStatus === 'Paid' ? Number(o.price || 0) : 0), 0);
       return { total, paid, pending: total - paid };
    }, [orders]);

    const topReferrals = useMemo(() => {
      const counts = orders.reduce((acc, o) => {
        if (o.referralPartner) {
          const name = o.referralPartner.name || (typeof o.referralPartner === 'string' ? 'Partner' : o.referralPartner.name) || 'Partner';
          acc[name] = (acc[name] || 0) + Number(o.price || 0);
        }
        return acc;
      }, {});
      return Object.entries(counts).map(([name, value]) => ({ name, value })).sort((a,b) => b.value - a.value).slice(0, 4);
    }, [orders]);

    return (
      <div className="space-y-6">
        <Card className="p-6 bg-gradient-to-r from-slate-900 via-blue-900 to-indigo-900 text-white shadow-xl shadow-blue-900/20 relative overflow-hidden">
          <div className="absolute top-0 right-0 p-8 opacity-10">
             <Activity size={120} />
          </div>
          <p className="text-cyan-200 text-xs font-black uppercase tracking-widest relative z-10">Admin Command Center (v1.1.8 - Power Tools)</p>
          <h2 className="text-3xl font-black mt-1 relative z-10">Operations Studio</h2>
          <p className="text-slate-200 mt-2 relative z-10">Service delivery, consultation conversion, and execution status in one place.</p>
          <div className="mt-4 flex gap-4 relative z-10">
             <div className="px-3 py-1 bg-white/10 backdrop-blur-md rounded-lg border border-white/10">
                <p className="text-[9px] font-black uppercase text-cyan-300">Active Pipeline</p>
                <p className="text-sm font-black">{orders.filter(o => o.status !== 'Completed').length} Projects</p>
             </div>
             <div className="px-3 py-1 bg-white/10 backdrop-blur-md rounded-lg border border-white/10">
                <p className="text-[9px] font-black uppercase text-emerald-300">Total Value</p>
                <p className="text-sm font-black">Rs. {orders.reduce((s, o) => s + Number(o.price || 0), 0).toLocaleString()}</p>
             </div>
          </div>
        </Card>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
           {[
             { l: 'New Order', i: Plus, c: 'bg-emerald-500', a: () => setIsNewOrderModalOpen(true) },
             { l: 'Add To-Do', i: CheckSquare, c: 'bg-amber-500', a: () => setIsNewTodoModalOpen(true) },
             { l: 'Finance', i: DollarSign, c: 'bg-indigo-500', a: () => setActiveTab('Finance') },
             { l: 'Refresh', i: RefreshCcw, c: 'bg-slate-700', a: handleRefresh }
           ].map((action, idx) => (
             <button key={idx} onClick={action.a} className="p-4 rounded-2xl bg-white border border-slate-100 shadow-sm hover:shadow-md transition-all flex flex-col items-center gap-2 group active:scale-95">
                <div className={`p-2.5 rounded-xl ${action.c} text-white group-hover:scale-110 transition-transform shadow-lg shadow-inner`}>
                   <action.i size={20} />
                </div>
                <span className="text-[10px] font-black uppercase text-slate-500 tracking-widest">{action.l}</span>
             </button>
           ))}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          {[
            { l: 'Total Orders', v: orders.length, key: 'Orders', f: 'All', i: Layers, c: 'text-blue-600', bg: 'bg-blue-50' },
            { l: 'Pending', v: orders.filter((o) => o.status !== 'Completed').length, key: 'Orders', f: 'Pending', i: Clock3, c: 'text-amber-600', bg: 'bg-amber-50' },
            { l: 'Completed', v: orders.filter((o) => o.status === 'Completed').length, key: 'Orders', f: 'Completed', i: ShieldCheck, c: 'text-emerald-600', bg: 'bg-emerald-50' },
            { l: 'Order Value', v: `Rs. ${orders.reduce((s, o) => s + Number(o.price || 0), 0).toLocaleString()}`, key: 'Finance', f: 'All', i: DollarSign, c: 'text-indigo-600', bg: 'bg-indigo-50' }
          ].map((item) => (
            <Card 
              key={item.l} 
              className="p-5 hover:scale-[1.02] active:scale-[0.98] transition-all cursor-pointer group hover:ring-2 hover:ring-indigo-600/20 relative overflow-hidden"
              onClick={() => {
                setActiveTab(item.key);
                if (item.key === 'Orders') {
                   setSelectedOrderId(null);
                   setOrderFilter(item.f);
                }
              }}
            >
              <div className="flex items-center justify-between relative z-10">
                <div>
                  <p className="text-[10px] uppercase font-black text-slate-400 tracking-widest group-hover:text-indigo-600 transition-colors">{item.l}</p>
                  <p className="text-3xl font-black mt-1 text-slate-900 tracking-tighter">{item.v}</p>
                </div>
                <div className={`p-3 rounded-2xl ${item.bg} ${item.c} shadow-sm group-hover:scale-110 transition-transform`}>
                   <item.i size={24} />
                </div>
              </div>
              <div className="absolute -bottom-2 -right-2 opacity-[0.03] group-hover:opacity-[0.07] transition-opacity">
                 <item.i size={80} />
              </div>
            </Card>
          ))}
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <Card className="xl:col-span-2 p-6 overflow-hidden">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-black text-slate-900 uppercase tracking-tight text-lg">Latest Work Updates</h3>
              <button onClick={() => { setActiveTab('Orders'); setSelectedOrderId(null); }} className="text-xs font-bold text-indigo-600 hover:underline">View All</button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-slate-100">
                    <th className="pb-3 text-xs font-black text-slate-400 uppercase">Service</th>
                    <th className="pb-3 text-xs font-black text-slate-400 uppercase">Client</th>
                    <th className="pb-3 text-xs font-black text-slate-400 uppercase">Status</th>
                    <th className="pb-3 text-xs font-black text-slate-400 uppercase text-right">Value</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {recentOrders.map(o => (
                    <tr key={o._id} className="group hover:bg-slate-50/50 cursor-pointer" onClick={() => { setSelectedOrderId(o._id); setActiveTab('Orders'); setOrderDetailTab('Overview'); }}>
                      <td className="py-3 text-sm font-bold text-slate-700">{o.serviceName}</td>
                      <td className="py-3 text-sm text-slate-500">{o.userName || o.user?.name || 'Guest'}</td>
                      <td className="py-3">
                         <span className={`px-2 py-1 rounded-md text-[10px] font-black uppercase ${o.status === 'Completed' ? 'bg-green-100 text-green-700' : 'bg-amber-100 text-amber-700'}`}>
                           {o.status}
                         </span>
                      </td>
                      <td className="py-3 text-sm font-black text-slate-900 text-right">Rs. {Number(o.price || 0).toLocaleString()}</td>
                    </tr>
                  ))}
                  {recentOrders.length === 0 && (
                    <tr>
                      <td colSpan="4" className="py-8 text-center text-slate-400 text-xs italic">No recent orders found</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Card>

          <div className="space-y-6">
            <Card className="p-6">
               <h3 className="font-black text-slate-900 uppercase tracking-tight mb-4">Order Pipeline</h3>
               <div className="space-y-4">
                  {Object.entries(statusCounts).length > 0 ? Object.entries(statusCounts).map(([status, count]) => (
                    <div key={status} className="flex flex-col gap-1.5">
                       <div className="flex items-center justify-between">
                          <span className="text-[10px] font-black text-slate-400 uppercase tracking-wider">{status}</span>
                          <span className="text-xs font-black text-slate-900">{count}</span>
                       </div>
                       <div className="w-full h-1.5 bg-slate-100 rounded-full overflow-hidden">
                          <div 
                            className="h-full bg-indigo-600" 
                            style={{ width: `${(count / orders.length) * 100}%` }}
                          />
                       </div>
                    </div>
                  )) : <p className="text-xs text-slate-400 italic">No data available</p>}
               </div>
            </Card>

            <Card className="p-6 bg-indigo-600 text-white shadow-lg shadow-indigo-200">
               <h3 className="font-black uppercase tracking-tight mb-2">System Insights</h3>
               <p className="text-xs text-indigo-100 leading-relaxed">Average project value: <span className="font-black text-white">Rs. {(orders.length > 0 ? (orders.reduce((s, o) => s + Number(o.price || 0), 0) / orders.length) : 0).toLocaleString()}</span></p>
               <button onClick={() => setActiveTab('Reports')} className="mt-4 w-full py-2 bg-white text-indigo-600 rounded-lg text-xs font-black uppercase hover:bg-indigo-50 transition-colors">View Analytics</button>
            </Card>
          </div>
        </div>
        
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
           <Card className="p-6">
              <div className="flex items-center justify-between mb-4">
                 <h3 className="font-black text-slate-900 uppercase tracking-tight">Recent Tasks</h3>
                 <button onClick={() => setActiveTab('ToDo')} className="text-xs font-bold text-indigo-600 hover:underline">Manage</button>
              </div>
              <div className="space-y-3">
                 {todos.slice(0, 4).map(t => (
                   <div key={t._id} className="flex items-start gap-3 p-2 rounded-lg hover:bg-slate-50 transition-colors border border-transparent hover:border-slate-100">
                      <div className={`mt-1.5 w-2 h-2 rounded-full flex-shrink-0 ${t.completed ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.4)]' : 'bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.4)]'}`} />
                      <div>
                         <p className="text-xs font-bold text-slate-800 line-clamp-1">{t.title}</p>
                         <p className="text-[10px] text-slate-500 mt-0.5 uppercase tracking-wider">{t.assignedTo?.name || 'Unassigned'}</p>
                      </div>
                   </div>
                 ))}
                 {todos.length === 0 && <p className="text-xs text-slate-400 italic py-4 text-center">No recent tasks</p>}
              </div>
           </Card>

           <Card className="p-6">
              <h3 className="font-black text-slate-900 uppercase tracking-tight mb-4">Top Services</h3>
              <div className="space-y-4">
                 {Object.entries(orders.reduce((acc, o) => {
                   acc[o.serviceName] = (acc[o.serviceName] || 0) + 1;
                   return acc;
                 }, {})).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([name, count]) => (
                   <div key={name} className="flex items-center justify-between group">
                      <span className="text-xs font-bold text-slate-600 truncate mr-2 group-hover:text-indigo-600 transition-colors">{name}</span>
                      <span className="text-xs font-black text-indigo-600 bg-indigo-50 px-2 py-1 rounded-lg border border-indigo-100">{count}</span>
                   </div>
                 ))}
                 {orders.length === 0 && <p className="text-xs text-slate-400 italic py-4 text-center">No service data</p>}
              </div>
           </Card>

           <Card className="p-6">
              <div className="flex items-center justify-between mb-4">
                 <h3 className="font-black text-slate-900 uppercase tracking-tight">New Users</h3>
                 <button onClick={() => setActiveTab('Users')} className="text-xs font-bold text-indigo-600 hover:underline">View All</button>
              </div>
              <div className="flex -space-x-3 overflow-hidden mb-5">
                 {users.slice(0, 6).map(u => (
                   <div key={u._id} className="inline-block h-10 w-10 rounded-full ring-4 ring-white bg-gradient-to-br from-indigo-500 to-blue-600 flex items-center justify-center text-xs font-black text-white shadow-sm" title={u.name}>
                      {u.name?.charAt(0) || 'U'}
                   </div>
                 ))}
                 {users.length > 6 && (
                   <div className="inline-block h-10 w-10 rounded-full ring-4 ring-white bg-slate-100 flex items-center justify-center text-xs font-black text-slate-600 shadow-sm">
                      +{users.length - 6}
                   </div>
                 )}
              </div>
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-100">
                 <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">Total Community</p>
                 <p className="text-xl font-black text-slate-900">{users.length} <span className="text-[10px] text-emerald-600 ml-1 font-black">Members</span></p>
              </div>
           </Card>

           <Card className="p-6">
              <div className="flex items-center justify-between mb-4">
                 <h3 className="font-black text-slate-900 uppercase tracking-tight">Top Referrals</h3>
                 <button onClick={() => setActiveTab('Referrals')} className="text-xs font-bold text-indigo-600 hover:underline">Manage</button>
              </div>
              <div className="space-y-4">
                 {topReferrals.map((ref, idx) => (
                   <div key={idx} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                         <div className="w-8 h-8 rounded-lg bg-red-50 text-red-600 flex items-center justify-center text-xs font-black">{ref.name.charAt(0)}</div>
                         <span className="text-xs font-bold text-slate-700">{ref.name}</span>
                      </div>
                      <span className="text-xs font-black text-slate-900">Rs. {ref.value.toLocaleString()}</span>
                   </div>
                 ))}
                 {topReferrals.length === 0 && <p className="text-xs text-slate-400 italic py-4 text-center">No referral data yet</p>}
              </div>
           </Card>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
           <Card className="p-6">
              <div className="flex items-center justify-between mb-6">
                 <div>
                    <h3 className="font-black text-slate-900 uppercase tracking-tight">Revenue Trend</h3>
                    <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-1">Monthly Billing Volume</p>
                 </div>
                 <div className="flex items-center gap-1 text-emerald-600 bg-emerald-50 px-2 py-1 rounded-lg text-[10px] font-black uppercase">
                    <TrendIcon size={12} /> +12.5%
                 </div>
              </div>
              <RevenueChart data={revenueData} />
           </Card>

           <Card className="p-6">
              <div className="flex items-center justify-between mb-6">
                 <div>
                    <h3 className="font-black text-slate-900 uppercase tracking-tight">Service Mix</h3>
                    <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-1">Top Performing Offerings</p>
                 </div>
              </div>
              <ServiceDistributionChart data={serviceDistribution} />
           </Card>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
           <Card className="p-6 xl:col-span-2">
              <div className="flex items-center justify-between mb-6">
                 <div>
                    <h3 className="font-black text-slate-900 uppercase tracking-tight flex items-center gap-2">
                       <AlertCircle className="text-amber-500" size={18} />
                       Pending Documents
                    </h3>
                    <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-1">Projects waiting for client input</p>
                 </div>
                 <button onClick={() => { setActiveTab('Orders'); setOrderFilter('Pending Documents'); }} className="text-xs font-bold text-indigo-600 hover:underline">View All</button>
              </div>
              <div className="space-y-3">
                 {pendingDocsOrders.map(o => (
                   <div key={o._id} className="flex items-center justify-between p-3 rounded-xl border border-slate-100 hover:border-indigo-200 transition-colors group cursor-pointer" onClick={() => { setSelectedOrderId(o._id); setActiveTab('Orders'); setOrderDetailTab('Overview'); }}>
                      <div className="flex items-center gap-3">
                         <div className="w-10 h-10 rounded-xl bg-slate-50 flex items-center justify-center text-slate-400 group-hover:bg-indigo-50 group-hover:text-indigo-600 transition-colors">
                            <FileText size={20} />
                         </div>
                         <div>
                            <p className="text-sm font-bold text-slate-800">{o.serviceName}</p>
                            <p className="text-xs text-slate-500">{o.userName || 'Guest'}</p>
                         </div>
                      </div>
                      <div className="flex items-center gap-4">
                         <div className="text-right hidden sm:block">
                            <p className="text-xs font-black text-slate-900">Rs. {Number(o.price || 0).toLocaleString()}</p>
                            <p className="text-[10px] text-slate-400 font-medium">Value</p>
                         </div>
                         <ArrowUpRight size={16} className="text-slate-300 group-hover:text-indigo-600 transition-colors" />
                      </div>
                   </div>
                 ))}
                 {pendingDocsOrders.length === 0 && <p className="text-xs text-slate-400 italic py-8 text-center">Excellent! No projects pending documents.</p>}
              </div>
           </Card>

           <div className="space-y-6">
              <Card className="p-6">
                 <h3 className="font-black text-slate-900 uppercase tracking-tight mb-4">Financial Health</h3>
                 <div className="space-y-4">
                    <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-100">
                       <div className="flex items-center justify-between mb-1">
                          <span className="text-[10px] font-black text-emerald-700 uppercase">Paid Inflow</span>
                          <CreditCard size={14} className="text-emerald-600" />
                       </div>
                       <p className="text-xl font-black text-emerald-900">Rs. {financialSummary.paid.toLocaleString()}</p>
                    </div>
                    <div className="p-3 rounded-xl bg-rose-50 border border-rose-100">
                       <div className="flex items-center justify-between mb-1">
                          <span className="text-[10px] font-black text-rose-700 uppercase">Outstanding</span>
                          <AlertCircle size={14} className="text-rose-600" />
                       </div>
                       <p className="text-xl font-black text-rose-900">Rs. {financialSummary.pending.toLocaleString()}</p>
                    </div>
                    <div className="pt-2 border-t border-slate-100">
                       <div className="flex items-center justify-between text-xs">
                          <span className="font-bold text-slate-500">Collection Rate</span>
                          <span className="font-black text-slate-900">{((financialSummary.paid / financialSummary.total) * 100).toFixed(1)}%</span>
                       </div>
                       <div className="w-full h-1.5 bg-slate-100 rounded-full mt-2 overflow-hidden">
                          <div className="h-full bg-emerald-500" style={{ width: `${(financialSummary.paid / financialSummary.total) * 100}%` }} />
                       </div>
                    </div>
                 </div>
              </Card>

              <Card className="p-6 bg-slate-900 text-white shadow-xl shadow-slate-200">
                 <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 rounded-2xl bg-white/10 flex items-center justify-center">
                       <Users size={20} className="text-cyan-400" />
                    </div>
                    <div>
                       <h3 className="font-black uppercase tracking-tight text-sm">Team Workload</h3>
                       <p className="text-[9px] text-slate-400 font-bold uppercase tracking-widest">Active Specialists</p>
                    </div>
                 </div>
                 <EmployeeWorkloadChart data={workloadData} />
              </Card>
           </div>
        </div>
        
        <Card className="p-6">
           <div className="flex items-center justify-between mb-6">
              <div>
                 <h3 className="font-black text-slate-900 uppercase tracking-tight">Upcoming Renewals</h3>
                 <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-1">Next 30 Days Projections</p>
              </div>
              <button onClick={() => setActiveTab('Recurring')} className="text-xs font-bold text-indigo-600 hover:underline">Manage All</button>
           </div>
           <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {recurring.filter(r => r.isActive).slice(0, 4).map(r => (
                <div key={r._id} className="flex items-center justify-between p-3 rounded-2xl bg-slate-50/50 border border-slate-100">
                   <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-white shadow-sm flex flex-col items-center justify-center text-indigo-600 border border-indigo-50">
                         <span className="text-[10px] font-black leading-none">{new Date(r.nextRunDate).toLocaleString('default', { month: 'short' })}</span>
                         <span className="text-sm font-black leading-none mt-0.5">{new Date(r.nextRunDate).getDate()}</span>
                      </div>
                      <div>
                         <p className="text-xs font-black text-slate-800 line-clamp-1">{r.serviceName}</p>
                         <p className="text-[10px] text-slate-500 font-medium">{r.clientName}</p>
                      </div>
                   </div>
                   <span className="text-xs font-black text-slate-900">Rs. {Number(r.price || 0).toLocaleString()}</span>
                </div>
              ))}
              {recurring.filter(r => r.isActive).length === 0 && (
                <div className="col-span-full py-8 text-center">
                   <p className="text-xs text-slate-400 italic">No active renewals scheduled</p>
                </div>
              )}
           </div>
        </Card>
      </div>
    );
  };

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
          onDeleteRequirement={deleteRequirement}
          onAddInvoice={addInvoice}
          onUpdateInvoiceStatus={updateInvoiceStatus}
          onOpenRecurringModal={() => setIsMakeRecurringModalOpen(true)}
          orderFilter={orderFilter}
          setOrderFilter={setOrderFilter}
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
    if (activeTab === 'Finance') return <FinanceModule token={userInfo?.token} />;
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
