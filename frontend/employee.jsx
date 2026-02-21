import React, { useState, useEffect } from 'react';
import {
  LayoutDashboard, CheckSquare, Clock, Calendar, Settings, Bell, Search,
  Menu, LogOut, Play, Square, Pause, ChevronRight, AlertCircle,
  Coffee, Briefcase, FileText, User, Filter, ArrowRight, Layers,
  ChevronDown as ChevronDownIcon, ChevronRight as ChevronRightIcon,
  MoreVertical, ArrowDownRight, Building2, Plus, Globe, Scale, Factory, Upload, Download, CheckCircle
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
  return <span className={`px-3 py-1 rounded-full text-xs font-bold ${styles[status] || 'bg-slate-100 text-slate-600'}`}>{status}</span>;
};

const ORDER_STATUSES = ['Pending Documents', 'Documents Verified', 'Processing at Portal', 'Waiting for Clarification', 'Completed'];

// --- MAIN EMPLOYEE APP ---
export default function EmployeeApp() {
  const [activeTab, setActiveTab] = useState('Dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [userInfo, setUserInfo] = useState(null);
  const [orders, setOrders] = useState([]);
  const [selectedOrder, setSelectedOrder] = useState(null);
  const [file, setFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const user = localStorage.getItem('userInfo');
    if (user) {
      const parsed = JSON.parse(user);
      if (parsed.role === 'employee' || parsed.role === 'admin') {
        setUserInfo(parsed);
        setIsLoggedIn(true);
      } else {
        alert("Access Denied. Employee only.");
        navigate('/');
      }
    } else {
      navigate('/');
    }
  }, [navigate]);

  const fetchOrders = async () => {
    if (!userInfo) return;
    try {
      const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
      const { data } = await axios.get('/api/orders', config);
      setOrders(data);
    } catch (error) {
      console.error("Failed to fetch orders:");
    }
  };

  useEffect(() => {
    if (userInfo) fetchOrders();
  }, [userInfo]);

  const handleStatusChange = async (orderId, newStatus) => {
    try {
      const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
      await axios.put(`/api/orders/${orderId}/status`, { status: newStatus }, config);
      fetchOrders();
      if (selectedOrder?._id === orderId) {
        setSelectedOrder(prev => ({ ...prev, status: newStatus }));
      }
    } catch (e) { alert("Error updating status"); }
  };

  const handleUploadCertificate = async (e) => {
    e.preventDefault();
    if (!file || !selectedOrder) return;

    const formData = new FormData();
    formData.append('document', file);

    setIsUploading(true);
    try {
      await axios.post(`/api/orders/${selectedOrder._id}/documents`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          Authorization: `Bearer ${userInfo.token}`
        }
      });
      alert('Final Certificate uploaded successfully! Order is now Complete.');
      setFile(null);
      setSelectedOrder(null);
      fetchOrders();
    } catch (error) {
      console.error(error);
      alert('Error uploading document');
    }
    setIsUploading(false);
  };

  const handleLogout = () => {
    localStorage.removeItem('userInfo');
    navigate('/');
  };

  if (!isLoggedIn) return <div className="min-h-screen flex items-center justify-center bg-slate-900 text-white font-bold">Verifying Access...</div>;

  // --- VIEWS ---

  const DashboardView = () => (
    <div className="space-y-6 animate-in fade-in">
      <div className="bg-slate-900 rounded-3xl p-8 text-white flex justify-between items-center shadow-lg">
        <div>
          <h2 className="text-3xl font-bold mb-2">Welcome, {userInfo.name}</h2>
          <p className="text-slate-400">You have {orders.filter(o => o.status !== 'Completed').length} active assignments.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
          <p className="text-sm font-bold text-slate-500 mb-1">Total Assigned</p>
          <h3 className="text-3xl font-black text-slate-800">{orders.length}</h3>
        </div>
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
          <p className="text-sm font-bold text-amber-500 mb-1">Pending Documents</p>
          <h3 className="text-3xl font-black text-amber-600">{orders.filter(o => o.status === 'Pending Documents').length}</h3>
        </div>
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
          <p className="text-sm font-bold text-emerald-500 mb-1">Completed</p>
          <h3 className="text-3xl font-black text-emerald-600">{orders.filter(o => o.status === 'Completed').length}</h3>
        </div>
      </div>

      <h3 className="font-bold text-xl text-slate-800 mt-8 mb-4">Recent Assignments</h3>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {orders.slice(0, 4).map(order => (
          <div key={order._id} className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm flex flex-col justify-between">
            <div className="flex justify-between items-start mb-4">
              <div>
                <h4 className="font-bold text-lg text-slate-800">{order.serviceName}</h4>
                <p className="text-sm text-slate-500">Client: {order.user?.name || 'Unknown'}</p>
              </div>
              <StatusBadge status={order.status} />
            </div>
            <button onClick={() => { setSelectedOrder(order); setActiveTab('Workspace'); }} className="mt-4 w-full py-2 bg-indigo-50 text-indigo-700 font-bold rounded-lg hover:bg-indigo-100 transition">
              Open Workspace
            </button>
          </div>
        ))}
        {orders.length === 0 && <p className="text-slate-500 p-4 border rounded-xl border-dashed border-slate-300">No recent assignments.</p>}
      </div>
    </div>
  );

  const WorkspaceView = () => (
    <div className="space-y-6 animate-in fade-in">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-bold text-slate-800">Order Workspace</h2>
        {selectedOrder && <button onClick={() => setSelectedOrder(null)} className="text-indigo-600 font-bold hover:underline">Back to List</button>}
      </div>

      {!selectedOrder ? (
        <div className="bg-white rounded-2xl shadow-sm border border-slate-200 p-6">
          <table className="w-full text-left">
            <thead className="bg-slate-50 text-xs uppercase font-bold text-slate-500">
              <tr>
                <th className="p-4 rounded-tl-lg">Client</th>
                <th className="p-4">Service</th>
                <th className="p-4">Status</th>
                <th className="p-4 rounded-tr-lg">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {orders.map(order => (
                <tr key={order._id} className="hover:bg-slate-50 transition">
                  <td className="p-4 font-bold text-slate-700">{order.user?.name}</td>
                  <td className="p-4 text-slate-600">{order.serviceName} <span className="text-xs text-slate-400 block">{order.packageName}</span></td>
                  <td className="p-4"><StatusBadge status={order.status} /></td>
                  <td className="p-4">
                    <button onClick={() => setSelectedOrder(order)} className="text-indigo-600 font-bold bg-indigo-50 px-3 py-1.5 rounded hover:bg-indigo-100">Work</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {orders.length === 0 && <p className="text-center text-slate-500 py-8">No assigned orders.</p>}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Col: Details & Status */}
          <div className="lg:col-span-1 space-y-6">
            <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-200">
              <h3 className="font-bold text-lg mb-4 text-slate-800">Order Details</h3>
              <div className="space-y-3 text-sm">
                <div><span className="text-slate-500">Client:</span> <span className="font-bold float-right">{selectedOrder.user?.name}</span></div>
                <div><span className="text-slate-500">Service:</span> <span className="font-bold float-right">{selectedOrder.serviceName}</span></div>
                <div><span className="text-slate-500">Package:</span> <span className="font-bold float-right">{selectedOrder.packageName}</span></div>
                <div><span className="text-slate-500">Date:</span> <span className="font-bold float-right">{new Date(selectedOrder.createdAt).toLocaleDateString()}</span></div>
              </div>
            </div>

            <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-200">
              <h3 className="font-bold text-lg mb-4 text-slate-800">Update Status</h3>
              <select
                value={selectedOrder.status}
                onChange={(e) => handleStatusChange(selectedOrder._id, e.target.value)}
                className="w-full p-3 border border-slate-300 rounded-lg bg-slate-50 font-medium text-slate-700 focus:ring-2 focus:ring-indigo-500 outline-none"
              >
                {ORDER_STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <p className="text-xs text-slate-400 mt-2">Updates immediately reflect on client dashboard.</p>
            </div>
          </div>

          {/* Right Col: Documents & Completion */}
          <div className="lg:col-span-2 space-y-6">
            <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-200">
              <h3 className="font-bold text-lg mb-4 text-slate-800 flex items-center"><FileText className="mr-2 text-indigo-600" /> Client Uploaded Documents</h3>
              <div className="space-y-2">
                {selectedOrder.clientDocuments?.map(doc => (
                  <div key={doc._id} className="flex justify-between items-center bg-slate-50 p-4 rounded-xl border border-slate-100">
                    <span className="font-medium text-slate-700">{doc.name}</span>
                    <a href={`http://localhost:5000${doc.url}`} target="_blank" rel="noreferrer" className="flex items-center text-indigo-600 hover:text-indigo-800 bg-indigo-50 px-3 py-1.5 rounded-lg text-sm font-bold">
                      <Download size={16} className="mr-2" /> Download
                    </a>
                  </div>
                ))}
                {(!selectedOrder.clientDocuments || selectedOrder.clientDocuments.length === 0) && (
                  <div className="p-8 border-2 border-dashed border-slate-200 rounded-xl text-center text-slate-500">
                    Client hasn't uploaded any documents yet.
                  </div>
                )}
              </div>
            </div>

            <div className="bg-emerald-50 p-6 rounded-2xl border border-emerald-200">
              <h3 className="font-bold text-lg mb-4 text-emerald-800 flex items-center"><CheckCircle className="mr-2" /> Complete Project (Upload Final Certificate)</h3>

              {selectedOrder.finalCertificateUrl ? (
                <div className="bg-white p-4 rounded-xl border border-emerald-100 flex justify-between items-center">
                  <span className="font-bold text-emerald-700">Certificate Uploaded</span>
                  <a href={`http://localhost:5000${selectedOrder.finalCertificateUrl}`} target="_blank" rel="noreferrer" className="text-emerald-700 hover:underline text-sm font-bold">View Certificate</a>
                </div>
              ) : (
                <form onSubmit={handleUploadCertificate} className="bg-white p-4 rounded-xl border border-emerald-100">
                  <p className="text-sm text-slate-600 mb-3">Uploading the final certificate will automatically mark this order as Completed.</p>
                  <input type="file" onChange={(e) => setFile(e.target.files[0])} className="w-full mb-4 text-sm file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-semibold file:bg-emerald-50 file:text-emerald-700 hover:file:bg-emerald-100" required />
                  <button type="submit" disabled={isUploading || !file} className="bg-emerald-600 text-white px-4 py-2 rounded-lg font-bold hover:bg-emerald-700 transition disabled:opacity-50 w-full flex justify-center items-center">
                    {isUploading ? 'Uploading...' : <><Upload size={18} className="mr-2" /> Upload & Complete</>}
                  </button>
                </form>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );

  return (
    <div className="flex h-screen bg-slate-50 font-sans text-slate-800 overflow-hidden">
      <aside className={`\${sidebarCollapsed ? 'w-20' : 'w-64'} bg-white h-full border-r border-slate-200 flex flex-col z-20 transition-all duration-300`} onMouseEnter={() => setSidebarCollapsed(false)} onMouseLeave={() => setSidebarCollapsed(true)}>
        <div className="h-20 flex items-center justify-center border-b border-slate-100"><div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center text-white font-bold text-lg shadow-lg">VR</div></div>
        <div className="flex-1 py-6 px-3 space-y-1">
          {['Dashboard', 'Workspace'].map(item => (
            <button key={item} onClick={() => setActiveTab(item)} className={`flex items-center w-full p-3 rounded-xl transition-all ${activeTab === item ? 'bg-indigo-50 text-indigo-600 font-bold' : 'text-slate-500 hover:bg-slate-50'}`}>
              <div className="shrink-0">{item === 'Workspace' ? <Layers size={20} /> : <LayoutDashboard size={20} />}</div>
              <span className={`ml-3 whitespace-nowrap transition-all duration-300 ${sidebarCollapsed ? 'opacity-0 w-0 overflow-hidden' : 'opacity-100'}`}>{item}</span>
            </button>
          ))}
        </div>
        <div className="p-4 border-t border-slate-100"><button onClick={handleLogout} className="flex items-center w-full p-2 rounded-lg text-rose-500 hover:bg-rose-50"><LogOut size={20} /><span className={`ml-3 text-sm transition-all duration-300 ${sidebarCollapsed ? 'opacity-0' : 'opacity-100'}`}>Logout</span></button></div>
      </aside>
      <main className="flex-1 flex flex-col h-full overflow-hidden relative">
        <header className="h-16 bg-white/80 backdrop-blur-md border-b border-slate-200 flex items-center justify-between px-8 sticky top-0 z-10">
          <h1 className="text-xl font-bold text-slate-800">{activeTab}</h1>
          <div className="flex items-center gap-4">
            <div className="w-8 h-8 rounded-full bg-indigo-100 text-indigo-700 flex items-center justify-center font-bold text-xs">{userInfo.name.charAt(0)}</div>
          </div>
        </header>
        <div className="flex-1 overflow-y-auto p-8">
          {activeTab === 'Dashboard' && <DashboardView />}
          {activeTab === 'Workspace' && <WorkspaceView />}
        </div>
      </main>
    </div>
  );
}