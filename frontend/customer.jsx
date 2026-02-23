import React, { useState, useEffect } from 'react';
import {
   LayoutDashboard, FileText, CheckSquare, Bell, Search,
   Menu, LogOut, Plus, Download, Upload, CreditCard,
   Briefcase, MessageSquare, User, HelpCircle,
   ChevronRight, AlertTriangle, Building2, FolderOpen
} from 'lucide-react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const getStatusProgress = (status) => {
   switch (status) {
      case 'Pending Documents': return 20;
      case 'Documents Verified': return 40;
      case 'Processing at Portal': return 60;
      case 'Waiting for Clarification': return 70;
      case 'Completed': return 100;
      default: return 0;
   }
};

const StatusBadge = ({ status }) => {
   const styles = {
      'Processing at Portal': 'bg-blue-100 text-blue-700',
      'Waiting for Clarification': 'bg-purple-100 text-purple-700',
      'Completed': 'bg-emerald-100 text-emerald-700',
      'Pending Documents': 'bg-amber-100 text-amber-700',
      'Documents Verified': 'bg-emerald-50 text-emerald-600',
   };
   return <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold ${styles[status] || 'bg-slate-100'}`}>{status}</span>;
};

// --- RECAPTURED COMPONENTS ---
const ProjectTimeline = ({ project }) => {
   const timelineItems = [
      { status: 'Order Placed', date: project.createdAt, done: true },
      { status: 'Payment Received', date: project.invoices?.find(i => i.status === 'Paid')?.updatedAt || project.createdAt, done: project.invoices?.some(i => i.status === 'Paid') },
      { status: 'Documents Verified', date: project.updatedAt, done: ['Documents Verified', 'Processing at Portal', 'Completed'].includes(project.status) },
      { status: 'Processing at Portal', date: project.updatedAt, done: ['Processing at Portal', 'Completed'].includes(project.status) },
      { status: 'Completed', date: project.updatedAt, done: project.status === 'Completed' },
   ];

   return (
      <div className="space-y-4 mt-6">
         <h4 className="text-xs font-black text-slate-400 uppercase tracking-wider">Project Timeline</h4>
         <div className="relative pl-6 space-y-6 before:content-[''] before:absolute before:left-[11px] before:top-2 before:bottom-2 before:w-[2px] before:bg-slate-100">
            {timelineItems.map((item, i) => (
               <div key={i} className="relative">
                  <div className={`absolute -left-[29px] top-1 w-5 h-5 rounded-full border-4 border-white shadow-sm \${item.done ? 'bg-indigo-500' : 'bg-slate-200'}`}></div>
                  <div className="flex justify-between items-start">
                     <div>
                        <p className={`text-sm font-bold \${item.done ? 'text-slate-800' : 'text-slate-400'}`}>{item.status}</p>
                        {item.done && <p className="text-[10px] text-slate-500">{new Date(item.date).toLocaleDateString()}</p>}
                     </div>
                     {item.done && <StatusBadge status="Done" />}
                  </div>
               </div>
            ))}
         </div>
      </div>
   );
};


const DashboardHome = ({ setActiveTab, orders }) => (
   <div className="space-y-6 animate-in fade-in zoom-in duration-300">
      <div className="bg-gradient-to-r from-indigo-600 to-indigo-800 rounded-2xl p-8 text-white flex justify-between items-center shadow-lg">
         <div>
            <h1 className="text-3xl font-bold mb-2">Welcome Back!</h1>
            <p className="text-indigo-100 opacity-90">Here is the status of your active packages.</p>
         </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
         <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
            <div><p className="text-slate-500 text-sm font-medium">Action Required</p><h3 className="text-2xl font-bold text-slate-800">{orders.filter(o => o.status === 'Pending Documents' || o.status === 'Waiting for Clarification').length} Orders</h3></div>
            <div className="p-3 bg-amber-50 text-amber-600 rounded-lg"><Upload size={24} /></div>
         </div>
         <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
            <div><p className="text-slate-500 text-sm font-medium">Active Services</p><h3 className="text-2xl font-bold text-slate-800">{orders.filter(o => o.status !== 'Completed').length} Projects</h3></div>
            <div className="p-3 bg-blue-50 text-blue-600 rounded-lg"><Briefcase size={24} /></div>
         </div>
         <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
            <div><p className="text-slate-500 text-sm font-medium">Total Paid</p><h3 className="text-2xl font-bold text-slate-800">₹ {orders.reduce((acc, curr) => acc + curr.price, 0).toLocaleString()}</h3></div>
            <div className="p-3 bg-emerald-50 text-emerald-600 rounded-lg"><CreditCard size={24} /></div>
         </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
         <div className="lg:col-span-2 bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-5 border-b border-slate-100 flex justify-between items-center">
               <h3 className="font-bold text-slate-800">Your Packages</h3>
               <button onClick={() => setActiveTab('Projects')} className="text-sm text-indigo-600 font-medium hover:underline">View All</button>
            </div>
            <div className="divide-y divide-slate-100">
               {orders.slice(0, 5).map(proj => (
                  <div key={proj._id} className="p-5 hover:bg-slate-50 transition-colors">
                     <div className="flex justify-between items-start mb-2">
                        <div>
                           <h4 className="font-bold text-slate-700">{proj.serviceName}</h4>
                           <p className="text-xs text-slate-500">{proj.packageName} • Paid: ₹{proj.price.toLocaleString()}</p>
                        </div>
                        <StatusBadge status={proj.status} />
                     </div>
                     <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden">
                        <div className="h-full bg-indigo-500 rounded-full transition-all duration-500" style={{ width: `${getStatusProgress(proj.status)}%` }}></div>
                     </div>
                     <div className="flex justify-between mt-2 text-xs text-slate-400">
                        <span>Progress: {getStatusProgress(proj.status)}%</span>
                     </div>
                  </div>
               ))}
               {orders.length === 0 && <p className="p-5 text-center text-slate-500">No orders found.</p>}
            </div>
         </div>

         <div className="bg-white rounded-xl border border-slate-200 shadow-sm h-fit">
            <div className="p-5 border-b border-slate-100">
               <h3 className="font-bold text-slate-800 flex items-center text-amber-600"><AlertTriangle size={18} className="mr-2" /> Required Actions</h3>
            </div>
            <div className="p-5 space-y-4">
               {orders.filter(o => o.status === 'Pending Documents').map(doc => (
                  <div key={doc._id} className="bg-amber-50 border border-amber-100 p-4 rounded-xl">
                     <p className="text-sm font-bold text-slate-700 mb-1">{doc.serviceName}</p>
                     <p className="text-xs text-slate-500 mb-3">Documents Required</p>
                     <button onClick={() => setActiveTab('Documents')} className="w-full py-2 bg-white border border-amber-200 text-amber-700 text-xs font-bold rounded-lg hover:bg-amber-100 transition-colors flex items-center justify-center">
                        <Upload size={14} className="mr-2" /> Go to Documents
                     </button>
                  </div>
               ))}
               {orders.filter(o => o.status === 'Pending Documents').length === 0 && <p className="text-center text-slate-400 text-sm py-4">All caught up!</p>}
            </div>
         </div>
      </div>
   </div>
);

const DocumentVault = ({ orders, refreshOrders }) => {
   const [activeOrder, setActiveOrder] = useState(orders[0]?._id || '');
   const [file, setFile] = useState(null);
   const [isUploading, setIsUploading] = useState(false);

   const handleUpload = async (e) => {
      e.preventDefault();
      if (!file || !activeOrder) return;

      const userInfo = JSON.parse(localStorage.getItem('userInfo'));
      const formData = new FormData();
      formData.append('document', file);

      setIsUploading(true);
      try {
         await axios.post(`/api/orders/${activeOrder}/documents`, formData, {
            headers: {
               'Content-Type': 'multipart/form-data',
               Authorization: `Bearer ${userInfo.token}`
            }
         });
         alert('Document uploaded successfully!');
         setFile(null);
         refreshOrders();
      } catch (error) {
         console.error(error);
         alert('Error uploading document');
      }
      setIsUploading(false);
   };

   return (
      <div className="space-y-6 animate-in fade-in zoom-in duration-300">
         <div className="flex justify-between items-center">
            <div><h2 className="text-2xl font-bold text-slate-800">Document Vault</h2><p className="text-slate-500">Upload requirements and download final certificates.</p></div>
         </div>

         <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 overflow-hidden">

            <div className="mb-6">
               <label className="block text-sm font-bold text-slate-700 mb-2">Select Project / Order</label>
               <select value={activeOrder} onChange={e => setActiveOrder(e.target.value)} className="w-full p-3 border border-slate-200 rounded-lg bg-slate-50">
                  {orders.map(o => (
                     <option key={o._id} value={o._id}>{o.serviceName} - {o.packageName} ({o.status})</option>
                  ))}
               </select>
            </div>

            {activeOrder && (
               <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                  <div className="border border-slate-200 rounded-xl p-6 bg-slate-50">
                     <h3 className="font-bold text-lg mb-4 text-slate-800"><Upload className="inline mr-2 text-indigo-600" />Upload Required Document</h3>
                     <form onSubmit={handleUpload}>
                        <input type="file" onChange={(e) => setFile(e.target.files[0])} className="w-full mb-4 text-sm" required />
                        <button type="submit" disabled={isUploading || !file} className="bg-indigo-600 text-white px-4 py-2 rounded-lg font-bold hover:bg-indigo-700 transition disabled:opacity-50">
                           {isUploading ? 'Uploading...' : 'Upload File'}
                        </button>
                     </form>
                  </div>

                  <div className="border border-slate-200 rounded-xl p-6">
                     <h3 className="font-bold text-lg mb-4 text-slate-800"><FileText className="inline mr-2 text-indigo-600" />Uploaded Files</h3>
                     {orders.find(o => o._id === activeOrder)?.clientDocuments?.map(doc => (
                        <div key={doc._id} className="flex justify-between items-center bg-slate-50 p-3 rounded-lg border border-slate-100 mb-2">
                           <span className="text-sm text-slate-600 font-medium truncate pr-4">{doc.name}</span>
                           <a href={`http://localhost:5000${doc.url}`} target="_blank" rel="noreferrer" className="text-indigo-600 hover:text-indigo-800"><Download size={18} /></a>
                        </div>
                     ))}
                     {orders.find(o => o._id === activeOrder)?.clientDocuments?.length === 0 && <p className="text-sm text-slate-400">No documents uploaded yet.</p>}

                     {orders.find(o => o._id === activeOrder)?.finalCertificateUrl && (
                        <div className="mt-4 pt-4 border-t border-slate-200">
                           <h4 className="font-bold text-emerald-600 mb-2">Final Certificate Ready!</h4>
                           <a href={`http://localhost:5000${orders.find(o => o._id === activeOrder).finalCertificateUrl}`} target="_blank" rel="noreferrer" className="flex items-center text-sm bg-emerald-50 text-emerald-700 px-4 py-2 rounded-lg font-bold border border-emerald-200 hover:bg-emerald-100">
                              <Download size={16} className="mr-2" /> Download Final Certificate
                           </a>
                        </div>
                     )}
                  </div>
               </div>
            )}
            {orders.length === 0 && <p className="text-slate-500 text-center py-10">No active projects to upload documents for.</p>}

         </div>
      </div>
   );
};


// --- MAIN CUSTOMER APP ---
export default function CustomerApp() {
   const [activeTab, setActiveTab] = useState('Dashboard');
   const [sidebarCollapsed, setSidebarCollapsed] = useState(true);
   const [isLoggedIn, setIsLoggedIn] = useState(false);
   const [userInfo, setUserInfo] = useState(null);
   const [orders, setOrders] = useState([]);
   const [notifications, setNotifications] = useState([]);
   const [showNotifications, setShowNotifications] = useState(false);
   const navigate = useNavigate();


   useEffect(() => {
      const user = localStorage.getItem('userInfo');
      if (user) {
         setUserInfo(JSON.parse(user));
         setIsLoggedIn(true);
      } else {
         navigate('/'); // Use root login
      }
   }, [navigate]);

   const fetchOrders = async () => {
      if (!userInfo) return;
      try {
         const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
         const { data } = await axios.get('/api/orders', config);
         setOrders(data);

         // derive notifications
         const newNotes = [];
         data.forEach(o => {
            if (o.status !== 'Pending Documents') {
               newNotes.push({ id: o._id + o.status, title: 'Status Update', text: `Project "${o.serviceName}" is now ${o.status}`, date: o.updatedAt });
            }
            o.invoices?.forEach(inv => {
               if (inv.status === 'Paid') {
                  newNotes.push({ id: inv._id, title: 'Invoice Paid', text: `Invoice ${inv.invoiceNumber} for ₹${inv.amount} has been verified as Paid.`, date: inv.updatedAt });
               }
            });
         });
         setNotifications(newNotes.sort((a, b) => new Date(b.date) - new Date(a.date)).slice(0, 10));
      } catch (error) {
         console.error("Failed to fetch orders:");
      }
   };


   useEffect(() => {
      if (userInfo) {
         fetchOrders();
      }
   }, [userInfo]);

   const handleLogout = () => {
      localStorage.removeItem('userInfo');
      navigate('/login');
   };

   if (!isLoggedIn) {
      return <div className="min-h-screen bg-slate-50 flex items-center justify-center p-4">Loading...</div>;
   }

   return (
      <div className="flex h-screen bg-slate-50 font-sans text-slate-800 overflow-hidden">
         {/* Sidebar */}
         <aside className={`\${sidebarCollapsed ? 'w-20' : 'w-64'} bg-white h-full border-r border-slate-200 flex flex-col z-20 transition-all duration-300`} onMouseEnter={() => setSidebarCollapsed(false)} onMouseLeave={() => setSidebarCollapsed(true)}>
            <div className="h-20 flex items-center justify-center border-b border-slate-100"><div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center text-white font-bold text-lg shadow-lg">VR</div></div>
            <div className="flex-1 py-6 px-3 space-y-1">
               {['Dashboard', 'Projects', 'Documents', 'Support'].map(item => (
                  <button key={item} onClick={() => setActiveTab(item)} className={`flex items-center w-full p-3 rounded-xl transition-all ${activeTab === item ? 'bg-indigo-50 text-indigo-600 font-bold' : 'text-slate-500 hover:bg-slate-50'}`}>
                     <div className="shrink-0">
                        {item === 'Dashboard' ? <LayoutDashboard size={20} /> : item === 'Projects' ? <CheckSquare size={20} /> : item === 'Documents' ? <FileText size={20} /> : item === 'Support' ? <HelpCircle size={20} /> : <Plus size={20} />}
                     </div>
                     <span className={`ml-3 whitespace-nowrap transition-all duration-300 ${sidebarCollapsed ? 'opacity-0 w-0 overflow-hidden' : 'opacity-100'}`}>{item}</span>
                  </button>
               ))}
            </div>
            <div className="p-4 border-t border-slate-100"><button onClick={handleLogout} className="flex items-center w-full p-2 rounded-lg text-rose-500 hover:bg-rose-50"><LogOut size={20} /><span className={`ml-3 text-sm transition-all duration-300 ${sidebarCollapsed ? 'opacity-0' : 'opacity-100'}`}>Logout</span></button></div>
         </aside>

         {/* Main Content */}
         <main className="flex-1 flex flex-col h-full overflow-hidden relative">
            <header className="h-16 bg-white/80 backdrop-blur-md border-b border-slate-200 flex items-center justify-between px-8 sticky top-0 z-10">
               <h1 className="text-xl font-bold text-slate-800">{activeTab}</h1>
               <div className="flex items-center gap-4">
                  <button className="p-2 text-slate-400 hover:text-indigo-600 relative"><Bell size={20} /></button>
                  <div className="w-8 h-8 rounded-full bg-indigo-100 border border-indigo-200 shadow-sm flex items-center justify-center text-xs font-bold text-indigo-700">
                     {userInfo.name.charAt(0).toUpperCase()}
                  </div>
               </div>
            </header>

            <div className="flex-1 overflow-y-auto p-4 md:p-8">
               {activeTab === 'Dashboard' && <DashboardHome setActiveTab={setActiveTab} orders={orders} />}
               {activeTab === 'Documents' && <DocumentVault orders={orders} refreshOrders={fetchOrders} />}
               {activeTab === 'Projects' && (
                  <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 animate-in fade-in">
                     {orders.map(proj => (
                        <div key={proj._id} className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm flex flex-col">
                           <div className="flex justify-between items-start mb-6">
                              <div>
                                 <h3 className="font-bold text-xl text-slate-800">{proj.serviceName}</h3>
                                 <p className="text-sm text-slate-500">{proj.packageName} • ID: {proj._id.slice(-6).toUpperCase()}</p>
                              </div>
                              <StatusBadge status={proj.status} />
                           </div>

                           <div className="flex-1 space-y-6">
                              <div>
                                 <div className="flex justify-between mb-2 text-xs font-bold text-slate-500">
                                    <span>Completion Progress</span>
                                    <span>{getStatusProgress(proj.status)}%</span>
                                 </div>
                                 <div className="w-full h-2.5 bg-slate-100 rounded-full overflow-hidden mb-2">
                                    <div className="h-full bg-indigo-500 transition-all duration-700 shadow-[0_0_10px_rgba(99,102,241,0.5)]" style={{ width: `${getStatusProgress(proj.status)}%` }}></div>
                                 </div>
                              </div>

                              <div className="grid grid-cols-2 gap-4">
                                 <div className="p-4 bg-slate-50 rounded-xl border border-slate-100">
                                    <p className="text-[10px] font-black text-slate-400 uppercase mb-1">Total Fee</p>
                                    <p className="text-lg font-black text-slate-800">₹ {proj.price.toLocaleString()}</p>
                                 </div>
                                 <div className="p-4 bg-slate-50 rounded-xl border border-slate-100">
                                    <p className="text-[10px] font-black text-slate-400 uppercase mb-1">Payment</p>
                                    <p className={`text-sm font-bold \${proj.status === 'Pending Documents' ? 'text-amber-600' : 'text-emerald-600'}`}>
                                       {proj.invoices?.some(i => i.status === 'Paid') ? 'Verified' : 'Initial Paid'}
                                    </p>
                                 </div>
                              </div>

                              <ProjectTimeline project={proj} />

                              {proj.invoices?.length > 0 && (
                                 <div className="pt-4 border-t border-slate-100">
                                    <h4 className="text-xs font-black text-slate-400 uppercase tracking-wider mb-3">Invoices</h4>
                                    <div className="space-y-2">
                                       {proj.invoices.map(inv => (
                                          <div key={inv._id} className="flex justify-between items-center p-3 bg-indigo-50/30 rounded-lg border border-indigo-100/50 hover:bg-indigo-50 transition-colors">
                                             <div className="flex items-center gap-3">
                                                <div className="p-2 bg-white rounded shadow-sm text-indigo-600"><FileText size={14} /></div>
                                                <div>
                                                   <p className="text-xs font-bold text-slate-800">{inv.invoiceNumber}</p>
                                                   <p className="text-[10px] text-slate-500">₹ {inv.amount.toLocaleString()}</p>
                                                </div>
                                             </div>
                                             <div className="flex items-center gap-3">
                                                <StatusBadge status={inv.status} />
                                                <button className="p-1.5 hover:bg-white rounded text-indigo-600"><Download size={14} /></button>
                                             </div>
                                          </div>
                                       ))}
                                    </div>
                                 </div>
                              )}
                           </div>
                        </div>
                     ))}
                     {orders.length === 0 && <p className="text-slate-500 text-center py-10 col-span-full">You have no active projects.</p>}
                  </div>
               )}

               {activeTab === 'Support' && <div className="flex h-full items-center justify-center text-slate-400 flex-col"><MessageSquare size={48} className="mb-4 opacity-20" /><p>Support Chat / Ticket System</p></div>}
            </div>
         </main>
      </div>
   );
}