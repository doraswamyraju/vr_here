import React, { useState } from 'react';
import { 
  LayoutDashboard, FileText, CheckSquare, Bell, Search, 
  Menu, LogOut, Plus, Download, Upload, CreditCard, 
  Briefcase, MessageSquare, User, HelpCircle, 
  ChevronRight, Clock, AlertTriangle, CheckCircle2,
  FileCheck, History, DollarSign, PieChart as PieIcon,
  Building2, FolderOpen
} from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

// --- MOCK DATA ---
const CUSTOMER_PROFILE = {
  name: 'TechFlow Solutions',
  contact: 'Rajesh Kumar (Director)',
  email: 'rajesh@techflow.com',
  type: 'Pvt Ltd Company'
};

const ACTIVE_PACKAGES = [
  { id: 1, title: 'Private Limited Registration', plan: 'Startup Plan', status: 'In Progress', progress: 40, amountPaid: 6999, pendingAction: 'Upload Documents' },
  { id: 2, title: 'GST Registration', plan: 'Standard', status: 'Review', progress: 90, amountPaid: 1499, pendingAction: 'None' },
];

const PENDING_DOCUMENTS = [
  { id: 1, name: 'PAN Card (All Directors)', requestDate: '16 Dec 2025', status: 'Pending', project: 'Pvt Ltd Registration' },
  { id: 2, name: 'Aadhaar Card / Voter ID', requestDate: '16 Dec 2025', status: 'Pending', project: 'Pvt Ltd Registration' },
  { id: 3, name: 'Passport Size Photo', requestDate: '16 Dec 2025', status: 'Pending', project: 'Pvt Ltd Registration' },
  { id: 4, name: 'Bank Statement / Electricity Bill', requestDate: '16 Dec 2025', status: 'Pending', project: 'Pvt Ltd Registration' }
];

const INVOICES = [
  { id: 'INV-25-001', date: '16 Dec 2025', service: 'Pvt Ltd Registration - Startup Plan', amount: 6999, status: 'Paid' },
];

const SERVICE_CATALOG_SHORT = [
  { title: 'Certification', desc: 'Net Worth, Turnover, Visa Certificates' },
  { title: 'New Registration', desc: 'GST, MSME, IEC, Trademark' },
  { title: 'Consultancy', desc: 'Project Reports, Loan Assistance' },
];

// --- COMPONENTS ---

const StatusBadge = ({ status }) => {
  const styles = {
    'In Progress': 'bg-blue-100 text-blue-700',
    'Review': 'bg-purple-100 text-purple-700',
    'Completed': 'bg-emerald-100 text-emerald-700',
    'Pending': 'bg-amber-100 text-amber-700',
    'Paid': 'bg-emerald-100 text-emerald-700',
    'Unpaid': 'bg-rose-100 text-rose-700',
  };
  return <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold ${styles[status] || 'bg-slate-100'}`}>{status}</span>;
};

// 1. DASHBOARD HOME
const DashboardHome = ({ setActiveTab }) => (
  <div className="space-y-6 animate-in fade-in zoom-in duration-300">
    {/* Welcome Banner */}
    <div className="bg-gradient-to-r from-indigo-600 to-indigo-800 rounded-2xl p-8 text-white flex justify-between items-center shadow-lg">
      <div>
        <h1 className="text-3xl font-bold mb-2">Welcome, {CUSTOMER_PROFILE.contact}</h1>
        <p className="text-indigo-100 opacity-90">Here is the status of your active packages.</p>
      </div>
      <div className="hidden md:block">
        <div className="bg-white/10 backdrop-blur-sm p-4 rounded-xl border border-white/20 text-center">
           <p className="text-xs font-bold uppercase tracking-wider mb-1">Active Plan</p>
           <p className="text-xl font-bold">Startup</p>
           <p className="text-xs opacity-75">Pvt Ltd Reg</p>
        </div>
      </div>
    </div>

    {/* Quick Stats Grid */}
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
       <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
          <div><p className="text-slate-500 text-sm font-medium">Pending Actions</p><h3 className="text-2xl font-bold text-slate-800">{PENDING_DOCUMENTS.length} Docs</h3></div>
          <div className="p-3 bg-amber-50 text-amber-600 rounded-lg"><Upload size={24}/></div>
       </div>
       <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
          <div><p className="text-slate-500 text-sm font-medium">Active Services</p><h3 className="text-2xl font-bold text-slate-800">{ACTIVE_PACKAGES.filter(p => p.status !== 'Completed').length} Projects</h3></div>
          <div className="p-3 bg-blue-50 text-blue-600 rounded-lg"><Briefcase size={24}/></div>
       </div>
       <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
          <div><p className="text-slate-500 text-sm font-medium">Total Paid</p><h3 className="text-2xl font-bold text-slate-800">₹ 8,498</h3></div>
          <div className="p-3 bg-emerald-50 text-emerald-600 rounded-lg"><CreditCard size={24}/></div>
       </div>
    </div>

    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
       {/* Active Projects List */}
       <div className="lg:col-span-2 bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
          <div className="p-5 border-b border-slate-100 flex justify-between items-center">
             <h3 className="font-bold text-slate-800">Your Active Packages</h3>
             <button onClick={() => setActiveTab('Projects')} className="text-sm text-indigo-600 font-medium hover:underline">View All</button>
          </div>
          <div className="divide-y divide-slate-100">
             {ACTIVE_PACKAGES.map(proj => (
                <div key={proj.id} className="p-5 hover:bg-slate-50 transition-colors">
                   <div className="flex justify-between items-start mb-2">
                      <div>
                         <h4 className="font-bold text-slate-700">{proj.title}</h4>
                         <p className="text-xs text-slate-500">{proj.plan} • Paid: ₹{proj.amountPaid}</p>
                      </div>
                      <StatusBadge status={proj.status}/>
                   </div>
                   <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden">
                      <div className="h-full bg-indigo-500 rounded-full transition-all duration-500" style={{width: `${proj.progress}%`}}></div>
                   </div>
                   <div className="flex justify-between mt-2 text-xs text-slate-400">
                      <span>Progress: {proj.progress}%</span>
                      <span className="text-amber-600 font-semibold">Action: {proj.pendingAction}</span>
                   </div>
                </div>
             ))}
          </div>
       </div>

       {/* Pending Documents (Action Required) */}
       <div className="bg-white rounded-xl border border-slate-200 shadow-sm h-fit">
          <div className="p-5 border-b border-slate-100">
             <h3 className="font-bold text-slate-800 flex items-center text-amber-600"><AlertTriangle size={18} className="mr-2"/> Required Documents</h3>
          </div>
          <div className="p-5 space-y-4">
             {PENDING_DOCUMENTS.map(doc => (
                <div key={doc.id} className="bg-amber-50 border border-amber-100 p-4 rounded-xl">
                   <p className="text-sm font-bold text-slate-700 mb-1">{doc.name}</p>
                   <p className="text-xs text-slate-500 mb-3">For: {doc.project}</p>
                   <button className="w-full py-2 bg-white border border-amber-200 text-amber-700 text-xs font-bold rounded-lg hover:bg-amber-100 transition-colors flex items-center justify-center">
                      <Upload size={14} className="mr-2"/> Upload File
                   </button>
                </div>
             ))}
             {PENDING_DOCUMENTS.length === 0 && <p className="text-center text-slate-400 text-sm py-4">No pending documents!</p>}
          </div>
       </div>
    </div>
  </div>
);

// 2. DOCUMENT VAULT
const DocumentVault = () => {
  const [tab, setTab] = useState('Requested');
  return (
    <div className="space-y-6 animate-in fade-in zoom-in duration-300">
       <div className="flex justify-between items-center">
          <div><h2 className="text-2xl font-bold text-slate-800">Document Vault</h2><p className="text-slate-500">Securely share files with your auditor.</p></div>
          <button className="bg-indigo-600 text-white px-4 py-2 rounded-xl text-sm font-bold flex items-center shadow-lg"><Upload size={16} className="mr-2"/> Upload General Doc</button>
       </div>

       <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden min-h-[400px]">
          <div className="flex border-b border-slate-100">
             {['Requested by Firm', 'My Uploads', 'Filed Returns'].map(t => (
                <button key={t} onClick={() => setTab(t.split(' ')[0])} className={`px-6 py-4 text-sm font-bold border-b-2 transition-all ${tab === t.split(' ')[0] ? 'border-indigo-600 text-indigo-600 bg-indigo-50/50' : 'border-transparent text-slate-500 hover:text-slate-700'}`}>{t}</button>
             ))}
          </div>
          
          <div className="p-6">
             {tab === 'Requested' && (
                <table className="w-full text-left">
                   <thead className="text-xs font-bold text-slate-400 uppercase bg-slate-50 border-b border-slate-100">
                      <tr><th className="px-4 py-3">Document Name</th><th className="px-4 py-3">Project</th><th className="px-4 py-3">Requested On</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Action</th></tr>
                   </thead>
                   <tbody className="divide-y divide-slate-100 text-sm">
                      {PENDING_DOCUMENTS.map(doc => (
                         <tr key={doc.id} className="hover:bg-slate-50">
                            <td className="px-4 py-3 font-medium text-slate-700">{doc.name}</td>
                            <td className="px-4 py-3 text-slate-500">{doc.project}</td>
                            <td className="px-4 py-3 text-slate-500">{doc.requestDate}</td>
                            <td className="px-4 py-3"><span className="bg-amber-100 text-amber-700 px-2 py-1 rounded text-xs font-bold">Pending</span></td>
                            <td className="px-4 py-3"><button className="text-indigo-600 hover:underline font-medium text-xs">Upload</button></td>
                         </tr>
                      ))}
                   </tbody>
                </table>
             )}
             {tab !== 'Requested' && (
                <div className="flex flex-col items-center justify-center h-64 text-slate-400">
                   <FolderOpen size={48} className="mb-4 opacity-20"/>
                   <p>No documents found in {tab} folder.</p>
                </div>
             )}
          </div>
       </div>
    </div>
  );
};

// 3. BILLING & PAYMENTS
const BillingView = () => (
  <div className="space-y-6 animate-in fade-in zoom-in duration-300">
     <div className="flex justify-between items-center">
        <div><h2 className="text-2xl font-bold text-slate-800">Billing & Invoices</h2><p className="text-slate-500">Track payments and download receipts.</p></div>
     </div>

     <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
           <p className="text-xs text-slate-400 font-bold uppercase mb-1">Total Paid (Lifetime)</p>
           <h3 className="text-2xl font-bold text-slate-800">₹ 8,498</h3>
        </div>
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
           <p className="text-xs text-slate-400 font-bold uppercase mb-1">Outstanding</p>
           <h3 className="text-2xl font-bold text-emerald-600">₹ 0</h3>
        </div>
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
           <p className="text-xs text-slate-400 font-bold uppercase mb-1">Last Payment</p>
           <h3 className="text-2xl font-bold text-emerald-600">₹ 6,999</h3>
           <p className="text-xs text-slate-400">via Razorpay on 16 Dec</p>
        </div>
     </div>

     <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
        <table className="w-full text-left">
           <thead className="bg-slate-50 border-b border-slate-200 text-xs font-bold text-slate-500 uppercase">
              <tr><th className="px-6 py-4">Invoice ID</th><th className="px-6 py-4">Date</th><th className="px-6 py-4">Service</th><th className="px-6 py-4">Amount</th><th className="px-6 py-4">Status</th><th className="px-6 py-4">Action</th></tr>
           </thead>
           <tbody className="divide-y divide-slate-100 text-sm">
              {INVOICES.map(inv => (
                 <tr key={inv.id} className="hover:bg-slate-50">
                    <td className="px-6 py-4 font-mono text-slate-600">{inv.id}</td>
                    <td className="px-6 py-4 text-slate-500">{inv.date}</td>
                    <td className="px-6 py-4 font-medium text-slate-700">{inv.service}</td>
                    <td className="px-6 py-4 font-bold text-slate-800">₹ {inv.amount.toLocaleString()}</td>
                    <td className="px-6 py-4"><StatusBadge status={inv.status}/></td>
                    <td className="px-6 py-4">
                       {inv.status === 'Unpaid' ? (
                          <button className="bg-indigo-600 text-white px-3 py-1.5 rounded-lg text-xs font-bold shadow hover:bg-indigo-700">Pay Now</button>
                       ) : (
                          <button className="text-slate-400 hover:text-indigo-600 flex items-center"><Download size={14} className="mr-1"/> Receipt</button>
                       )}
                    </td>
                 </tr>
              ))}
           </tbody>
        </table>
     </div>
  </div>
);

// 4. REQUEST SERVICE
const RequestServiceView = () => (
  <div className="space-y-6 animate-in fade-in zoom-in duration-300">
     <div className="text-center max-w-2xl mx-auto mb-10">
        <h2 className="text-3xl font-bold text-slate-800 mb-2">How can we help you today?</h2>
        <p className="text-slate-500">Select a service category to initiate a new request. Our team will get back to you within 24 hours.</p>
     </div>

     <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {SERVICE_CATALOG_SHORT.map((svc, i) => (
           <div key={i} className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm hover:shadow-md hover:border-indigo-200 transition-all cursor-pointer group">
              <div className="w-12 h-12 bg-indigo-50 text-indigo-600 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                 <Briefcase size={24}/>
              </div>
              <h3 className="font-bold text-lg text-slate-800 mb-2">{svc.title}</h3>
              <p className="text-sm text-slate-500 mb-4">{svc.desc}</p>
              <button className="text-indigo-600 font-bold text-sm flex items-center group-hover:underline">Request Now <ChevronRight size={16} className="ml-1"/></button>
           </div>
        ))}
        {/* Contact Card */}
        <div className="bg-gradient-to-br from-slate-800 to-slate-900 p-6 rounded-2xl text-white shadow-lg flex flex-col justify-between">
           <div>
              <h3 className="font-bold text-lg mb-2">Need Custom Advice?</h3>
              <p className="text-slate-300 text-sm">Schedule a call with our partners.</p>
           </div>
           <button className="w-full bg-white text-slate-900 font-bold py-2 rounded-lg mt-4 hover:bg-slate-100">Book Appointment</button>
        </div>
     </div>
  </div>
);

// --- MAIN CUSTOMER APP ---
export default function CustomerApp() {
  const [activeTab, setActiveTab] = useState('Dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true);
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  // Simple Login
  if (!isLoggedIn) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center p-4">
         <div className="bg-white p-8 rounded-3xl shadow-xl w-full max-w-md border border-slate-100 text-center">
            <div className="w-16 h-16 bg-indigo-600 rounded-2xl flex items-center justify-center mx-auto mb-6 text-white shadow-lg shadow-indigo-200"><Building2 size={32}/></div>
            <h1 className="text-2xl font-bold text-slate-800 mb-2">Client Portal</h1>
            <p className="text-slate-500 mb-8">Access your documents, track audits, and manage compliance.</p>
            <button onClick={() => setIsLoggedIn(true)} className="w-full bg-indigo-600 text-white font-bold py-3.5 rounded-xl shadow-lg hover:bg-indigo-700 transition-all">Login as Client</button>
            <p className="text-xs text-slate-400 mt-6">Powered by VR Here</p>
         </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-slate-50 font-sans text-slate-800 overflow-hidden">
      {/* Sidebar */}
      <aside className={`${sidebarCollapsed ? 'w-20' : 'w-64'} bg-white h-full border-r border-slate-200 flex flex-col z-20 transition-all duration-300`} onMouseEnter={() => setSidebarCollapsed(false)} onMouseLeave={() => setSidebarCollapsed(true)}>
        <div className="h-20 flex items-center justify-center border-b border-slate-100"><div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center text-white font-bold text-lg shadow-lg">VR</div></div>
        <div className="flex-1 py-6 px-3 space-y-1">
           {['Dashboard', 'Projects', 'Documents', 'Invoices', 'Request Service', 'Support'].map(item => (
             <button key={item} onClick={() => setActiveTab(item)} className={`flex items-center w-full p-3 rounded-xl transition-all ${activeTab === item ? 'bg-indigo-50 text-indigo-600 font-bold' : 'text-slate-500 hover:bg-slate-50'}`}>
               <div className="shrink-0">
                 {item === 'Dashboard' ? <LayoutDashboard size={20}/> : item === 'Projects' ? <CheckSquare size={20}/> : item === 'Documents' ? <FileText size={20}/> : item === 'Invoices' ? <CreditCard size={20}/> : item === 'Support' ? <HelpCircle size={20}/> : <Plus size={20}/>}
               </div>
               <span className={`ml-3 whitespace-nowrap transition-all duration-300 ${sidebarCollapsed ? 'opacity-0 w-0 overflow-hidden' : 'opacity-100'}`}>{item}</span>
             </button>
           ))}
        </div>
        <div className="p-4 border-t border-slate-100"><button onClick={() => setIsLoggedIn(false)} className="flex items-center w-full p-2 rounded-lg text-rose-500 hover:bg-rose-50"><LogOut size={20} /><span className={`ml-3 text-sm transition-all duration-300 ${sidebarCollapsed ? 'opacity-0' : 'opacity-100'}`}>Logout</span></button></div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col h-full overflow-hidden relative">
        <header className="h-16 bg-white/80 backdrop-blur-md border-b border-slate-200 flex items-center justify-between px-8 sticky top-0 z-10">
           <h1 className="text-xl font-bold text-slate-800">{activeTab}</h1>
           <div className="flex items-center gap-4">
              <button className="p-2 text-slate-400 hover:text-indigo-600 relative"><Bell size={20}/><span className="absolute top-2 right-2 w-2 h-2 bg-rose-500 rounded-full ring-2 ring-white"></span></button>
              <div className="w-8 h-8 rounded-full bg-indigo-100 border border-indigo-200 shadow-sm flex items-center justify-center text-xs font-bold text-indigo-700">TK</div>
           </div>
        </header>

        <div className="flex-1 overflow-y-auto p-4 md:p-8">
           {activeTab === 'Dashboard' && <DashboardHome setActiveTab={setActiveTab} />}
           {activeTab === 'Documents' && <DocumentVault />}
           {activeTab === 'Invoices' && <BillingView />}
           {activeTab === 'Request Service' && <RequestServiceView />}
           {activeTab === 'Projects' && (
              <div className="space-y-4 animate-in fade-in">
                 {ACTIVE_PACKAGES.map(proj => (
                    <div key={proj.id} className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
                       <div className="flex justify-between mb-4">
                          <div>
                             <h3 className="font-bold text-lg">{proj.title}</h3>
                             <p className="text-xs text-slate-500">{proj.plan} • Paid: ₹{proj.amountPaid}</p>
                          </div>
                          <StatusBadge status={proj.status}/>
                       </div>
                       <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden mb-2"><div className="h-full bg-indigo-500" style={{width: `${proj.progress}%`}}></div></div>
                       <p className="text-sm text-slate-500">
                          Progress: {proj.progress}% • 
                          <span className="text-amber-600 font-semibold ml-2">Action: {proj.pendingAction}</span>
                       </p>
                    </div>
                 ))}
              </div>
           )}
           {activeTab === 'Support' && <div className="flex h-full items-center justify-center text-slate-400 flex-col"><MessageSquare size={48} className="mb-4 opacity-20"/><p>Support Chat / Ticket System</p></div>}
        </div>
      </main>
    </div>
  );
}