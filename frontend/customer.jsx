import React, { useState, useEffect, useCallback } from 'react';
import {
   LayoutDashboard, Briefcase, Package, FileText,
   Wallet, Headphones, User, Bell, LogOut,
   Menu, MessageSquare, Plus, X, Phone
} from 'lucide-react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

// Import Modular Components
import DashboardView from './components/customer/DashboardView';
import ServicesView from './components/customer/ServicesView';
import OrdersView from './components/customer/OrdersView';
import DocumentsView from './components/customer/DocumentsView';
import AccountsView from './components/customer/AccountsView';
import SupportView from './components/customer/SupportView';
import AccountingServicesView from './components/customer/AccountingServicesView';
import ServiceDetailView from './components/customer/ServiceDetailView';
import { SERVICE_CATALOG } from './data/serviceCatalog';

export default function CustomerApp() {
   const [activeTab, setActiveTab] = useState('Home');
   const [selectedOrderId, setSelectedOrderId] = useState('');
   const [sidebarCollapsed, setSidebarCollapsed] = useState(true);
   const [isLoggedIn, setIsLoggedIn] = useState(false);
   const [userInfo, setUserInfo] = useState(null);
   const [orders, setOrders] = useState([]);
   const [payments, setPayments] = useState([]);
   const [notifications, setNotifications] = useState([]);
   const [isNotificationOpen, setIsNotificationOpen] = useState(false);
   const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
   const [serviceSearchQuery, setServiceSearchQuery] = useState('');
   const navigate = useNavigate();

   // -- Authentication --
   useEffect(() => {
      const user = localStorage.getItem('userInfo');
      if (user) {
         setUserInfo(JSON.parse(user));
         setIsLoggedIn(true);
      } else {
         navigate('/');
      }
   }, [navigate]);

   // -- Data Fetching --
   const fetchData = useCallback(async () => {
      if (!userInfo) return;
      try {
         const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
         const [ordersRes, paymentsRes, notificationsRes] = await Promise.all([
            axios.get('/api/orders', config),
            axios.get('/api/payments', config),
            axios.get('/api/notifications', config)
         ]);
         setOrders(ordersRes.data);
         setPayments(paymentsRes.data);
         setNotifications(notificationsRes.data);
      } catch (error) {
         console.error("Failed to fetch data:", error);
      }
   }, [userInfo]);

   useEffect(() => {
      if (userInfo) {
         fetchData();
      }
   }, [userInfo, fetchData]);

   const handleLogout = () => {
      localStorage.removeItem('userInfo');
      navigate('/login');
   };

   if (!isLoggedIn || !userInfo) {
      return (
         <div className="min-h-screen bg-slate-50 flex flex-col items-center justify-center p-4">
            <div className="w-12 h-12 border-4 border-indigo-600 border-t-transparent rounded-full animate-spin mb-4"></div>
            <p className="text-slate-500 font-black text-xs uppercase tracking-widest">Loading Your Dashboard...</p>
         </div>
      );
   }

   // -- Tab Mapping --
   const renderView = () => {
      switch (activeTab) {
         case 'Home': return (
            <DashboardView
               setActiveTab={(tab, query) => {
                  if (query) setServiceSearchQuery(query);
                  setActiveTab(tab);
               }}
               orders={orders}
               notifications={notifications}
               userInfo={userInfo}
               onOpenProject={(orderId) => {
                  setSelectedOrderId(orderId);
                  setActiveTab('Orders');
               }}
            />
         );
         case 'Services': {
            const q = serviceSearchQuery;
            if (q) setServiceSearchQuery(''); // consume once
            return <ServicesView setActiveTab={setActiveTab} initialQuery={q} />;
         }
         case 'Accounting': return <AccountingServicesView setActiveTab={setActiveTab} userInfo={userInfo} />;
         case 'Orders': return (
            <OrdersView
               orders={orders}
               notifications={notifications}
               selectedOrderId={selectedOrderId}
               setSelectedOrderId={setSelectedOrderId}
               payments={payments}
               onOpenVault={() => setActiveTab('Documents')}
               setActiveTab={setActiveTab}
            />
         );
         case 'Documents': return <DocumentsView orders={orders} refreshOrders={fetchData} userInfo={userInfo} notifications={notifications} />;
         case 'Account': return <AccountsView orders={orders} payments={payments} />;
         case 'New': return <SupportView userInfo={userInfo} />;
         default: 
            if (SERVICE_CATALOG[activeTab]) {
                return <ServiceDetailView serviceKey={activeTab} setActiveTab={setActiveTab} userInfo={userInfo} />;
            }
            return <DashboardView setActiveTab={setActiveTab} orders={orders} notifications={notifications} userInfo={userInfo} />;
      }
   };

   const NavItems = [
      { id: 'Home', icon: LayoutDashboard, label: 'Home' },
      { id: 'Services', icon: Briefcase, label: 'Services' },
      { id: 'Orders', icon: Package, label: 'Orders' },
      { id: 'Documents', icon: FileText, label: 'Vault' },
      { id: 'New', icon: MessageSquare, label: 'Support' },
      { id: 'Account', icon: Wallet, label: 'Account' },
   ];

   return (
      <div className="flex h-screen bg-slate-50 font-sans text-slate-800 overflow-hidden relative">

         {/* --- DESKTOP SIDEBAR --- */}
         <aside
            className={`hidden md:flex flex-col ${sidebarCollapsed ? 'w-24' : 'w-64'} bg-white border-r border-slate-100 transition-all duration-500 z-30`}
            onMouseEnter={() => setSidebarCollapsed(false)}
            onMouseLeave={() => setSidebarCollapsed(true)}
         >
            <div className="h-24 flex items-center justify-center border-b border-slate-50">
               <div className="w-12 h-12 bg-gradient-to-tr from-indigo-600 to-violet-600 rounded-2xl flex items-center justify-center text-white font-black text-xl shadow-lg shadow-indigo-100">
                  VR
               </div>
            </div>

            <nav className="flex-1 py-10 px-4 space-y-2">
               {NavItems.map(item => (
                  <button
                     key={item.id}
                     onClick={() => setActiveTab(item.id)}
                     className={`flex items-center w-full p-4 rounded-2xl transition-all group ${activeTab === item.id ? 'bg-indigo-600 text-white shadow-xl shadow-indigo-100' : 'text-slate-400 hover:bg-slate-50 hover:text-slate-600'}`}
                  >
                     <item.icon size={22} className={`${activeTab === item.id ? '' : 'group-hover:scale-110 transition-transform'}`} />
                     <span className={`ml-4 text-sm font-black transition-all duration-300 whitespace-nowrap overflow-hidden ${sidebarCollapsed ? 'opacity-0 w-0' : 'opacity-100 w-auto'}`}>
                        {item.label}
                     </span>
                  </button>
               ))}
            </nav>

            <div className="p-4 border-t border-slate-50">
               <button
                  onClick={handleLogout}
                  className="flex items-center w-full p-4 rounded-2xl text-rose-500 hover:bg-rose-50 transition-colors group"
               >
                  <LogOut size={22} className="group-hover:rotate-12 transition-transform" />
                  <span className={`ml-4 text-sm font-black transition-all duration-300 ${sidebarCollapsed ? 'opacity-0 w-0' : 'opacity-100 w-auto'}`}>
                     Logout
                  </span>
               </button>
            </div>
         </aside>

         {/* --- MOBILE SIDEBAR / MENU --- */}
         {isMobileMenuOpen && (
            <div className="fixed inset-0 z-50 md:hidden bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-300" onClick={() => setIsMobileMenuOpen(false)}>
               <div
                  className="w-72 h-full bg-white shadow-2xl animate-in slide-in-from-left duration-500 flex flex-col"
                  onClick={e => e.stopPropagation()}
               >
                  <div className="p-6 border-b border-slate-50 flex items-center justify-between">
                     <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center text-white font-black text-lg">VR</div>
                        <span className="font-black text-slate-800 tracking-tight">VR HERE</span>
                     </div>
                     <button onClick={() => setIsMobileMenuOpen(false)} className="p-2 text-slate-400 hover:text-slate-600">
                        <X size={24} />
                     </button>
                  </div>

                  <nav className="flex-1 py-8 px-4 space-y-1 overflow-y-auto">
                     {NavItems.map(item => (
                        <button
                           key={item.id}
                           onClick={() => { setActiveTab(item.id); setIsMobileMenuOpen(false); }}
                           className={`flex items-center w-full p-4 rounded-2xl transition-all ${activeTab === item.id ? 'bg-indigo-50 text-indigo-600' : 'text-slate-500 hover:bg-slate-50'}`}
                        >
                           <item.icon size={22} className="mr-4" />
                           <span className="font-bold text-sm">{item.label}</span>
                        </button>
                     ))}
                  </nav>

                  <div className="p-6 border-t border-slate-50">
                     <button
                        onClick={handleLogout}
                        className="flex items-center w-full p-4 rounded-2xl text-rose-500 bg-rose-50 hover:bg-rose-100 transition-colors font-bold text-sm"
                     >
                        <LogOut size={22} className="mr-4" />
                        Logout Session
                     </button>
                  </div>
               </div>
            </div>
         )}

         {/* --- MAIN CONTENT AREA --- */}
         <main className="flex-1 flex flex-col min-w-0 overflow-hidden relative">

            {/* Mobile Header */}
            <header className="md:hidden flex h-16 items-center justify-between px-5 bg-white border-b border-slate-50 sticky top-0 z-20">
               <button onClick={() => setIsMobileMenuOpen(true)} className="p-2 -ml-2 text-slate-600">
                  <Menu size={24} />
               </button>
               <div className="flex items-center gap-2">
                  <div className="w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center text-white font-black text-sm">VR</div>
                  <span className="font-black text-slate-800 text-sm tracking-tight uppercase">Dashboard</span>
               </div>
               <button onClick={handleLogout} className="p-2 -mr-2 text-rose-500">
                  <LogOut size={22} />
               </button>
            </header>

            {/* Desktop/Tablet Header */}
            <header className="hidden md:flex h-20 items-center justify-between px-10 bg-white/50 backdrop-blur-xl border-b border-slate-100 sticky top-0 z-20">
               <div className="flex items-center gap-3">
                  <h1 className="text-xl font-black text-slate-800 tracking-tight">{activeTab}</h1>
                  <div className="w-1.5 h-1.5 bg-indigo-500 rounded-full animate-pulse"></div>
               </div>
               <div className="flex items-center gap-6">
                  <div className="flex items-center gap-3 bg-white p-1.5 pr-4 rounded-2xl border border-slate-100 shadow-sm">
                     <div className="w-10 h-10 bg-indigo-50 rounded-xl flex items-center justify-center text-indigo-600 font-black">
                        {userInfo.name.charAt(0).toUpperCase()}
                     </div>
                     <div className="text-left">
                        <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest leading-none mb-1">Customer</p>
                        <p className="text-xs font-bold text-slate-700 leading-none">{userInfo.name}</p>
                     </div>
                  </div>
               </div>
            </header>

            {/* SCROLLABLE VIEWPORT */}
            <div className="flex-1 overflow-y-auto overflow-x-hidden pt-6 px-5 md:px-10 md:pt-10 scroll-smooth">
               <div className="max-w-7xl mx-auto w-full">
                  {renderView()}
               </div>
            </div>

            {/* --- MOBILE BOTTOM NAVBAR --- */}
            <nav className="md:hidden fixed bottom-1.5 left-4 right-4 h-16 bg-slate-900/90 backdrop-blur-2xl rounded-3xl border border-white/10 flex items-center justify-around px-2 z-50 shadow-2xl shadow-indigo-200/50">
               {NavItems.filter(i => i.id !== 'New').map((item) => (
                  <button
                     key={item.id}
                     onClick={() => setActiveTab(item.id)}
                     className={`flex flex-col items-center gap-1 px-3 py-1.5 transition-all ${activeTab === item.id ? 'text-white' : 'text-slate-400'}`}
                  >
                     <div className={`transition-all duration-300 ${activeTab === item.id ? 'scale-110 -translate-y-0.5' : ''}`}>
                        <item.icon size={20} />
                     </div>
                     <span className={`text-[8px] font-black uppercase tracking-widest transition-opacity ${activeTab === item.id ? 'opacity-100' : 'opacity-60'}`}>
                        {item.id === 'Home' ? 'Me' : item.label === 'Vault' ? 'Docs' : item.label}
                     </span>
                  </button>
               ))}
            </nav>

            {/* --- FLOATING CONTACT BUTTON --- */}
            <div className="fixed bottom-24 right-5 z-40 flex flex-col gap-3 md:bottom-10 md:right-10">
               <a
                  href="https://wa.me/918008530606"
                  target="_blank"
                  rel="noreferrer"
                  className="w-14 h-14 bg-emerald-500 text-white rounded-full shadow-2xl shadow-emerald-200 flex items-center justify-center hover:bg-emerald-600 transform hover:scale-110 active:scale-90 transition-all group relative border-4 border-white"
               >
                  <MessageSquare size={24} />
                  <span className="absolute right-full mr-4 bg-slate-900 text-white text-[10px] font-black px-3 py-1.5 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap shadow-xl">
                     Chat on WhatsApp
                  </span>
               </a>
               <button
                  onClick={() => setActiveTab('New')}
                  className="w-14 h-14 bg-indigo-600 text-white rounded-full shadow-2xl shadow-indigo-200 flex items-center justify-center hover:bg-indigo-700 transform hover:scale-110 active:scale-90 transition-all group relative border-4 border-white"
               >
                  <Headphones size={24} />
                  <span className="absolute right-full mr-4 bg-slate-900 text-white text-[10px] font-black px-3 py-1.5 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap shadow-xl">
                     Raise Support Ticket
                  </span>
               </button>
            </div>
         </main>
      </div>
   );
}
