import React, { useState, useEffect, useCallback } from 'react';
import {
   LayoutDashboard, Briefcase, Package, FileText,
   Wallet, Headphones, User, Bell, LogOut,
   Menu, MessageSquare, Plus, X, Phone, BookOpen
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
import CustomerFinanceView from './components/customer/CustomerFinanceView';
import BookkeepingView from './components/customer/BookkeepingView';
import { SERVICE_CATALOG } from './data/serviceCatalog';
import { useNotifications, NotificationsFeed, InAppBanner } from './modules/notifications/v1.1';

const formatImageUrl = (url) => {
   if (!url || typeof url !== 'string') return '';
   if (url.includes('drive.google.com/file/d/')) {
      const match = url.match(/\/file\/d\/([a-zA-Z0-9_-]+)/);
      if (match && match[1]) {
         return `https://lh3.googleusercontent.com/d/${match[1]}`;
      }
   }
   if (url.includes('drive.google.com/open?id=')) {
      const match = url.match(/id=([a-zA-Z0-9_-]+)/);
      if (match && match[1]) {
         return `https://lh3.googleusercontent.com/d/${match[1]}`;
      }
   }
   return url;
};

export default function CustomerApp() {
   const [activeTab, setActiveTab] = useState('Home');
   const [selectedOrderId, setSelectedOrderId] = useState('');
   const [sidebarCollapsed, setSidebarCollapsed] = useState(true);
   const [isLoggedIn, setIsLoggedIn] = useState(false);
   const [userInfo, setUserInfo] = useState(null);
   const [orders, setOrders] = useState([]);
   const [payments, setPayments] = useState([]);
   const {
      notifications,
      activeBannerNotification,
      setActiveBannerNotification,
      unreadCount,
      markRead,
      markAllRead
   } = useNotifications(userInfo?.token);
   const [isNotificationOpen, setIsNotificationOpen] = useState(false);
   const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
   const [selectedService, setSelectedService] = useState(null);
   const [serviceSearchQuery, setServiceSearchQuery] = useState('');
   const navigate = useNavigate();
   const [menuExpanded, setMenuExpanded] = useState(false);

   const toggleLetsTrack = () => {
      if (window.LetsTrack) {
         if (typeof window.LetsTrack.toggle === 'function') {
            window.LetsTrack.toggle();
            return;
         }
         if (typeof window.LetsTrack.open === 'function') {
            window.LetsTrack.open();
            return;
         }
      }
      const rootEl = document.getElementById('letstrack-widget-root');
      const shadow = (rootEl && rootEl.shadowRoot) || window.__letsTrackShadowRoot;
      if (shadow) {
         const btn = shadow.querySelector('.lt-widget-btn, button:not(#lt-custom-close-btn), [class*="widget-btn"], [class*="launcher"]');
         if (btn) {
            btn.click();
            return;
         }
      }
      const fallbackBtn = document.querySelector('.lt-widget-btn, #letstrack-widget-btn');
      if (fallbackBtn) {
         fallbackBtn.click();
      }
   };

   const [phonePromptOpen, setPhonePromptOpen] = useState(false);
   const [inputPhone, setInputPhone] = useState('');
   const [savingPhone, setSavingPhone] = useState(false);

   // -- Authentication --
   useEffect(() => {
      const user = localStorage.getItem('userInfo');
      if (user) {
         const parsed = JSON.parse(user);
         setUserInfo(parsed);
         setIsLoggedIn(true);
         if (!parsed.phone || parsed.requiresPhone) {
            setPhonePromptOpen(true);
         }
      } else {
         navigate('/');
      }
   }, [navigate]);

   const handleSavePhone = async (e) => {
      e.preventDefault();
      const cleaned = inputPhone.trim();
      if (!cleaned || cleaned.length < 10) {
         alert('Please enter a valid 10-digit mobile number');
         return;
      }
      setSavingPhone(true);
      try {
         const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
         await axios.put('/api/auth/profile', { phone: cleaned }, config);
         const updated = { ...userInfo, phone: cleaned, requiresPhone: false };
         setUserInfo(updated);
         localStorage.setItem('userInfo', JSON.stringify(updated));
         setPhonePromptOpen(false);
         alert('Phone number updated successfully!');
      } catch (err) {
         alert(err.response?.data?.message || 'Failed to save phone number');
      } finally {
         setSavingPhone(false);
      }
   };

   // -- Data Fetching --
   const fetchData = useCallback(async () => {
      if (!userInfo) return;
      try {
         const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
         const [ordersRes, paymentsRes] = await Promise.all([
            axios.get('/api/orders', config),
            axios.get('/api/payments', config)
         ]);
         setOrders(ordersRes.data);
         setPayments(paymentsRes.data);
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
            <div className="w-12 h-12 border-4 border-red-600 border-t-transparent rounded-full animate-spin mb-4"></div>
            <p className="text-slate-500 font-black text-xs uppercase tracking-widest">Loading Your Dashboard...</p>
         </div>
      );
   }

   const handleOrderPlacedSuccess = async (data) => {
      await fetchData();
      setSelectedService(null);
      if (data?.order?._id) {
         setSelectedOrderId(data.order._id);
      }
      setActiveTab('Orders');
   };

   // -- Tab Mapping --
   const renderView = () => {
      switch (activeTab) {
         case 'Home': return (
             <DashboardView
                setActiveTab={(tab, query) => {
                   if (query) setServiceSearchQuery(query);
                   setActiveTab(tab);
                }}
                onSelectService={(serviceObj) => {
                   setSelectedService(serviceObj);
                   setActiveTab('Services');
                }}
                orders={orders}
                notifications={notifications}
                userInfo={userInfo}
                onOpenProject={(orderId) => {
                   setSelectedOrderId(orderId);
                   setActiveTab('Orders');
                }}
                onOpenNotifications={() => setIsNotificationOpen(true)}
             />
          );
         case 'Services': {
            if (selectedService) {
                return (
                    <ServiceDetailView 
                        service={selectedService}
                        onBack={() => setSelectedService(null)}
                        setActiveTab={setActiveTab}
                        userInfo={userInfo}
                        onOrderSuccess={handleOrderPlacedSuccess}
                    />
                );
            }
            const q = serviceSearchQuery;
            if (q) setServiceSearchQuery(''); // consume once
            return (
                <ServicesView 
                    setActiveTab={setActiveTab} 
                    initialQuery={q} 
                    onSelectService={(serviceObj) => {
                        setSelectedService(serviceObj);
                    }}
                />
            );
         }
         case 'Accounting': return <AccountingServicesView setActiveTab={setActiveTab} userInfo={userInfo} onOrderSuccess={handleOrderPlacedSuccess} />;
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
         case 'Invoices': return <CustomerFinanceView token={userInfo?.token} />;
         case 'Bookkeeping': return <BookkeepingView token={userInfo?.token} />;
         case 'Account': return <AccountsView orders={orders} payments={payments} userInfo={userInfo} token={userInfo?.token} />;
         case 'New': return <SupportView userInfo={userInfo} />;
         default: 
            return <DashboardView setActiveTab={setActiveTab} orders={orders} notifications={notifications} userInfo={userInfo} onSelectService={(serviceObj) => { setSelectedService(serviceObj); setActiveTab('Services'); }} />;
      }
   };

   const NavGroups = [
      {
         group: 'Main Workspace',
         items: [
            { id: 'Home', icon: LayoutDashboard, label: 'Overview' },
            { id: 'Services', icon: Briefcase, label: 'Service Catalog' },
            { id: 'Orders', icon: Package, label: 'Orders & Projects' },
            { id: 'Invoices', icon: Wallet, label: 'Billing & Invoices' },
         ]
      },
      {
         group: 'Compliance & Tools',
         items: [
            { id: 'Documents', icon: FileText, label: 'Document Vault' },
            { id: 'Bookkeeping', icon: BookOpen, label: 'Bookkeeping & AaaS' },
         ]
      },
      {
         group: 'Help & Settings',
         items: [
            { id: 'New', icon: MessageSquare, label: 'Support & Tickets' },
            { id: 'Account', icon: User, label: 'Account Settings' },
         ]
      }
   ];

   const allNavItems = NavGroups.flatMap(g => g.items);

   return (
      <div className="flex h-screen bg-slate-50 font-sans text-slate-800 overflow-hidden relative">

         {/* --- DESKTOP EXECUTIVE SIDEBAR --- */}
         <aside className="hidden lg:flex flex-col w-64 bg-slate-950 text-slate-300 border-r border-slate-800/90 z-30 shrink-0 select-none">
            {/* Official Logo & Brand Header (White Background) */}
            <div className="h-20 px-5 flex items-center justify-between bg-white border-b border-slate-200">
               <a href="/" className="flex items-center gap-3 group">
                  <img src="/logo.png" alt="VR Here" className="h-10 w-auto object-contain group-hover:scale-105 transition-transform shrink-0" />
                  <div className="flex flex-col min-w-0">
                     <span className="font-black text-slate-900 text-base leading-none tracking-tight">VR Here</span>
                     <span className="text-[8.5px] font-extrabold text-red-600 uppercase tracking-widest mt-0.5 truncate">Customer Suite</span>
                  </div>
               </a>
            </div>

            {/* Navigation Groups */}
            <div className="flex-1 py-6 px-4 space-y-6 overflow-y-auto custom-scrollbar">
               {NavGroups.map((group, gIdx) => (
                  <div key={gIdx} className="space-y-1.5">
                     <p className="px-3 text-[10px] font-black uppercase tracking-widest text-slate-400 mb-2">{group.group}</p>
                     {group.items.map(item => {
                        const Icon = item.icon;
                        const isActive = activeTab === item.id;
                        return (
                           <button
                              key={item.id}
                              onClick={() => {
                                 setActiveTab(item.id);
                                 if (item.id === 'Services') setSelectedService(null);
                              }}
                              className={`flex items-center justify-between w-full px-3.5 py-3 rounded-xl font-bold text-xs transition-all duration-200 group ${
                                 isActive
                                    ? 'bg-gradient-to-r from-red-600 to-rose-600 text-white shadow-md shadow-red-600/30 font-black'
                                    : 'text-slate-300 hover:text-white hover:bg-slate-900/90'
                              }`}
                           >
                              <div className="flex items-center gap-3">
                                 <Icon size={18} className={isActive ? 'text-white' : 'text-slate-400 group-hover:text-white group-hover:scale-110 transition-all'} />
                                 <span>{item.label}</span>
                              </div>
                              {item.id === 'Orders' && orders.filter(o => o.status !== 'Completed').length > 0 && (
                                 <span className={`px-2 py-0.5 rounded-full text-[10px] font-black ${isActive ? 'bg-white text-red-600' : 'bg-slate-800 text-slate-300'}`}>
                                    {orders.filter(o => o.status !== 'Completed').length}
                                 </span>
                              )}
                              {item.id === 'New' && unreadCount > 0 && (
                                 <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
                              )}
                           </button>
                        );
                     })}
                  </div>
               ))}
            </div>

            {/* Quick CA Support & User Profile Footer */}
            <div className="p-4 border-t border-slate-800/80 space-y-3 bg-slate-900/40">
               <div className="p-3 bg-slate-900 rounded-xl border border-slate-800 flex items-center justify-between">
                  <div className="flex items-center gap-2.5 min-w-0">
                     <div className="w-8 h-8 rounded-lg bg-red-500/10 text-red-400 flex items-center justify-center font-black text-xs shrink-0">
                        CA
                     </div>
                     <div className="min-w-0">
                        <p className="text-[11px] font-bold text-white truncate">Direct Helpline</p>
                        <p className="text-[10px] text-slate-400 font-medium">+91 80085 30606</p>
                     </div>
                  </div>
                  <a href="tel:+918008530606" className="p-1.5 bg-red-600/20 text-red-400 hover:bg-red-600 hover:text-white rounded-lg transition-colors" title="Call CA Support">
                     <Phone size={14} />
                  </a>
               </div>

               <div className="flex items-center justify-between pt-1">
                  <div className="flex items-center gap-2.5 min-w-0 cursor-pointer" onClick={() => setActiveTab('Account')} title="View Account Settings">
                     {userInfo.profilePhoto || userInfo.companyLogo ? (
                        <img
                           src={formatImageUrl(userInfo.profilePhoto || userInfo.companyLogo)}
                           alt={userInfo.name}
                           className="w-9 h-9 rounded-xl object-cover border border-slate-700 shrink-0"
                        />
                     ) : (
                        <div className="w-9 h-9 rounded-xl bg-slate-800 text-white font-bold text-xs flex items-center justify-center shrink-0 border border-slate-700">
                           {(userInfo.name || 'C').charAt(0).toUpperCase()}
                        </div>
                     )}
                     <div className="min-w-0">
                        <p className="text-xs font-bold text-slate-200 truncate">{userInfo.name}</p>
                        <p className="text-[10px] text-slate-400 truncate">{userInfo.companyName || userInfo.email}</p>
                     </div>
                  </div>
                  <button
                     onClick={handleLogout}
                     className="p-2 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-xl transition-colors"
                     title="Logout"
                  >
                     <LogOut size={16} />
                  </button>
               </div>
            </div>
         </aside>

         {/* --- MOBILE SIDEBAR DRAWER --- */}
         {isMobileMenuOpen && (
            <div className="fixed inset-0 z-50 lg:hidden bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-300" onClick={() => setIsMobileMenuOpen(false)}>
               <div
                  className="w-72 h-full bg-slate-950 text-white shadow-2xl animate-in slide-in-from-left duration-500 flex flex-col"
                  onClick={e => e.stopPropagation()}
               >
                  <div className="p-6 bg-white border-b border-slate-200 flex items-center justify-between">
                     <div className="flex items-center gap-3">
                        <img src="/logo.png" alt="VR Here" className="h-9 w-auto object-contain" />
                        <div className="flex flex-col">
                           <span className="font-black text-slate-900 tracking-tight">VR Here</span>
                           <span className="text-[9px] font-extrabold text-red-600 uppercase tracking-widest">Customer Portal</span>
                        </div>
                     </div>
                     <button onClick={() => setIsMobileMenuOpen(false)} className="p-2 text-slate-500 hover:text-slate-900">
                        <X size={24} />
                     </button>
                  </div>

                   <nav className="flex-1 py-6 px-4 space-y-1.5 overflow-y-auto">
                     {allNavItems.map(item => (
                        <button
                           key={item.id}
                           onClick={() => { 
                              setActiveTab(item.id); 
                              if (item.id === 'Services') setSelectedService(null);
                              setIsMobileMenuOpen(false); 
                           }}
                           className={`flex items-center w-full p-3.5 rounded-xl font-bold text-xs transition-all ${
                              activeTab === item.id ? 'bg-red-600 text-white' : 'text-slate-400 hover:bg-slate-900'
                           }`}
                        >
                           <item.icon size={20} className="mr-3" />
                           <span>{item.label}</span>
                        </button>
                     ))}
                  </nav>

                  <div className="p-6 border-t border-slate-800">
                     <button
                        onClick={handleLogout}
                        className="flex items-center w-full p-3.5 rounded-xl text-red-400 bg-red-500/10 hover:bg-red-500/20 transition-colors font-bold text-xs"
                     >
                        <LogOut size={20} className="mr-3" />
                        Logout Session
                     </button>
                  </div>
               </div>
            </div>
         )}

         {/* --- MAIN CONTENT AREA --- */}
         <main className="flex-1 flex flex-col min-w-0 overflow-hidden relative">

            {/* Mobile Header */}
            <header className="lg:hidden flex h-16 items-center justify-between px-5 bg-white border-b border-slate-100 sticky top-0 z-20 shadow-2xs">
               <button onClick={() => setIsMobileMenuOpen(true)} className="p-2 -ml-2 text-slate-700">
                  <Menu size={24} />
               </button>
               <div className="flex items-center gap-2">
                  <img src="/logo.png" alt="VR Here" className="h-8 w-auto object-contain" />
                  <span className="font-black text-slate-900 text-sm tracking-tight uppercase">Portal</span>
               </div>
               <div className="flex items-center gap-2">
                  <button onClick={() => setIsNotificationOpen(true)} className="p-2 text-slate-700 relative">
                     <Bell size={20} />
                     {unreadCount > 0 && (
                        <span className="absolute top-1.5 right-1.5 w-2.5 h-2.5 bg-red-500 rounded-full"></span>
                     )}
                  </button>
                  <button onClick={handleLogout} className="p-2 -mr-2 text-rose-500">
                     <LogOut size={20} />
                  </button>
               </div>
            </header>

            {/* Desktop Top Header Bar */}
            <header className="hidden lg:flex h-20 items-center justify-between px-10 bg-white/80 backdrop-blur-xl border-b border-slate-200/80 sticky top-0 z-20">
               <div className="flex items-center gap-3">
                  <h1 className="text-xl font-black text-slate-900 tracking-tight">
                     {activeTab === 'Services' && selectedService ? selectedService.title : activeTab}
                  </h1>
                  <span className="px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider bg-red-50 text-red-600 border border-red-200/80">
                     {activeTab === 'Services' && selectedService ? 'Service Details' : 'Customer Suite'}
                  </span>
               </div>

               <div className="flex items-center gap-4">
                  {/* Quick Website Switcher */}
                  <a
                     href="/"
                     className="px-3.5 py-2 text-xs font-bold text-slate-600 hover:text-red-600 hover:bg-slate-100 rounded-xl transition-all"
                  >
                     &larr; Back to Website
                  </a>

                  {/* New Engagement Button */}
                  <button
                     onClick={() => {
                        setActiveTab('Services');
                        setSelectedService(null);
                     }}
                     className="bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-700 hover:to-rose-700 text-white font-bold text-xs uppercase tracking-wider px-4 py-2.5 rounded-xl transition-all shadow-md shadow-red-600/25 flex items-center gap-2"
                  >
                     <Plus size={16} />
                     <span>New Engagement</span>
                  </button>

                  {/* Notification Bell with Badge */}
                  <div className="relative">
                     <button
                        onClick={() => setIsNotificationOpen(true)}
                        className="p-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl transition-all relative"
                        title="Notifications"
                     >
                        <Bell size={18} />
                        {unreadCount > 0 && (
                           <span className="absolute -top-1 -right-1 px-1.5 py-0.2 bg-red-600 text-white text-[9px] font-black rounded-full border-2 border-white">
                              {unreadCount}
                           </span>
                        )}
                     </button>
                  </div>

                  {/* User Profile Snippet */}
                  <div
                     className="flex items-center gap-3 pl-3 border-l border-slate-200 cursor-pointer group"
                     onClick={() => setActiveTab('Account')}
                     title="View Profile & Business Settings"
                  >
                     {userInfo.profilePhoto || userInfo.companyLogo ? (
                        <img
                           src={formatImageUrl(userInfo.profilePhoto || userInfo.companyLogo)}
                           alt={userInfo.name}
                           className="w-10 h-10 rounded-xl object-cover border border-slate-200 shadow-sm group-hover:ring-2 group-hover:ring-red-500 transition-all"
                        />
                     ) : (
                        <div className="w-10 h-10 bg-red-50 border border-red-200 rounded-xl flex items-center justify-center text-red-600 font-black group-hover:bg-red-600 group-hover:text-white transition-all">
                           {(userInfo.name || 'C').charAt(0).toUpperCase()}
                        </div>
                     )}
                     <div className="text-left leading-tight">
                        <p className="text-xs font-black text-slate-900 truncate max-w-[150px]">{userInfo.name}</p>
                        <p className="text-[10px] font-semibold text-slate-400">
                           {userInfo.companyName || 'Verified Client'}
                        </p>
                     </div>
                  </div>
               </div>
            </header>

            {/* SCROLLABLE VIEWPORT */}
            <div className="flex-1 overflow-y-auto overflow-x-hidden pt-4 px-4 sm:px-6 lg:px-10 lg:pt-8 scroll-smooth">
               <div className="max-w-[1440px] mx-auto w-full">
                  {renderView()}
               </div>
            </div>

            {/* --- MOBILE BOTTOM NAVBAR --- */}
            <nav className="lg:hidden fixed bottom-1.5 left-4 right-4 h-16 bg-slate-950/95 backdrop-blur-2xl rounded-3xl border border-white/10 flex items-center justify-around px-2 z-50 shadow-2xl shadow-slate-900/50">
               {allNavItems.filter(i => ['Home', 'Services', 'Orders', 'Documents', 'Account'].includes(i.id)).map((item) => (
                  <button
                     key={item.id}
                     onClick={() => setActiveTab(item.id)}
                     className={`flex flex-col items-center gap-1 px-3 py-1.5 transition-all ${activeTab === item.id ? 'text-red-500' : 'text-slate-400'}`}
                  >
                     <div className={`transition-all duration-300 ${activeTab === item.id ? 'scale-110 -translate-y-0.5' : ''}`}>
                        <item.icon size={20} />
                     </div>
                     <span className={`text-[8px] font-black uppercase tracking-widest transition-opacity ${activeTab === item.id ? 'opacity-100 font-bold' : 'opacity-60'}`}>
                        {item.id === 'Home' ? 'Me' : item.label === 'Document Vault' ? 'Vault' : item.label.split(' ')[0]}
                     </span>
                  </button>
               ))}
            </nav>

            {/* --- FLOATING CONTACT BUTTONS (WITH SEPARATED CALL & WHATSAPP) --- */}
            <div className="fixed bottom-24 right-5 z-40 flex flex-col items-end gap-3 md:bottom-10 md:right-10">
               {/* Stacked Menu Options */}
               <div className={`flex flex-col gap-3 transition-all duration-300 origin-bottom ${
                  menuExpanded 
                     ? 'opacity-100 translate-y-0 scale-100 pointer-events-auto' 
                     : 'opacity-0 translate-y-4 scale-90 pointer-events-none'
               }`}>
                  {/* Option 1: LetsTrack Live Chat */}
                  <button
                     onClick={() => {
                        toggleLetsTrack();
                        setMenuExpanded(false);
                     }}
                     className="w-12 h-12 bg-rose-500 text-white rounded-full shadow-lg flex items-center justify-center hover:bg-rose-600 transform hover:scale-110 active:scale-95 transition-all group relative border-2 border-white"
                     title="Open Live Chat"
                  >
                     <MessageSquare size={20} />
                     <span className="absolute right-full mr-3 bg-slate-900 text-white text-[10px] font-black px-3 py-1.5 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap shadow-xl">
                        Live Chat
                     </span>
                  </button>

                  {/* Option 2: WhatsApp Chat */}
                  <a
                     href="https://wa.me/918008530606?text=Hi%20VR%20HERE%20Team,%20I%20am%20chatting%20from%20the%20Customer%20Portal."
                     target="_blank"
                     rel="noreferrer"
                     onClick={() => setMenuExpanded(false)}
                     className="w-12 h-12 bg-emerald-500 text-white rounded-full shadow-lg flex items-center justify-center hover:bg-emerald-600 transform hover:scale-110 active:scale-95 transition-all group relative border-2 border-white"
                     title="WhatsApp Support"
                  >
                     <svg className="w-5 h-5 fill-current" viewBox="0 0 24 24">
                        <path d="M12.031 6.172c-3.181 0-5.767 2.586-5.768 5.766-.001 1.298.38 2.27 1.019 3.287l-.582 2.128 2.182-.573c.978.58 1.911.928 3.145.929 3.178 0 5.767-2.587 5.768-5.766.001-3.187-2.575-5.771-5.764-5.771zm3.392 8.244c-.144.405-.837.774-1.17.824-.312.045-.632.062-1.748-.387-1.196-.481-2.097-1.636-2.158-1.716-.061-.08-1.111-1.474-1.111-2.812 0-1.34.704-1.999.954-2.271.25-.271.545-.339.726-.339.181 0 .363.003.521.011.168.008.394-.064.615.467.228.547.778 1.897.846 2.034.068.136.113.295.023.476-.091.181-.136.295-.272.453-.136.159-.286.355-.408.476-.136.136-.278.283-.12.554.159.272.705 1.162 1.512 1.881 1.038.924 1.913 1.21 2.185 1.346.272.136.431.114.59-.068.159-.181.68-.793.861-1.065.181-.272.363-.227.612-.136.25.091 1.587.748 1.859.884.272.136.453.204.521.317.068.113.068.657-.076 1.062zM12 2C6.477 2 2 6.477 2 12c0 1.891.526 3.662 1.442 5.176L2 22l4.981-1.306C8.423 21.536 10.151 22 12 22c5.523 0 10-4.477 10-10S17.523 2 12 2z" />
                     </svg>
                     <span className="absolute right-full mr-3 bg-slate-900 text-white text-[10px] font-black px-3 py-1.5 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap shadow-xl">
                        WhatsApp Chat
                     </span>
                  </a>

                  {/* Option 3: Phone Direct Call */}
                  <a
                     href="tel:+918008530606"
                     onClick={() => setMenuExpanded(false)}
                     className="w-12 h-12 bg-blue-600 text-white rounded-full shadow-lg flex items-center justify-center hover:bg-blue-700 transform hover:scale-110 active:scale-95 transition-all group relative border-2 border-white"
                     title="Direct Phone Call"
                  >
                     <Phone size={20} />
                     <span className="absolute right-full mr-3 bg-slate-900 text-white text-[10px] font-black px-3 py-1.5 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap shadow-xl">
                        Call Helpline
                     </span>
                  </a>

                  {/* Option 4: Raise Ticket */}
                  <button
                     onClick={() => {
                        setActiveTab('New');
                        setMenuExpanded(false);
                     }}
                     className="w-12 h-12 bg-slate-900 text-white rounded-full shadow-lg flex items-center justify-center hover:bg-slate-800 transform hover:scale-110 active:scale-95 transition-all group relative border-2 border-white"
                     title="Support Ticket Desk"
                  >
                     <Headphones size={20} />
                     <span className="absolute right-full mr-3 bg-slate-900 text-white text-[10px] font-black px-3 py-1.5 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap shadow-xl">
                        Raise Support Ticket
                     </span>
                  </button>
               </div>

               {/* Main Floating Toggle Button */}
               <button
                  onClick={() => setMenuExpanded(!menuExpanded)}
                  className="w-14 h-14 bg-gradient-to-tr from-red-600 to-rose-600 text-white rounded-full shadow-2xl flex items-center justify-center hover:scale-105 active:scale-95 transition-all border-4 border-white z-50 relative"
                  title="Contact Actions"
               >
                  <div className={`transition-transform duration-300 transform ${menuExpanded ? 'rotate-[135deg]' : ''}`}>
                     <Plus size={28} />
                  </div>
               </button>
            </div>

            <InAppBanner 
               activeNotification={activeBannerNotification}
               onDismiss={() => setActiveBannerNotification(null)}
               onClickAction={() => setActiveTab('Home')}
            />

            {/* --- NOTIFICATIONS FULL-SCREEN / RESPONSIVE COMMAND CENTER --- */}
            {isNotificationOpen && (
               <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 lg:p-10 bg-slate-950/70 backdrop-blur-md animate-in fade-in duration-300" onClick={() => setIsNotificationOpen(false)}>
                  <div 
                     className="w-full max-w-5xl h-[88vh] bg-white rounded-3xl shadow-2xl border border-slate-200 overflow-hidden flex flex-col animate-in zoom-in-95 duration-300"
                     onClick={e => e.stopPropagation()}
                  >
                     {/* Full-Screen Notification Header */}
                     <div className="px-6 py-5 border-b border-slate-200 flex items-center justify-between bg-slate-900 text-white">
                        <div className="flex items-center gap-3">
                           <div className="w-10 h-10 rounded-2xl bg-red-600 flex items-center justify-center text-white font-bold shadow-md shadow-red-600/30">
                              <Bell size={20} />
                           </div>
                           <div>
                              <h3 className="font-black text-white text-base tracking-tight flex items-center gap-2">
                                 <span>Notification Command Center</span>
                                 {unreadCount > 0 && (
                                    <span className="px-2 py-0.5 bg-red-600 text-[10px] text-white font-black rounded-full uppercase tracking-wider">
                                       {unreadCount} Unread
                                    </span>
                                 )}
                              </h3>
                              <p className="text-xs text-slate-400 font-medium">Real-time alerts, MCA status changes, and filing milestones</p>
                           </div>
                        </div>

                        <div className="flex items-center gap-3">
                           {unreadCount > 0 && (
                              <button
                                 onClick={markAllRead}
                                 className="hidden sm:inline-block px-3.5 py-1.5 bg-white/10 hover:bg-white/20 text-white text-xs font-bold rounded-xl transition-all"
                              >
                                 Mark All as Read
                              </button>
                           )}
                           <button onClick={() => setIsNotificationOpen(false)} className="p-2 text-slate-400 hover:text-white rounded-xl hover:bg-slate-800 transition">
                              <X size={20} />
                           </button>
                        </div>
                     </div>

                     {/* Notification Body Feed */}
                     <div className="flex-1 overflow-y-auto p-6 bg-slate-50/50">
                        <NotificationsFeed 
                           notifications={notifications}
                           onMarkRead={markRead}
                           onMarkAllRead={markAllRead}
                           onClickAction={(notif) => {
                              setIsNotificationOpen(false);
                              if (notif.type === 'Ticket') {
                                 setActiveTab('New');
                              } else {
                                 setSelectedOrderId(notif.referenceId || '');
                                 setActiveTab('Orders');
                              }
                           }}
                        />
                     </div>
                  </div>
               </div>
            )}

            {/* --- GOOGLE SIGNIN / FIRST-TIME PHONE CAPTURE MODAL --- */}
            {phonePromptOpen && (
               <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-md animate-in fade-in duration-300">
                  <div className="bg-white rounded-3xl p-6 sm:p-8 max-w-md w-full shadow-2xl border border-slate-100 animate-in zoom-in-95 duration-200 space-y-6">
                     <div className="text-center space-y-2">
                        <div className="w-14 h-14 bg-red-50 text-red-600 rounded-2xl flex items-center justify-center mx-auto shadow-inner">
                           <Phone size={28} />
                        </div>
                        <h3 className="text-xl font-black text-slate-900 tracking-tight">Complete Your Profile</h3>
                        <p className="text-xs text-slate-500 font-medium">
                           Welcome to VR HERE! Please provide your mobile number for real-time filing milestone updates and official WhatsApp communication.
                        </p>
                     </div>

                     <form onSubmit={handleSavePhone} className="space-y-4">
                        <div className="space-y-1.5">
                           <label className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                              Mobile Number <span className="text-red-500">*</span>
                           </label>
                           <div className="flex items-center rounded-2xl border border-slate-200 bg-slate-50 focus-within:bg-white focus-within:border-red-500 focus-within:ring-2 focus-within:ring-red-500/20 transition-all overflow-hidden p-1">
                              <span className="px-3 text-xs font-black text-slate-500 border-r border-slate-200">
                                 +91
                              </span>
                              <input
                                 type="tel"
                                 required
                                 autoFocus
                                 maxLength={12}
                                 value={inputPhone}
                                 onChange={(e) => setInputPhone(e.target.value.replace(/[^0-9]/g, ''))}
                                 placeholder="98765 43210"
                                 className="w-full px-3 py-2.5 bg-transparent text-sm font-bold text-slate-900 outline-none placeholder:text-slate-400"
                              />
                           </div>
                        </div>

                        <div className="flex items-center gap-3 pt-2">
                           <button
                              type="button"
                              onClick={() => setPhonePromptOpen(false)}
                              className="flex-1 py-3 px-4 rounded-xl text-xs font-bold text-slate-500 hover:bg-slate-100 transition-colors"
                           >
                              Skip For Now
                           </button>
                           <button
                              type="submit"
                              disabled={savingPhone || inputPhone.trim().length < 10}
                              className="flex-1 py-3 px-4 rounded-xl text-xs font-black text-white bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-700 hover:to-rose-700 shadow-md shadow-red-600/25 transition-all disabled:opacity-50 flex items-center justify-center gap-2"
                           >
                              {savingPhone ? 'Saving...' : 'Save & Continue'}
                           </button>
                        </div>
                     </form>
                  </div>
               </div>
            )}
         </main>
      </div>
   );
}
