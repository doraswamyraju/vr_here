import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
    LayoutDashboard, Users, LogOut, Menu, X, 
    Bell, User as UserIcon, Settings, ChevronRight
} from 'lucide-react';
import PartnerOverviewView from './components/partner/PartnerOverviewView';
import PartnerSettingsView from './components/partner/PartnerSettingsView';

const PartnerDashboard = () => {
    const navigate = useNavigate();
    const [activeTab, setActiveTab] = useState('Overview');
    const [isSidebarOpen, setIsSidebarOpen] = useState(false);
    const [userInfo, setUserInfo] = useState(null);

    useEffect(() => {
        const storedUser = localStorage.getItem('userInfo');
        if (storedUser) {
            const parsedUser = JSON.parse(storedUser);
            if (parsedUser.role !== 'partner') {
                navigate('/login');
            } else {
                setUserInfo(parsedUser);
            }
        } else {
            navigate('/login');
        }
    }, [navigate]);

    const handleLogout = () => {
        localStorage.removeItem('userInfo');
        localStorage.removeItem('token');
        navigate('/login');
    };

    const sidebarItems = [
        { name: 'Overview', icon: LayoutDashboard },
        { name: 'Referrals', icon: Users },
        { name: 'Settings', icon: Settings }
    ];

    if (!userInfo) return null;

    return (
        <div className="flex h-screen bg-slate-50 font-sans overflow-hidden">
            
            {/* Mobile Sidebar Overlay */}
            {isSidebarOpen && (
                <div 
                    className="fixed inset-0 bg-slate-900/60 backdrop-blur-sm z-[60] lg:hidden animate-fade-in"
                    onClick={() => setIsSidebarOpen(false)}
                ></div>
            )}

            {/* Sidebar */}
            <aside className={`
                fixed lg:relative inset-y-0 left-0 w-[280px] bg-white border-r border-slate-100 z-[70] 
                transform transition-transform duration-500 ease-out flex flex-col
                ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
            `}>
                {/* Logo Section */}
                <div className="p-8 flex items-center justify-between">
                    <div className="flex items-center space-x-3 group cursor-pointer" onClick={() => navigate('/')}>
                        <div className="w-10 h-10 bg-slate-900 rounded-xl flex items-center justify-center transform group-hover:rotate-12 transition-transform duration-300">
                            <span className="text-white font-black text-xl">VR</span>
                        </div>
                        <div>
                            <h2 className="text-xl font-black text-slate-900 leading-none">VR HERE</h2>
                            <p className="text-[10px] text-red-600 font-black uppercase tracking-widest mt-1">Partner Portal</p>
                        </div>
                    </div>
                    <button className="lg:hidden p-2 text-slate-400 hover:text-slate-900" onClick={() => setIsSidebarOpen(false)}>
                        <X className="w-6 h-6" />
                    </button>
                </div>

                {/* Navigation */}
                <nav className="flex-grow px-6 space-y-2 mt-4">
                    {sidebarItems.map((item) => (
                        <button
                            key={item.name}
                            onClick={() => {
                                setActiveTab(item.name);
                                setIsSidebarOpen(false);
                            }}
                            className={`
                                w-full flex items-center justify-between px-4 py-4 rounded-2xl transition-all duration-300 group
                                ${activeTab === item.name 
                                    ? 'bg-slate-900 text-white shadow-xl shadow-slate-200' 
                                    : 'text-slate-500 hover:bg-slate-50 hover:text-slate-900'}
                            `}
                        >
                            <div className="flex items-center gap-3">
                                <item.icon className={`w-5 h-5 transition-transform duration-300 group-hover:scale-110 ${activeTab === item.name ? 'text-red-500' : ''}`} />
                                <span className="font-bold text-sm tracking-wide">{item.name}</span>
                            </div>
                            {activeTab === item.name && <ChevronRight className="w-4 h-4 text-red-500" />}
                        </button>
                    ))}
                </nav>

                {/* Bottom Section */}
                <div className="p-6 mt-auto">
                    <div className="bg-slate-50 rounded-3xl p-5 mb-4 border border-slate-100">
                        <div className="flex items-center gap-3 mb-3">
                            <div className="w-10 h-10 bg-white rounded-full border-2 border-white shadow-sm flex items-center justify-center overflow-hidden">
                                <UserIcon className="w-6 h-6 text-slate-300" />
                            </div>
                            <div className="flex-grow min-w-0">
                                <h4 className="text-sm font-black text-slate-900 truncate">{userInfo.name}</h4>
                                <p className="text-[10px] text-slate-400 font-bold uppercase truncate tracking-tight">{userInfo.email}</p>
                            </div>
                        </div>
                        <button 
                            onClick={handleLogout}
                            className="w-full h-11 bg-white border border-slate-200 rounded-xl flex items-center justify-center gap-2 text-sm font-bold text-red-600 hover:bg-red-50 hover:border-red-100 transition-all shadow-sm"
                        >
                            <LogOut className="w-4 h-4" /> Sign Out
                        </button>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <main className="flex-grow flex flex-col min-w-0 overflow-hidden">
                {/* Top Header */}
                <header className="h-20 bg-white border-b border-slate-100 flex items-center justify-between px-6 lg:px-10 shrink-0 relative z-50">
                    <div className="flex items-center gap-4">
                        <button 
                            className="lg:hidden p-2.5 bg-slate-50 rounded-xl text-slate-600 hover:text-slate-900 transition-colors shadow-sm"
                            onClick={() => setIsSidebarOpen(true)}
                        >
                            <Menu className="w-6 h-6" />
                        </button>
                        <div className="hidden sm:block">
                            <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">Welcome Back</span>
                            <h2 className="text-lg font-black text-slate-900 tracking-tight leading-none mt-0.5">{userInfo.name.split(' ')[0]}</h2>
                        </div>
                    </div>

                    <div className="flex items-center gap-3 md:gap-5">
                        <div className="hidden md:flex items-center px-4 py-2 bg-green-50 text-green-600 rounded-xl border border-green-100 text-[10px] font-black uppercase tracking-widest">
                             System Active
                        </div>
                        <button className="p-2.5 text-slate-400 hover:text-red-500 hover:bg-red-50 rounded-xl transition-all relative">
                            <Bell className="w-5 h-5" />
                            <span className="absolute top-2.5 right-2.5 w-2 h-2 bg-red-600 rounded-full border-2 border-white"></span>
                        </button>
                        <div className="w-10 h-10 bg-slate-900 rounded-xl flex items-center justify-center text-white shadow-lg shadow-slate-200 cursor-pointer hover:rotate-6 transition-transform">
                             <UserIcon className="w-5 h-5" />
                        </div>
                    </div>
                </header>

                {/* Content Area */}
                <div className="flex-grow overflow-y-auto custom-scrollbar bg-slate-50/50">
                    <div className="max-w-[1400px] mx-auto p-6 lg:p-10">
                        {activeTab === 'Overview' && <PartnerOverviewView userInfo={userInfo} mode="overview" />}
                        {activeTab === 'Referrals' && <PartnerOverviewView userInfo={userInfo} mode="referrals" />}
                        {activeTab === 'Settings' && (
                            <PartnerSettingsView 
                                userInfo={userInfo} 
                                onProfileUpdate={(updated) => setUserInfo(updated)} 
                            />
                        )}
                    </div>
                </div>
            </main>
        </div>
    );
};

export default PartnerDashboard;
