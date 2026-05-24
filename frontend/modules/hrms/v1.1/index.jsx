import React, { useState } from 'react';
import LeaveForm from './components/LeaveForm';
import LeaveApprovals from './components/LeaveApprovals';
import HolidayNoticeManager from './components/HolidayNoticeManager';
import NoticeBoard from './components/NoticeBoard';
import LiveStatusDashboard from './components/LiveStatusDashboard';

/**
 * HRMS Module Entrypoint
 * 
 * @param {Object} props
 * @param {string} props.role - User role ('admin' | 'employee' | 'client' | 'partner')
 */
const HRMSModule = ({ role = 'employee' }) => {
    const isAdmin = role === 'admin';
    const [activeTab, setActiveTab] = useState(isAdmin ? 'live' : 'bulletin');

    const adminTabs = [
        { id: 'live', label: 'Workforce Live Tracker', icon: '🟢' },
        { id: 'approvals', label: 'Leave Approvals', icon: '📝' },
        { id: 'bulletin-mgmt', label: 'Bulletin Board Manager', icon: '📢' }
    ];

    const employeeTabs = [
        { id: 'bulletin', label: 'Notice Board & Calendar', icon: '📅' },
        { id: 'leave', label: 'Apply for Leaves', icon: '✉️' }
    ];

    const tabs = isAdmin ? adminTabs : employeeTabs;

    return (
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 animate-fade-in space-y-6">
            
            {/* Header branding */}
            <div className="flex justify-between items-center border-b border-slate-100 pb-5">
                <div>
                    <h2 className="text-2xl font-black text-slate-800 tracking-tight flex items-center gap-2">
                        💼 HRMS Portal
                    </h2>
                    <p className="text-sm text-slate-400 mt-1">Human Resource Management System — v1.1</p>
                </div>
            </div>

            {/* Navigation Tabs */}
            <div className="flex border-b border-slate-200 gap-1 overflow-x-auto pb-px">
                {tabs.map((t) => (
                    <button
                        key={t.id}
                        onClick={() => setActiveTab(t.id)}
                        className={`flex items-center gap-2 px-6 py-4 font-bold text-sm border-b-2 whitespace-nowrap transition-all duration-200 ${
                            activeTab === t.id
                                ? 'border-indigo-600 text-indigo-600 bg-indigo-50/10'
                                : 'border-transparent text-slate-500 hover:text-slate-800 hover:border-slate-300'
                        }`}
                    >
                        <span>{t.icon}</span>
                        {t.label}
                    </button>
                ))}
            </div>

            {/* Render Active Tab Screen */}
            <div className="mt-8">
                {isAdmin ? (
                    <>
                        {activeTab === 'live' && <LiveStatusDashboard />}
                        {activeTab === 'approvals' && <LeaveApprovals />}
                        {activeTab === 'bulletin-mgmt' && <HolidayNoticeManager />}
                    </>
                ) : (
                    <>
                        {activeTab === 'bulletin' && <NoticeBoard />}
                        {activeTab === 'leave' && <LeaveForm />}
                    </>
                )}
            </div>
        </div>
    );
};

export default HRMSModule;
