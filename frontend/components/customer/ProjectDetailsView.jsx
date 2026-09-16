import React, { useState, useMemo } from 'react';
import axios from 'axios';
import { 
    ArrowLeft, Clock, FileText, Mail, Phone, User, 
    CheckCircle2, Circle, AlertCircle, FileCheck, IndianRupee,
    Download, ExternalLink, ShieldCheck, ChevronDown, ChevronUp,
    MessageSquare, Send, Loader2, Sparkles, CreditCard, Lock,
    CheckCircle, ListOrdered, FolderOpen, Layers, Shield
} from 'lucide-react';
import RequirementsWorkspace from './RequirementsWorkspace';
import { launchRazorpayCheckout } from '../../utils/razorpayCheckout';

const getStatusProgress = (status, tasks = []) => {
    // If tasks exist, calculate dynamic weighted progress
    if (tasks && tasks.length > 0) {
        let totalItems = 0;
        let completedItems = 0;

        tasks.forEach((t) => {
            totalItems += 1;
            if (t.status === 'Completed') completedItems += 1;

            if (t.subtasks && t.subtasks.length > 0) {
                t.subtasks.forEach((st) => {
                    totalItems += 1;
                    if (st.status === 'Completed' || st.isCompleted) completedItems += 1;
                });
            }
        });

        if (totalItems > 0) {
            const calculated = Math.round((completedItems / totalItems) * 100);
            if (status === 'Completed') return 100;
            return Math.max(15, Math.min(95, calculated));
        }
    }

    switch (status) {
        case 'Pending Documents': return 20;
        case 'Documents Verified': return 40;
        case 'Processing at Portal': return 65;
        case 'Waiting for Clarification': return 75;
        case 'Completed': return 100;
        default: return 10;
    }
};

const PHASES = [
    { label: 'Pending Documents', step: 1 },
    { label: 'Documents Verified', step: 2 },
    { label: 'Processing at Portal', step: 3 },
    { label: 'Waiting for Clarification', step: 4 },
    { label: 'Completed', step: 5 }
];

const getPhaseStepIndex = (status) => {
    const found = PHASES.findIndex((p) => p.label === status);
    return found !== -1 ? found + 1 : 1;
};

const ProjectDetailsView = ({ 
    order, 
    payments = [], 
    onBack, 
    onOpenVault, 
    setActiveTab, 
    userInfo, 
    refreshOrders 
}) => {
    const [currentTab, setCurrentTab] = useState('overview'); // 'overview' | 'requirements' | 'documents' | 'financials'
    const [expandedTasks, setExpandedTasks] = useState({});
    const [isPaying, setIsPaying] = useState(false);
    const [isTicketModalOpen, setIsTicketModalOpen] = useState(false);
    const [ticketData, setTicketData] = useState({
        title: `Query regarding Order ${order?._id?.slice(-8)?.toUpperCase() || ''}: ${order?.serviceName || ''}`,
        category: 'Order',
        priority: 'Medium',
        description: ''
    });
    const [isSubmittingTicket, setIsSubmittingTicket] = useState(false);
    const [ticketSuccessMsg, setTicketSuccessMsg] = useState('');

    // Filter payments for this order
    const orderPayments = useMemo(() => {
        return (payments || []).filter((p) => {
            const pOrderId = p.order?._id || p.order;
            return pOrderId === order?._id;
        });
    }, [payments, order?._id]);

    const totalPaid = useMemo(() => {
        return orderPayments.reduce((acc, curr) => acc + (curr.status === 'Completed' || curr.status === 'Paid' ? Number(curr.amount || 0) : 0), 0);
    }, [orderPayments]);

    const orderPrice = Number(order?.price || 0);
    const balanceDue = Math.max(0, orderPrice - totalPaid);

    // Resolve assigned staff
    const assignedExpert = order?.assignedProjectManager || order?.assignedEmployee || order?.assignedMaker || null;
    const expertRole = order?.assignedProjectManager 
        ? 'Project Manager' 
        : (order?.assignedMaker ? 'Lead Operations Specialist' : (order?.assignedEmployee?.role || 'Relationship Manager'));

    const toggleTaskExpand = (taskId) => {
        setExpandedTasks((prev) => ({
            ...prev,
            [taskId]: !prev[taskId]
        }));
    };

    const handlePayBalance = async () => {
        if (balanceDue <= 0) return;
        setIsPaying(true);
        try {
            await launchRazorpayCheckout({
                amount: balanceDue,
                serviceName: order?.serviceName || 'Order Balance Payment',
                packageName: order?.packageName || 'Standard',
                customerName: userInfo?.name || order?.clientName || '',
                customerEmail: userInfo?.email || order?.clientEmail || '',
                customerPhone: userInfo?.phone || order?.clientPhone || '',
                token: userInfo?.token,
                onSuccess: async () => {
                    alert('Payment successful! Your order balance has been updated.');
                    if (refreshOrders) await refreshOrders();
                },
                onFailure: (err) => {
                    alert(err?.message || 'Payment was cancelled or failed.');
                },
                onSubmittingChange: setIsPaying
            });
        } catch (err) {
            console.error('Payment launch error:', err);
            alert(err?.message || 'Failed to initiate payment.');
        } finally {
            setIsPaying(false);
        }
    };

    const handleCreateTicket = async (e) => {
        e.preventDefault();
        if (!ticketData.description.trim()) {
            alert('Please provide a brief description of your query.');
            return;
        }
        setIsSubmittingTicket(true);
        try {
            const config = {
                headers: { Authorization: `Bearer ${userInfo?.token}` }
            };
            await axios.post('/api/tickets', {
                title: ticketData.title,
                category: ticketData.category,
                priority: ticketData.priority,
                description: ticketData.description,
                orderId: order?._id
            }, config);

            setTicketSuccessMsg('Support ticket raised successfully! Your Project Manager has been notified.');
            setTimeout(() => {
                setIsTicketModalOpen(false);
                setTicketSuccessMsg('');
                setTicketData((prev) => ({ ...prev, description: '' }));
            }, 2500);
        } catch (err) {
            alert(err.response?.data?.message || 'Failed to create ticket.');
        } finally {
            setIsSubmittingTicket(false);
        }
    };

    const progressPercentage = getStatusProgress(order?.status, order?.tasks);
    const currentStepIndex = getPhaseStepIndex(order?.status);

    const hasRequirements = order?.customerRequirements && order.customerRequirements.length > 0;
    const finalCertificateUrl = order?.finalCertificate || (order?.adminDocuments && order.adminDocuments.length > 0 ? order.adminDocuments[order.adminDocuments.length - 1]?.url : null);

    return (
        <div className="space-y-6 pb-20 md:pb-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {/* Top Navigation Bar */}
            <div className="flex flex-wrap items-center justify-between gap-4 px-1">
                <div className="flex items-center gap-3.5">
                    <button 
                        onClick={onBack}
                        className="p-2.5 bg-white border border-slate-200 rounded-2xl text-slate-600 hover:bg-slate-50 transition-all shadow-xs"
                        title="Back to Orders"
                    >
                        <ArrowLeft size={18} />
                    </button>
                    <div>
                        <div className="flex items-center gap-2">
                            <h1 className="text-2xl font-black text-slate-900 tracking-tight">{order?.serviceName}</h1>
                            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider bg-red-50 text-red-600 border border-red-100">
                                {order?.status}
                            </span>
                        </div>
                        <p className="text-slate-400 text-xs font-semibold mt-0.5">
                            Order ID: <span className="text-slate-700 font-bold">#{order?._id?.slice(-8)?.toUpperCase()}</span> • {order?.packageName || 'Standard'} • Placed {new Date(order?.createdAt || Date.now()).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })}
                        </p>
                    </div>
                </div>

                <div className="flex items-center gap-2.5">
                    <button
                        onClick={() => setIsTicketModalOpen(true)}
                        className="px-4 py-2.5 rounded-2xl bg-white border border-slate-200 text-slate-700 hover:bg-slate-50 text-xs font-extrabold transition-all flex items-center gap-2 shadow-xs"
                    >
                        <MessageSquare size={15} className="text-indigo-600" />
                        <span>Ask Query / Support</span>
                    </button>

                    {balanceDue > 0 && (
                        <button
                            onClick={handlePayBalance}
                            disabled={isPaying}
                            className="px-4 py-2.5 rounded-2xl bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-700 hover:to-rose-700 text-white text-xs font-black transition-all flex items-center gap-2 shadow-md shadow-red-500/20 active:scale-95 disabled:opacity-50"
                        >
                            {isPaying ? <Loader2 size={14} className="animate-spin" /> : <CreditCard size={14} />}
                            <span>Pay Balance ₹{balanceDue.toLocaleString()}</span>
                        </button>
                    )}
                </div>
            </div>

            {/* Completion / Final Deliverables Banner (If order completed or has final certificate) */}
            {(order?.status === 'Completed' || finalCertificateUrl) && (
                <div className="p-6 rounded-3xl bg-gradient-to-br from-emerald-600 via-emerald-700 to-teal-800 text-white shadow-xl shadow-emerald-500/15 relative overflow-hidden">
                    <div className="absolute right-0 top-0 w-80 h-80 bg-white/10 rounded-full blur-3xl -mr-20 -mt-20 pointer-events-none" />
                    <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
                        <div className="space-y-1.5 max-w-xl">
                            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/20 text-[11px] font-black uppercase tracking-wider backdrop-blur-md">
                                <Sparkles size={13} className="text-amber-300" /> Official Deliverables Ready
                            </div>
                            <h2 className="text-xl font-black tracking-tight">Project Completed Successfully!</h2>
                            <p className="text-emerald-100 text-xs font-medium leading-relaxed">
                                All statutory filings and government formalities for <strong className="text-white">{order?.serviceName}</strong> have been finalized and verified by our audit team.
                            </p>
                        </div>
                        {finalCertificateUrl && (
                            <a
                                href={finalCertificateUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="px-5 py-3 rounded-2xl bg-white text-emerald-900 hover:bg-emerald-50 text-xs font-black flex items-center gap-2.5 shadow-lg shadow-black/10 transition-all shrink-0 active:scale-95"
                            >
                                <Download size={16} className="text-emerald-600" />
                                <span>Download Final Certificate</span>
                            </a>
                        )}
                    </div>
                </div>
            )}

            {/* Navigation Tabs */}
            <div className="flex border-b border-slate-200 overflow-x-auto gap-2 scrollbar-none">
                <button
                    onClick={() => setCurrentTab('overview')}
                    className={`px-4 py-3 text-xs font-black uppercase tracking-wider border-b-2 transition-all flex items-center gap-2 whitespace-nowrap ${
                        currentTab === 'overview'
                            ? 'border-red-600 text-red-600'
                            : 'border-transparent text-slate-500 hover:text-slate-800'
                    }`}
                >
                    <ListOrdered size={15} /> Overview & Milestones
                </button>

                <button
                    onClick={() => setCurrentTab('requirements')}
                    className={`px-4 py-3 text-xs font-black uppercase tracking-wider border-b-2 transition-all flex items-center gap-2 whitespace-nowrap ${
                        currentTab === 'requirements'
                            ? 'border-red-600 text-red-600'
                            : 'border-transparent text-slate-500 hover:text-slate-800'
                    }`}
                >
                    <FileCheck size={15} /> Checklist & Requirements
                    {hasRequirements && (
                        <span className="px-1.5 py-0.5 rounded-full bg-slate-100 text-slate-700 text-[10px] font-bold">
                            {order.customerRequirements.length}
                        </span>
                    )}
                </button>

                <button
                    onClick={() => setCurrentTab('documents')}
                    className={`px-4 py-3 text-xs font-black uppercase tracking-wider border-b-2 transition-all flex items-center gap-2 whitespace-nowrap ${
                        currentTab === 'documents'
                            ? 'border-red-600 text-red-600'
                            : 'border-transparent text-slate-500 hover:text-slate-800'
                    }`}
                >
                    <FolderOpen size={15} /> Vault & Documents
                </button>

                <button
                    onClick={() => setCurrentTab('financials')}
                    className={`px-4 py-3 text-xs font-black uppercase tracking-wider border-b-2 transition-all flex items-center gap-2 whitespace-nowrap ${
                        currentTab === 'financials'
                            ? 'border-red-600 text-red-600'
                            : 'border-transparent text-slate-500 hover:text-slate-800'
                    }`}
                >
                    <IndianRupee size={15} /> Invoices & Payments
                </button>
            </div>

            {/* Tab 1: Overview & Milestones */}
            {currentTab === 'overview' && (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Left Column (2/3) */}
                    <div className="lg:col-span-2 space-y-6">
                        {/* Overall Progress Card */}
                        <div className="bg-white rounded-3xl border border-slate-200/80 shadow-xs p-6">
                            <div className="flex justify-between items-center mb-4">
                                <div>
                                    <h3 className="text-sm font-black text-slate-900">Project Completion Status</h3>
                                    <p className="text-xs text-slate-400 font-medium">Real-time status tracking & milestone progress</p>
                                </div>
                                <div className="text-right">
                                    <span className="text-2xl font-black text-red-600">{progressPercentage}%</span>
                                    <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Complete</p>
                                </div>
                            </div>

                            <div className="w-full h-3 bg-slate-100 rounded-full overflow-hidden mb-6">
                                <div
                                    className="h-full bg-gradient-to-r from-red-600 via-rose-500 to-red-500 rounded-full transition-all duration-1000 ease-out"
                                    style={{ width: `${progressPercentage}%` }}
                                />
                            </div>

                            {/* Phase Stepper */}
                            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-2 border-t border-slate-100">
                                {PHASES.map((phase, idx) => {
                                    const isDone = idx + 1 < currentStepIndex || order?.status === 'Completed';
                                    const isCurrent = idx + 1 === currentStepIndex && order?.status !== 'Completed';

                                    return (
                                        <div key={phase.label} className="text-center p-2 rounded-2xl transition-all">
                                            <div className={`w-7 h-7 mx-auto mb-1.5 rounded-full flex items-center justify-center text-xs font-black transition-all ${
                                                isDone 
                                                    ? 'bg-emerald-500 text-white' 
                                                    : isCurrent 
                                                        ? 'bg-red-600 text-white ring-4 ring-red-100' 
                                                        : 'bg-slate-100 text-slate-400'
                                            }`}>
                                                {isDone ? <CheckCircle size={14} /> : idx + 1}
                                            </div>
                                            <p className={`text-[10px] font-black uppercase tracking-tight leading-tight line-clamp-2 ${
                                                isCurrent ? 'text-red-600 font-bold' : isDone ? 'text-slate-800' : 'text-slate-400'
                                            }`}>
                                                {phase.label}
                                            </p>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>

                        {/* Workflow Tasks Breakdown */}
                        <div className="bg-white rounded-3xl border border-slate-200/80 shadow-xs p-6">
                            <div className="flex items-center justify-between mb-5">
                                <div>
                                    <h3 className="text-sm font-black text-slate-900">Execution Stages & Milestones</h3>
                                    <p className="text-xs text-slate-400 font-medium">Step-by-step statutory process managed by our specialists</p>
                                </div>
                                <span className="text-xs font-bold text-slate-400">
                                    {(order?.tasks || []).length} Main Tasks
                                </span>
                            </div>

                            {order?.tasks && order.tasks.length > 0 ? (
                                <div className="space-y-3">
                                    {order.tasks.map((task, idx) => {
                                        const isExpanded = expandedTasks[task._id];
                                        const hasSubtasks = task.subtasks && task.subtasks.length > 0;
                                        const completedSubtasks = (task.subtasks || []).filter(st => st.status === 'Completed' || st.isCompleted).length;

                                        return (
                                            <div key={task._id || idx} className="border border-slate-200/80 rounded-2xl p-4 bg-slate-50/50 hover:bg-white transition-all">
                                                <div 
                                                    onClick={() => hasSubtasks && toggleTaskExpand(task._id)}
                                                    className={`flex items-start justify-between gap-3 ${hasSubtasks ? 'cursor-pointer' : ''}`}
                                                >
                                                    <div className="flex items-start gap-3">
                                                        <div className="mt-0.5">
                                                            {task.status === 'Completed' ? (
                                                                <CheckCircle2 size={18} className="text-emerald-500" />
                                                            ) : task.status === 'In Progress' ? (
                                                                <Clock size={18} className="text-indigo-600 animate-pulse" />
                                                            ) : (
                                                                <Circle size={18} className="text-slate-300" />
                                                            )}
                                                        </div>
                                                        <div>
                                                            <div className="flex items-center gap-2">
                                                                <p className={`text-xs font-black ${task.status === 'Completed' ? 'text-slate-800' : 'text-slate-900'}`}>
                                                                    {task.taskCode ? `${task.taskCode}: ` : ''}{task.title}
                                                                </p>
                                                                <span className={`px-2 py-0.5 rounded-md text-[9px] font-black uppercase tracking-wider ${
                                                                    task.status === 'Completed'
                                                                        ? 'bg-emerald-100 text-emerald-800'
                                                                        : task.status === 'In Progress'
                                                                            ? 'bg-blue-100 text-blue-800'
                                                                            : 'bg-slate-200 text-slate-600'
                                                                }`}>
                                                                    {task.status || 'Pending'}
                                                                </span>
                                                            </div>
                                                            {task.description && (
                                                                <p className="text-[11px] text-slate-500 mt-0.5">{task.description}</p>
                                                            )}
                                                            {hasSubtasks && (
                                                                <p className="text-[10px] text-slate-400 font-bold mt-1">
                                                                    {completedSubtasks} of {task.subtasks.length} steps completed
                                                                </p>
                                                            )}
                                                        </div>
                                                    </div>

                                                    {hasSubtasks && (
                                                        <button 
                                                            type="button" 
                                                            className="text-slate-400 hover:text-slate-600 p-1"
                                                            aria-label="Toggle subtasks"
                                                        >
                                                            {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                                                        </button>
                                                    )}
                                                </div>

                                                {/* Subtasks Accordion */}
                                                {hasSubtasks && isExpanded && (
                                                    <div className="mt-3 pt-3 border-t border-slate-200/60 pl-7 space-y-2">
                                                        {task.subtasks.map((st, sIdx) => (
                                                            <div key={st._id || sIdx} className="flex items-center justify-between text-xs py-1 border-b border-slate-100 last:border-0">
                                                                <div className="flex items-center gap-2">
                                                                    <div className={`w-2 h-2 rounded-full ${st.status === 'Completed' || st.isCompleted ? 'bg-emerald-500' : 'bg-slate-300'}`} />
                                                                    <span className="font-semibold text-slate-700">
                                                                        {st.subTaskCode ? `${st.subTaskCode} • ` : ''}{st.title}
                                                                    </span>
                                                                </div>
                                                                <div className="flex items-center gap-3">
                                                                    {st.duration && <span className="text-[10px] text-slate-400 font-medium">Est: {st.duration}</span>}
                                                                    <span className={`text-[10px] font-bold uppercase ${
                                                                        st.status === 'Completed' || st.isCompleted ? 'text-emerald-600' : 'text-slate-400'
                                                                    }`}>
                                                                        {st.status || (st.isCompleted ? 'Completed' : 'Pending')}
                                                                    </span>
                                                                </div>
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}
                                            </div>
                                        );
                                    })}
                                </div>
                            ) : (
                                <div className="text-center py-8 text-slate-400 bg-slate-50/50 rounded-2xl border border-dashed border-slate-200">
                                    <Clock size={28} className="mx-auto mb-2 opacity-50" />
                                    <p className="text-xs font-bold text-slate-600">Tasks are being initialized by your Project Manager.</p>
                                    <p className="text-[11px] text-slate-400 mt-0.5">Workflow stages will update live as progress is made.</p>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Right Sidebar (1/3) */}
                    <div className="space-y-6">
                        {/* Assigned Expert / Team Card */}
                        <div className="bg-white rounded-3xl border border-slate-200/80 shadow-xs p-6 relative overflow-hidden">
                            <div className="flex items-center justify-between mb-4">
                                <h3 className="text-sm font-black text-slate-900">Dedicated Expert</h3>
                                <span className="px-2 py-0.5 rounded-md bg-indigo-50 text-indigo-700 text-[10px] font-black uppercase">
                                    Verified
                                </span>
                            </div>

                            {assignedExpert ? (
                                <div className="space-y-4">
                                    <div className="flex items-center gap-3.5">
                                        {assignedExpert.profilePhoto ? (
                                            <img 
                                                src={assignedExpert.profilePhoto} 
                                                alt={assignedExpert.name} 
                                                className="w-12 h-12 rounded-2xl object-cover border border-slate-200"
                                            />
                                        ) : (
                                            <div className="w-12 h-12 bg-gradient-to-br from-indigo-500 to-blue-600 text-white rounded-2xl flex items-center justify-center font-black text-base shadow-sm">
                                                {assignedExpert.name ? assignedExpert.name.charAt(0).toUpperCase() : 'E'}
                                            </div>
                                        )}
                                        <div>
                                            <p className="text-sm font-black text-slate-900">{assignedExpert.name}</p>
                                            <p className="text-[11px] font-bold text-indigo-600 uppercase tracking-wider">{expertRole}</p>
                                        </div>
                                    </div>

                                    <div className="pt-3 border-t border-slate-100 space-y-2.5">
                                        {assignedExpert.email && (
                                            <a 
                                                href={`mailto:${assignedExpert.email}`}
                                                className="flex items-center gap-2.5 text-xs text-slate-600 hover:text-indigo-600 font-semibold transition-colors"
                                            >
                                                <div className="w-7 h-7 rounded-xl bg-slate-50 flex items-center justify-center text-slate-400">
                                                    <Mail size={13} />
                                                </div>
                                                <span className="truncate">{assignedExpert.email}</span>
                                            </a>
                                        )}
                                        {assignedExpert.phone && (
                                            <a 
                                                href={`tel:${assignedExpert.phone}`}
                                                className="flex items-center gap-2.5 text-xs text-slate-600 hover:text-indigo-600 font-semibold transition-colors"
                                            >
                                                <div className="w-7 h-7 rounded-xl bg-slate-50 flex items-center justify-center text-slate-400">
                                                    <Phone size={13} />
                                                </div>
                                                <span>{assignedExpert.phone}</span>
                                            </a>
                                        )}
                                    </div>

                                    <button
                                        onClick={() => setIsTicketModalOpen(true)}
                                        className="w-full py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-bold transition-all flex items-center justify-center gap-2 shadow-sm"
                                    >
                                        <MessageSquare size={13} /> Contact Manager
                                    </button>
                                </div>
                            ) : (
                                <div className="text-center py-6 text-slate-400 bg-slate-50 rounded-2xl border border-dashed border-slate-200">
                                    <User size={28} className="mx-auto mb-2 opacity-50 text-indigo-500" />
                                    <p className="text-xs font-bold text-slate-700">Expert assignment in progress</p>
                                    <p className="text-[11px] text-slate-400 mt-1">Our ops desk is assigning the best domain specialist for your request.</p>
                                </div>
                            )}
                        </div>

                        {/* Financial Card */}
                        <div className="bg-white rounded-3xl border border-slate-200/80 shadow-xs p-6">
                            <h3 className="text-sm font-black text-slate-900 mb-4 flex items-center gap-2">
                                <IndianRupee size={16} className="text-red-600" /> Financial Overview
                            </h3>

                            <div className="space-y-3">
                                <div className="flex justify-between items-center text-xs font-semibold text-slate-600">
                                    <span>Total Package Price</span>
                                    <span className="font-bold text-slate-900">₹{orderPrice.toLocaleString()}</span>
                                </div>
                                <div className="flex justify-between items-center text-xs font-semibold text-emerald-600">
                                    <span>Amount Paid</span>
                                    <span className="font-bold">₹{totalPaid.toLocaleString()}</span>
                                </div>
                                <div className="pt-3 border-t border-slate-100 flex justify-between items-center text-sm font-black text-slate-900">
                                    <span>Balance Due</span>
                                    <span className={balanceDue > 0 ? 'text-red-600' : 'text-emerald-600'}>
                                        ₹{balanceDue.toLocaleString()}
                                    </span>
                                </div>
                            </div>

                            {balanceDue > 0 ? (
                                <button
                                    onClick={handlePayBalance}
                                    disabled={isPaying}
                                    className="w-full mt-4 py-3 rounded-2xl bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-700 hover:to-rose-700 text-white text-xs font-black transition-all flex items-center justify-center gap-2 shadow-md shadow-red-500/20 active:scale-98 disabled:opacity-50"
                                >
                                    {isPaying ? <Loader2 size={15} className="animate-spin" /> : <CreditCard size={15} />}
                                    <span>Pay Outstanding Balance</span>
                                </button>
                            ) : (
                                <div className="mt-4 p-2.5 rounded-xl bg-emerald-50 text-emerald-700 text-xs font-bold text-center flex items-center justify-center gap-1.5 border border-emerald-100">
                                    <ShieldCheck size={14} /> Full Payment Settled
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* Tab 2: Requirements & Checklist */}
            {currentTab === 'requirements' && (
                <div className="bg-white rounded-3xl border border-slate-200/80 shadow-xs p-6">
                    <RequirementsWorkspace 
                        selectedOrder={order} 
                        userInfo={userInfo} 
                        refreshOrders={refreshOrders} 
                    />
                </div>
            )}

            {/* Tab 3: Vault & Documents */}
            {currentTab === 'documents' && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Client Documents */}
                    <div className="bg-white rounded-3xl border border-slate-200/80 shadow-xs p-6 space-y-4">
                        <div className="flex justify-between items-center border-b border-slate-100 pb-3">
                            <h3 className="text-sm font-black text-slate-900 flex items-center gap-2">
                                <FileCheck size={16} className="text-indigo-600" /> Uploaded Documents ({order?.clientDocuments?.length || 0})
                            </h3>
                            <button
                                onClick={onOpenVault}
                                className="text-xs font-bold text-red-600 hover:underline"
                            >
                                Open Full Vault
                            </button>
                        </div>

                        {order?.clientDocuments && order.clientDocuments.length > 0 ? (
                            <div className="space-y-2.5">
                                {order.clientDocuments.map((doc) => (
                                    <div key={doc._id} className="p-3 bg-slate-50 rounded-2xl flex items-center justify-between gap-3 border border-slate-100">
                                        <div className="flex items-center gap-3 truncate">
                                            <FileText size={16} className="text-slate-400 shrink-0" />
                                            <div className="truncate">
                                                <p className="text-xs font-bold text-slate-800 truncate">{doc.name}</p>
                                                <p className="text-[10px] text-slate-400 font-medium">Uploaded {new Date(doc.uploadedAt || Date.now()).toLocaleDateString()}</p>
                                            </div>
                                        </div>
                                        {doc.url && (
                                            <a
                                                href={doc.url}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="p-2 bg-white rounded-xl text-slate-600 hover:text-indigo-600 border border-slate-200 text-xs shadow-2xs"
                                                title="View Document"
                                            >
                                                <ExternalLink size={13} />
                                            </a>
                                        )}
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <p className="text-xs text-slate-400 italic py-6 text-center">No documents uploaded yet for this order.</p>
                        )}
                    </div>

                    {/* Admin / Official Issued Documents */}
                    <div className="bg-white rounded-3xl border border-slate-200/80 shadow-xs p-6 space-y-4">
                        <div className="flex justify-between items-center border-b border-slate-100 pb-3">
                            <h3 className="text-sm font-black text-slate-900 flex items-center gap-2">
                                <ShieldCheck size={16} className="text-emerald-600" /> Government & Statutory Deliverables ({order?.adminDocuments?.length || 0})
                            </h3>
                        </div>

                        {order?.adminDocuments && order.adminDocuments.length > 0 ? (
                            <div className="space-y-2.5">
                                {order.adminDocuments.map((doc) => (
                                    <div key={doc._id} className="p-3 bg-emerald-50/60 rounded-2xl flex items-center justify-between gap-3 border border-emerald-100">
                                        <div className="flex items-center gap-3 truncate">
                                            <FileCheck size={16} className="text-emerald-600 shrink-0" />
                                            <div className="truncate">
                                                <p className="text-xs font-bold text-slate-900 truncate">{doc.name}</p>
                                                <p className="text-[10px] text-emerald-700 font-medium">Issued {new Date(doc.uploadedAt || Date.now()).toLocaleDateString()}</p>
                                            </div>
                                        </div>
                                        {doc.url && (
                                            <a
                                                href={doc.url}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="px-3 py-1.5 bg-emerald-600 text-white rounded-xl hover:bg-emerald-700 text-xs font-bold flex items-center gap-1.5 shadow-2xs"
                                            >
                                                <Download size={12} /> Download
                                            </a>
                                        )}
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <p className="text-xs text-slate-400 italic py-6 text-center">Official filings and certificates will appear here once processed by government portals.</p>
                        )}
                    </div>
                </div>
            )}

            {/* Tab 4: Invoices & Payments */}
            {currentTab === 'financials' && (
                <div className="bg-white rounded-3xl border border-slate-200/80 shadow-xs p-6 space-y-6">
                    <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-100 pb-4">
                        <div>
                            <h3 className="text-sm font-black text-slate-900">Invoices & Payment Receipts</h3>
                            <p className="text-xs text-slate-400 font-medium">GST compliant invoices and verified payment transaction records</p>
                        </div>
                        {balanceDue > 0 && (
                            <button
                                onClick={handlePayBalance}
                                disabled={isPaying}
                                className="px-4 py-2.5 rounded-xl bg-red-600 hover:bg-red-700 text-white text-xs font-black transition-all flex items-center gap-2 shadow-md shadow-red-500/20"
                            >
                                <CreditCard size={14} /> Settle Balance Due (₹{balanceDue.toLocaleString()})
                            </button>
                        )}
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="p-4 rounded-2xl bg-slate-50 border border-slate-100">
                            <p className="text-[10px] font-black uppercase text-slate-400 tracking-wider">Total Value</p>
                            <p className="text-xl font-black text-slate-900 mt-1">₹{orderPrice.toLocaleString()}</p>
                        </div>
                        <div className="p-4 rounded-2xl bg-emerald-50 border border-emerald-100">
                            <p className="text-[10px] font-black uppercase text-emerald-600 tracking-wider">Paid to Date</p>
                            <p className="text-xl font-black text-emerald-700 mt-1">₹{totalPaid.toLocaleString()}</p>
                        </div>
                        <div className="p-4 rounded-2xl bg-rose-50 border border-rose-100">
                            <p className="text-[10px] font-black uppercase text-rose-600 tracking-wider">Outstanding Balance</p>
                            <p className="text-xl font-black text-rose-700 mt-1">₹{balanceDue.toLocaleString()}</p>
                        </div>
                    </div>

                    <div className="space-y-3">
                        <h4 className="text-xs font-black uppercase tracking-wider text-slate-400">Payment Transactions</h4>
                        {orderPayments && orderPayments.length > 0 ? (
                            <div className="border border-slate-200 rounded-2xl overflow-hidden">
                                <table className="w-full text-xs text-left">
                                    <thead className="bg-slate-50 border-b border-slate-200 text-slate-400 font-black uppercase text-[10px]">
                                        <tr>
                                            <th className="p-3.5">Date</th>
                                            <th className="p-3.5">Payment ID</th>
                                            <th className="p-3.5">Method</th>
                                            <th className="p-3.5">Amount</th>
                                            <th className="p-3.5">Status</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-100 font-medium">
                                        {orderPayments.map((p) => (
                                            <tr key={p._id} className="hover:bg-slate-50/50">
                                                <td className="p-3.5 text-slate-800">{new Date(p.createdAt).toLocaleDateString()}</td>
                                                <td className="p-3.5 font-mono text-slate-500 text-[11px]">{p.razorpayPaymentId || p._id?.slice(-8)}</td>
                                                <td className="p-3.5 text-slate-600 capitalize">{p.paymentMethod || 'Razorpay / Online'}</td>
                                                <td className="p-3.5 font-bold text-slate-900">₹{Number(p.amount || 0).toLocaleString()}</td>
                                                <td className="p-3.5">
                                                    <span className={`px-2 py-0.5 rounded-md text-[10px] font-black uppercase ${
                                                        p.status === 'Completed' || p.status === 'Paid'
                                                            ? 'bg-emerald-100 text-emerald-800'
                                                            : 'bg-amber-100 text-amber-800'
                                                    }`}>
                                                        {p.status}
                                                    </span>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        ) : (
                            <p className="text-xs text-slate-400 italic py-4 text-center">No payment transactions recorded yet.</p>
                        )}
                    </div>
                </div>
            )}

            {/* Modal: Raise Support Query for this Order */}
            {isTicketModalOpen && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 animate-in fade-in">
                    <div className="bg-white rounded-3xl max-w-lg w-full p-6 shadow-2xl border border-slate-100 space-y-4">
                        <div className="flex justify-between items-center border-b border-slate-100 pb-3">
                            <div>
                                <h3 className="text-base font-black text-slate-900">Ask Query / Raise Ticket</h3>
                                <p className="text-xs text-slate-400 font-medium">Direct communication with your designated team</p>
                            </div>
                            <button 
                                onClick={() => setIsTicketModalOpen(false)}
                                className="p-1 rounded-lg text-slate-400 hover:text-slate-600"
                            >
                                ✕
                            </button>
                        </div>

                        {ticketSuccessMsg ? (
                            <div className="p-4 bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-2xl text-xs font-bold flex items-center gap-2">
                                <CheckCircle size={16} className="text-emerald-600" />
                                <span>{ticketSuccessMsg}</span>
                            </div>
                        ) : (
                            <form onSubmit={handleCreateTicket} className="space-y-4">
                                <div>
                                    <label className="block text-[10px] font-black uppercase tracking-wider text-slate-400 mb-1">Subject</label>
                                    <input
                                        type="text"
                                        value={ticketData.title}
                                        onChange={(e) => setTicketData({ ...ticketData, title: e.target.value })}
                                        required
                                        className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs font-bold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500"
                                    />
                                </div>

                                <div>
                                    <label className="block text-[10px] font-black uppercase tracking-wider text-slate-400 mb-1">Message / Question</label>
                                    <textarea
                                        rows={4}
                                        value={ticketData.description}
                                        onChange={(e) => setTicketData({ ...ticketData, description: e.target.value })}
                                        placeholder="Type your question or clarification request here..."
                                        required
                                        className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500"
                                    />
                                </div>

                                <div className="flex justify-end gap-3 pt-2">
                                    <button
                                        type="button"
                                        onClick={() => setIsTicketModalOpen(false)}
                                        className="px-4 py-2.5 rounded-xl border border-slate-200 text-slate-600 text-xs font-bold hover:bg-slate-50"
                                    >
                                        Cancel
                                    </button>
                                    <button
                                        type="submit"
                                        disabled={isSubmittingTicket}
                                        className="px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-black shadow-md shadow-indigo-200 flex items-center gap-2 disabled:opacity-50"
                                    >
                                        {isSubmittingTicket ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />}
                                        <span>Submit Ticket</span>
                                    </button>
                                </div>
                            </form>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
};

export default ProjectDetailsView;
