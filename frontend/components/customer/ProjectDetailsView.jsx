import React, { useState, useMemo } from 'react';
import axios from 'axios';
import { 
    ArrowLeft, Clock, FileText, Mail, Phone, User, 
    CheckCircle2, Circle, AlertCircle, FileCheck, IndianRupee,
    Download, ExternalLink, ShieldCheck, ChevronDown, ChevronUp,
    MessageSquare, Send, Loader2, Sparkles, CreditCard, Lock,
    CheckCircle, ListOrdered, FolderOpen, Layers, Shield, Upload,
    Save, HelpCircle, FileX, Plus
} from 'lucide-react';
import { launchRazorpayCheckout } from '../../utils/razorpayCheckout';
import { ORDER_PHASES, getOrderStatusProgress, getPhaseStepIndex } from '../../utils/orderProgress';

const PHASES = ORDER_PHASES;

const ProjectDetailsView = ({ 
    order, 
    payments = [], 
    onBack, 
    onOpenVault, 
    setActiveTab, 
    userInfo, 
    refreshOrders 
}) => {
    const [currentTab, setCurrentTab] = useState('requirements'); // 'requirements' | 'documents' | 'financials'
    const [reqFilter, setReqFilter] = useState('pending'); // 'all' | 'pending' | 'completed'
    const [isPaying, setIsPaying] = useState(false);
    const [isTicketModalOpen, setIsTicketModalOpen] = useState(false);
    const [ticketData, setTicketData] = useState({
        title: `Query regarding Order #${order?._id?.slice(-8)?.toUpperCase() || ''}: ${order?.serviceName || ''}`,
        category: 'Order',
        priority: 'Medium',
        description: ''
    });
    const [isSubmittingTicket, setIsSubmittingTicket] = useState(false);
    const [ticketSuccessMsg, setTicketSuccessMsg] = useState('');

    // Dynamic Draft Inputs & Upload Loading States
    const [drafts, setDrafts] = useState({});
    const [uploadingId, setUploadingId] = useState('');
    const [savingId, setSavingId] = useState('');

    const requirements = order?.customerRequirements || [];

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

    // Categorized Requirements
    const pendingRequirements = useMemo(() => {
        return requirements.filter((item) => {
            const isCompleted = item.status === 'Received' || item.status === 'Verified' || item.isClientCompleted || item.documentUrl || item.clientValue;
            return !isCompleted;
        });
    }, [requirements]);

    const completedRequirements = useMemo(() => {
        return requirements.filter((item) => {
            return item.status === 'Received' || item.status === 'Verified' || item.isClientCompleted || item.documentUrl || item.clientValue;
        });
    }, [requirements]);

    const filteredRequirements = useMemo(() => {
        if (reqFilter === 'pending') return pendingRequirements;
        if (reqFilter === 'completed') return completedRequirements;
        return requirements;
    }, [reqFilter, pendingRequirements, completedRequirements, requirements]);

    const reqProgressPercentage = useMemo(() => {
        if (!requirements.length) return order?.status === 'Completed' ? 100 : 25;
        const comp = completedRequirements.length;
        const total = requirements.length;
        return Math.round((comp / total) * 100);
    }, [requirements, completedRequirements, order?.status]);

    // Save Text / Form Detail Requirement
    const handleSaveDetail = async (requirementId) => {
        const value = drafts[requirementId]?.value ?? '';
        const notes = drafts[requirementId]?.notes ?? '';
        setSavingId(requirementId);
        try {
            const config = { headers: { Authorization: `Bearer ${userInfo?.token}` } };
            await axios.put(
                `/api/orders/${order._id}/requirements/${requirementId}`,
                {
                    clientValue: value,
                    clientNotes: notes,
                    isClientCompleted: Boolean(value.trim())
                },
                config
            );
            if (refreshOrders) await refreshOrders();
        } catch (err) {
            alert(err.response?.data?.message || 'Failed to save detail');
        } finally {
            setSavingId('');
        }
    };

    // Upload Document for Requirement
    const handleUploadForRequirement = async (requirementId, filesList) => {
        if (!filesList || filesList.length === 0) return;
        setUploadingId(requirementId);
        try {
            for (let i = 0; i < filesList.length; i++) {
                const formData = new FormData();
                formData.append('document', filesList[i]);
                formData.append('requirementId', requirementId);

                await axios.post(`/api/orders/${order._id}/documents`, formData, {
                    headers: {
                        Authorization: `Bearer ${userInfo?.token}`,
                        'Content-Type': 'multipart/form-data'
                    }
                });
            }
            if (refreshOrders) await refreshOrders();
        } catch (error) {
            console.error('Document Upload Error:', error);
            alert(error?.response?.data?.message || 'Error uploading file(s).');
        } finally {
            setUploadingId('');
        }
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

    const currentStepIndex = getPhaseStepIndex(order?.status);
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

            {/* Completion / Deliverables Ready Banner */}
            {(order?.status === 'Completed' || finalCertificateUrl) && (
                <div className="p-6 rounded-3xl bg-gradient-to-br from-emerald-600 via-emerald-700 to-teal-800 text-white shadow-xl shadow-emerald-500/15 relative overflow-hidden">
                    <div className="absolute right-0 top-0 w-80 h-80 bg-white/10 rounded-full blur-3xl -mr-20 -mt-20 pointer-events-none" />
                    <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
                        <div className="space-y-1.5 max-w-xl">
                            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/20 text-[11px] font-black uppercase tracking-wider backdrop-blur-md">
                                <Sparkles size={13} className="text-amber-300" /> Statutory Deliverables Ready
                            </div>
                            <h2 className="text-xl font-black tracking-tight">Project Completed Successfully!</h2>
                            <p className="text-emerald-100 text-xs font-medium leading-relaxed">
                                All government filings and certifications for <strong className="text-white">{order?.serviceName}</strong> have been finalized. You can download the official documents below.
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

            {/* High-Level Milestone Stepper Card */}
            <div className="bg-white rounded-3xl border border-slate-200/80 shadow-xs p-6">
                <div className="flex flex-wrap justify-between items-center gap-4 mb-5">
                    <div>
                        <h3 className="text-sm font-black text-slate-900">Project Progress Overview</h3>
                        <p className="text-xs text-slate-400 font-medium">Live statutory lifecycle tracked by our compliance department</p>
                    </div>
                    <div className="flex items-center gap-3">
                        <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">
                            Phase: <strong className="text-red-600">{order?.status}</strong>
                        </span>
                    </div>
                </div>

                {/* Phase Stepper */}
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-2 border-t border-slate-100">
                    {PHASES.map((phase, idx) => {
                        const isDone = idx + 1 < currentStepIndex || order?.status === 'Completed';
                        const isCurrent = idx + 1 === currentStepIndex && order?.status !== 'Completed';

                        return (
                            <div key={phase.key} className="text-center p-2 rounded-2xl transition-all">
                                <div className={`w-8 h-8 mx-auto mb-1.5 rounded-full flex items-center justify-center text-xs font-black transition-all ${
                                    isDone 
                                        ? 'bg-emerald-500 text-white' 
                                        : isCurrent 
                                            ? 'bg-red-600 text-white ring-4 ring-red-100' 
                                            : 'bg-slate-100 text-slate-400'
                                }`}>
                                    {isDone ? <CheckCircle size={15} /> : idx + 1}
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

            {/* Navigation Tabs */}
            <div className="flex border-b border-slate-200 overflow-x-auto gap-2 scrollbar-none">
                <button
                    onClick={() => setCurrentTab('requirements')}
                    className={`px-4 py-3 text-xs font-black uppercase tracking-wider border-b-2 transition-all flex items-center gap-2 whitespace-nowrap ${
                        currentTab === 'requirements'
                            ? 'border-red-600 text-red-600'
                            : 'border-transparent text-slate-500 hover:text-slate-800'
                    }`}
                >
                    <FileCheck size={15} /> Customer Action Items & Requirements
                    {pendingRequirements.length > 0 ? (
                        <span className="px-2 py-0.5 rounded-full bg-rose-100 text-rose-700 text-[10px] font-black animate-pulse">
                            {pendingRequirements.length} Pending
                        </span>
                    ) : (
                        <span className="px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 text-[10px] font-black">
                            ✓ Complete
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
                    <FolderOpen size={15} /> Vault & Deliverables ({(order?.adminDocuments?.length || 0) + (order?.clientDocuments?.length || 0)})
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

            {/* Tab 1: Customer Action Items & Requirements (Primary View) */}
            {currentTab === 'requirements' && (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Left Column (2/3) */}
                    <div className="lg:col-span-2 space-y-6">
                        {/* Dynamic Action Required Header Card */}
                        <div className={`rounded-3xl border p-6 transition-all ${
                            pendingRequirements.length > 0 
                                ? 'bg-amber-50/70 border-amber-200' 
                                : 'bg-emerald-50/70 border-emerald-200'
                        }`}>
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                                <div className="space-y-1">
                                    <div className="flex items-center gap-2">
                                        {pendingRequirements.length > 0 ? (
                                            <span className="p-1.5 rounded-xl bg-amber-500 text-white">
                                                <AlertCircle size={18} />
                                            </span>
                                        ) : (
                                            <span className="p-1.5 rounded-xl bg-emerald-500 text-white">
                                                <CheckCircle2 size={18} />
                                            </span>
                                        )}
                                        <h3 className="text-sm font-black text-slate-900">
                                            {pendingRequirements.length > 0 
                                                ? `Action Required: ${pendingRequirements.length} Pending Requirement${pendingRequirements.length > 1 ? 's' : ''}`
                                                : 'All Customer Requirements Completed!'}
                                        </h3>
                                    </div>
                                    <p className="text-xs text-slate-600 font-medium pl-8">
                                        {pendingRequirements.length > 0 
                                            ? 'Please upload the requested files and enter details below so our team can submit your application without delay.' 
                                            : 'Everything requested from your side has been received and verified. Our team is actively executing portal processing.'}
                                    </p>
                                </div>

                                <div className="shrink-0 text-right pl-8 sm:pl-0">
                                    <span className="text-xl font-black text-slate-900">{reqProgressPercentage}%</span>
                                    <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Requirements Done</p>
                                </div>
                            </div>
                        </div>

                        {/* Requirements List & Upload Hub */}
                        <div className="bg-white rounded-3xl border border-slate-200/80 shadow-xs p-6 space-y-5">
                            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-4">
                                <div>
                                    <h3 className="text-sm font-black text-slate-900">Required Documents & Information</h3>
                                    <p className="text-xs text-slate-400 font-medium">Official checklist required for government filing</p>
                                </div>

                                {/* Filter Tags */}
                                <div className="flex items-center gap-1.5 bg-slate-100 p-1 rounded-xl">
                                    <button
                                        onClick={() => setReqFilter('pending')}
                                        className={`px-3 py-1 rounded-lg text-xs font-black transition-all ${
                                            reqFilter === 'pending'
                                                ? 'bg-white text-slate-900 shadow-2xs'
                                                : 'text-slate-500 hover:text-slate-900'
                                        }`}
                                    >
                                        Pending ({pendingRequirements.length})
                                    </button>
                                    <button
                                        onClick={() => setReqFilter('completed')}
                                        className={`px-3 py-1 rounded-lg text-xs font-black transition-all ${
                                            reqFilter === 'completed'
                                                ? 'bg-white text-slate-900 shadow-2xs'
                                                : 'text-slate-500 hover:text-slate-900'
                                        }`}
                                    >
                                        Submitted ({completedRequirements.length})
                                    </button>
                                    <button
                                        onClick={() => setReqFilter('all')}
                                        className={`px-3 py-1 rounded-lg text-xs font-black transition-all ${
                                            reqFilter === 'all'
                                                ? 'bg-white text-slate-900 shadow-2xs'
                                                : 'text-slate-500 hover:text-slate-900'
                                        }`}
                                    >
                                        All ({requirements.length})
                                    </button>
                                </div>
                            </div>

                            {/* Checklist Items */}
                            {filteredRequirements.length > 0 ? (
                                <div className="space-y-4">
                                    {filteredRequirements.map((item, idx) => {
                                        const isDone = item.status === 'Received' || item.status === 'Verified' || item.isClientCompleted || item.documentUrl || item.clientValue;
                                        const isDocument = item.type === 'Document';
                                        const draft = drafts[item._id] || { value: item.clientValue || item.value || '', notes: item.clientNotes || '' };

                                        return (
                                            <div 
                                                key={item._id || idx} 
                                                className={`rounded-2xl border p-4 transition-all ${
                                                    isDone 
                                                        ? 'bg-slate-50/50 border-slate-200' 
                                                        : 'bg-white border-amber-200 shadow-xs'
                                                }`}
                                            >
                                                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                                                    <div className="flex items-start gap-3">
                                                        <div className="mt-0.5">
                                                            {isDone ? (
                                                                <CheckCircle2 size={18} className="text-emerald-500" />
                                                            ) : (
                                                                <Circle size={18} className="text-amber-500" />
                                                            )}
                                                        </div>
                                                        <div className="space-y-1">
                                                            <div className="flex items-center gap-2 flex-wrap">
                                                                <p className="text-xs font-black text-slate-900">
                                                                    {item.itemCode ? `${item.itemCode}: ` : ''}{item.title}
                                                                </p>
                                                                <span className={`px-2 py-0.5 rounded-md text-[9px] font-black uppercase tracking-wider ${
                                                                    item.status === 'Verified' 
                                                                        ? 'bg-emerald-100 text-emerald-800' 
                                                                        : isDone 
                                                                            ? 'bg-blue-100 text-blue-800' 
                                                                            : 'bg-amber-100 text-amber-800'
                                                                }`}>
                                                                    {item.status === 'Verified' ? 'Verified by CA' : isDone ? 'Submitted' : 'Pending Upload'}
                                                                </span>
                                                                {item.required && (
                                                                    <span className="text-[10px] font-bold text-rose-500 uppercase">
                                                                        *Required
                                                                    </span>
                                                                )}
                                                            </div>
                                                            {item.description && (
                                                                <p className="text-[11px] text-slate-500">{item.description}</p>
                                                            )}
                                                            {item.sheetName && (
                                                                <p className="text-[10px] text-slate-400 font-semibold">Category: {item.sheetName}</p>
                                                            )}
                                                        </div>
                                                    </div>

                                                    {/* Upload Action / Form Input */}
                                                    <div className="shrink-0 pl-7 sm:pl-0">
                                                        {isDocument ? (
                                                            <div className="flex items-center gap-2">
                                                                {item.documentUrl && (
                                                                    <a
                                                                        href={item.documentUrl}
                                                                        target="_blank"
                                                                        rel="noopener noreferrer"
                                                                        className="px-3 py-1.5 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 text-xs font-bold flex items-center gap-1.5 shadow-2xs"
                                                                    >
                                                                        <FileText size={13} className="text-indigo-600" /> View Uploaded
                                                                    </a>
                                                                )}
                                                                <label className="cursor-pointer px-3.5 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-black flex items-center gap-1.5 shadow-sm active:scale-95 transition-all">
                                                                    {uploadingId === item._id ? (
                                                                        <Loader2 size={13} className="animate-spin" />
                                                                    ) : (
                                                                        <Upload size={13} />
                                                                    )}
                                                                    <span>{item.documentUrl ? 'Re-upload' : 'Upload File'}</span>
                                                                    <input
                                                                        type="file"
                                                                        className="hidden"
                                                                        disabled={uploadingId === item._id}
                                                                        onChange={(e) => handleUploadForRequirement(item._id, e.target.files)}
                                                                    />
                                                                </label>
                                                            </div>
                                                        ) : (
                                                            <div className="flex items-center gap-2">
                                                                <input
                                                                    type={item.inputType || 'text'}
                                                                    value={draft.value}
                                                                    placeholder={item.placeholder || 'Enter value...'}
                                                                    onChange={(e) => setDrafts({
                                                                        ...drafts,
                                                                        [item._id]: { ...draft, value: e.target.value }
                                                                    })}
                                                                    className="p-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500 w-44"
                                                                />
                                                                <button
                                                                    type="button"
                                                                    onClick={() => handleSaveDetail(item._id)}
                                                                    disabled={savingId === item._id}
                                                                    className="px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-black flex items-center gap-1 shadow-sm disabled:opacity-50"
                                                                >
                                                                    {savingId === item._id ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}
                                                                    <span>Save</span>
                                                                </button>
                                                            </div>
                                                        )}
                                                    </div>
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            ) : (
                                <div className="text-center py-10 text-slate-400 bg-slate-50/50 rounded-2xl border border-dashed border-slate-200">
                                    <CheckCircle size={32} className="mx-auto mb-2 opacity-40 text-emerald-600" />
                                    <p className="text-xs font-bold text-slate-700">
                                        {reqFilter === 'pending'
                                            ? 'No pending requirements!'
                                            : 'No requirements found in this category.'}
                                    </p>
                                    <p className="text-[11px] text-slate-400 mt-0.5">
                                        We will notify you immediately if any additional clarifications are requested.
                                    </p>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Right Column (1/3) */}
                    <div className="space-y-6">
                        {/* Assigned Expert / Team Card */}
                        <div className="bg-white rounded-3xl border border-slate-200/80 shadow-xs p-6 relative overflow-hidden">
                            <div className="flex items-center justify-between mb-4">
                                <h3 className="text-sm font-black text-slate-900">Assigned Lead Expert</h3>
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
                                        <MessageSquare size={13} /> Message Expert
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

                        {/* Financial Overview Card */}
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

            {/* Tab 2: Vault & Documents */}
            {currentTab === 'documents' && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Official Admin / Government Issued Deliverables */}
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

                    {/* Client Uploaded Documents */}
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
                </div>
            )}

            {/* Tab 3: Invoices & Payments */}
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
