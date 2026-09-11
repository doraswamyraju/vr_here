import React, { useState, useEffect, useMemo, useCallback } from 'react';
import axios from 'axios';
import { 
  Upload, 
  Download, 
  CheckCircle, 
  Eye, 
  ShieldCheck, 
  AlertCircle, 
  Send, 
  Users, 
  Clock, 
  FileText, 
  Sparkles, 
  Lock, 
  Unlock, 
  MessageSquare,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  UserCheck
} from 'lucide-react';
import { ORDER_STATUSES } from './constants';
import { getOrderClientLabel, StatusBadge } from './helpers';
import { rupees } from '../admin/orders/helpers';
import RequirementsModule from './RequirementsModule';

const OrderProcessingModule = ({
  orders,
  selectedOrder,
  setSelectedOrder,
  onStatusChange,
  onUpdateOrderName,
  onUploadCertificate,
  isUploading,
  userInfo,
  onUpdateRequirementStatus,
  onRaiseRequirement,
  linkedTodos = [],
  onTodoStatusChange,
  isClockedIn,
  onTaskStatusChange,
  onUpdateSubtask,
  onRefresh
}) => {
  const handleTodoUpdate = (id, status) => {
    if (!isClockedIn) {
      alert('Please clock in before starting work.');
      return;
    }
    onTodoStatusChange(id, status);
  };

  const [file, setFile] = useState(null);
  const [detailTab, setDetailTab] = useState('Tasks');
  const [isEditingName, setIsEditingName] = useState(false);
  const [editedName, setEditedName] = useState('');

  const [adminDocFiles, setAdminDocFiles] = useState([]);
  const [adminDocName, setAdminDocName] = useState('');
  const [isUploadingAdminDoc, setIsUploadingAdminDoc] = useState(false);
  const [itrAssessment, setItrAssessment] = useState(null);
  const [isUploadingFinal, setIsUploadingFinal] = useState(false);

  // 3-Tier Audit state
  const [submitAuditModalOpen, setSubmitAuditModalOpen] = useState(false);
  const [auditNotesInput, setAuditNotesInput] = useState('');
  const [isSubmittingAudit, setIsSubmittingAudit] = useState(false);

  const [checkerDecisionModalOpen, setCheckerDecisionModalOpen] = useState(false);
  const [auditDecision, setAuditDecision] = useState('Approved');
  const [checkerNotesInput, setCheckerNotesInput] = useState('');
  const [isAuditing, setIsAuditing] = useState(false);

  const [assignModalOpen, setAssignModalOpen] = useState(false);
  const [staffList, setStaffList] = useState([]);
  const [selectedPmId, setSelectedPmId] = useState('');
  const [selectedMakerId, setSelectedMakerId] = useState('');
  const [selectedCheckerId, setSelectedCheckerId] = useState('');
  const [isSavingAssignments, setIsSavingAssignments] = useState(false);
  const [pmOverrideDeliver, setPmOverrideDeliver] = useState(false);

  const config = useMemo(() => {
    const activeToken = userInfo?.token;
    return activeToken ? { headers: { Authorization: `Bearer ${activeToken}` } } : null;
  }, [userInfo]);

  const normalizeId = useCallback((value) => {
    if (!value) return '';
    if (typeof value === 'string') return value;
    if (value?._id) return String(value._id);
    return String(value);
  }, []);

  const employeeId = userInfo?._id ? String(userInfo._id) : '';
  const userRoleLower = String(userInfo?.role || '').toLowerCase();
  const isAdmin = userRoleLower === 'admin';

  // Role identification in 3-tier hierarchy
  const isPM = useMemo(() => {
    if (isAdmin) return true;
    if (!selectedOrder) return false;
    const pmId = normalizeId(selectedOrder.assignedProjectManager);
    const legacyEmpId = normalizeId(selectedOrder.assignedEmployee);
    const makerId = normalizeId(selectedOrder.assignedMaker);
    const checkerId = normalizeId(selectedOrder.assignedChecker);

    if (pmId && pmId === employeeId) return true;
    if (!pmId && legacyEmpId === employeeId && makerId !== employeeId && checkerId !== employeeId) return true;
    return false;
  }, [isAdmin, selectedOrder, normalizeId, employeeId]);

  const isMaker = useMemo(() => {
    if (!selectedOrder) return false;
    const makerId = normalizeId(selectedOrder.assignedMaker);
    return Boolean(makerId && makerId === employeeId);
  }, [selectedOrder, normalizeId, employeeId]);

  const isChecker = useMemo(() => {
    if (!selectedOrder) return false;
    const checkerId = normalizeId(selectedOrder.assignedChecker);
    return Boolean(checkerId && checkerId === employeeId);
  }, [selectedOrder, normalizeId, employeeId]);

  // Determine if financial information should be completely hidden
  const isFinancialsHidden = useMemo(() => {
    if (isAdmin) return false;
    if (isPM) return false;
    // Always hide financials for Maker, Checker, or general employee/freelancer
    return true;
  }, [isAdmin, isPM]);

  // Current user's tier role badge label
  const currentUserRoleLabel = useMemo(() => {
    if (isAdmin) return 'Admin (Full Oversight)';
    if (isPM) return 'Project Manager (Lead)';
    if (isChecker && isMaker) return 'Maker & Checker';
    if (isChecker) return 'Checker (Quality Audit)';
    if (isMaker) return 'Maker (Execution)';
    return 'Specialist';
  }, [isAdmin, isPM, isMaker, isChecker]);

  useEffect(() => {
    if (selectedOrder) {
      setEditedName(selectedOrder.serviceName || '');
      setSelectedPmId(normalizeId(selectedOrder.assignedProjectManager || selectedOrder.assignedEmployee));
      setSelectedMakerId(normalizeId(selectedOrder.assignedMaker));
      setSelectedCheckerId(normalizeId(selectedOrder.assignedChecker));
    }
  }, [selectedOrder, normalizeId]);

  // Fetch staff list for PM assignment modal
  useEffect(() => {
    const fetchStaff = async () => {
      if (!config || (!isPM && !isAdmin)) return;
      try {
        const { data } = await axios.get('/api/employees', config);
        setStaffList(Array.isArray(data) ? data : []);
      } catch (err) {
        // Fallback gracefully
      }
    };
    fetchStaff();
  }, [config, isPM, isAdmin]);

  const handleUploadFinalCertificate = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (!isClockedIn) {
      alert('Please clock in before starting work.');
      return;
    }
    if (!file || !config) return;
    setIsUploadingFinal(true);
    const formData = new FormData();
    formData.append('document', file);
    formData.append('isFinalCertificate', 'true');
    try {
      await axios.post(`/api/orders/${selectedOrder._id}/documents`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          ...config.headers
        }
      });
      alert('Final certificate uploaded successfully and project status set to Completed!');
      setFile(null);
      if (onRefresh) {
        onRefresh();
      } else {
        window.location.reload();
      }
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to upload final certificate');
    } finally {
      setIsUploadingFinal(false);
    }
  };

  const [payments, setPayments] = useState([]);
  const [history, setHistory] = useState([]);
  const [isLoadingPayments, setIsLoadingPayments] = useState(false);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);

  const fetchPayments = async () => {
    if (!config || !selectedOrder?._id || isFinancialsHidden) return;
    setIsLoadingPayments(true);
    try {
      const { data } = await axios.get(`/api/payments?orderId=${selectedOrder._id}`, config);
      setPayments(data || []);
    } catch (err) {
      console.error('Error fetching payments:', err.message);
    } finally {
      setIsLoadingPayments(false);
    }
  };

  const fetchHistory = async () => {
    if (!config || !selectedOrder?._id) return;
    setIsLoadingHistory(true);
    try {
      const { data } = await axios.get(`/api/orders/${selectedOrder._id}/history`, config);
      setHistory(data || []);
    } catch (err) {
      console.error('Error fetching history:', err.message);
    } finally {
      setIsLoadingHistory(false);
    }
  };

  const fetchItrAssessment = async () => {
    if (!config || !selectedOrder?._id) return;
    const isITR = selectedOrder?.serviceName?.toLowerCase().includes('income tax') || selectedOrder?.packageName?.toLowerCase().includes('itr');
    if (!isITR) {
      setItrAssessment(null);
      return;
    }
    try {
      const { data } = await axios.get(`/api/income-tax-assessment?orderId=${selectedOrder._id}`, config);
      if (data && data.length > 0) {
        setItrAssessment(data[0]);
      } else {
        setItrAssessment(null);
      }
    } catch (err) {
      console.error('Error fetching ITR assessment:', err.message);
    }
  };

  const handleUploadAdminDoc = async (e) => {
    e.preventDefault();
    if (!isClockedIn) {
      alert('Please clock in before starting work.');
      return;
    }
    if (adminDocFiles.length === 0 || !config) return;
    setIsUploadingAdminDoc(true);
    try {
      for (const file of adminDocFiles) {
        const formData = new FormData();
        formData.append('document', file);
        const displayName = adminDocFiles.length === 1 && adminDocName.trim()
          ? adminDocName.trim()
          : file.name;
        formData.append('name', displayName);
        await axios.post(`/api/orders/${selectedOrder._id}/documents`, formData, {
          headers: {
            'Content-Type': 'multipart/form-data',
            ...config.headers
          }
        });
      }
      alert('Document(s) uploaded successfully to customer portal!');
      setAdminDocFiles([]);
      setAdminDocName('');
      if (onRefresh) {
        onRefresh();
      } else {
        window.location.reload();
      }
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to upload document(s)');
    } finally {
      setIsUploadingAdminDoc(false);
    }
  };

  const handleDownloadAllDocs = () => {
    if (!selectedOrder) return;
    const urls = [];
    
    if (selectedOrder.finalCertificateUrl) {
      urls.push({ name: 'Final_Certificate', url: selectedOrder.finalCertificateUrl });
    }
    
    (selectedOrder.customerRequirements || []).forEach(r => {
      if (r.documents && r.documents.length > 0) {
        r.documents.forEach((doc, idx) => {
          if (doc.url) {
            urls.push({ name: `${r.title || 'Requirement'}_${idx + 1}`, url: doc.url });
          }
        });
      } else if (r.uploadedDocumentUrl) {
        urls.push({ name: r.title || 'Requirement', url: r.uploadedDocumentUrl });
      }
    });

    const requirementUrls = new Set();
    (selectedOrder.customerRequirements || []).forEach(r => {
      if (r.documents && r.documents.length > 0) {
        r.documents.forEach(doc => {
          if (doc.url) requirementUrls.add(doc.url);
        });
      }
      if (r.uploadedDocumentUrl) {
        requirementUrls.add(r.uploadedDocumentUrl);
      }
    });

    (selectedOrder.clientDocuments || []).forEach(doc => {
      if (doc.url && !requirementUrls.has(doc.url)) {
        urls.push({ name: doc.name || 'ClientDoc', url: doc.url });
      }
    });

    (selectedOrder.adminDocuments || []).forEach(doc => {
      if (doc.url) {
        urls.push({ name: doc.name || 'AdminDoc', url: doc.url });
      }
    });

    if (itrAssessment) {
      itrAssessment.responses?.forEach(r => {
        if (r.documents && r.documents.length > 0) {
          r.documents.forEach((doc, dIdx) => {
            if (doc.documentUrl) {
              urls.push({ name: `${r.description}_${dIdx + 1}`, url: doc.documentUrl });
            }
          });
        } else if (r.documentUrl) {
          urls.push({ name: r.description, url: r.documentUrl });
        }
      });
    }

    if (urls.length === 0) {
      alert('No documents available to download.');
      return;
    }

    urls.forEach((item, index) => {
      setTimeout(() => {
        const a = document.createElement('a');
        a.href = item.url;
        a.target = '_blank';
        a.download = item.name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
      }, index * 400);
    });
  };

  // Submit to Checker API Call
  const handleSubmitToChecker = async () => {
    if (!config || !selectedOrder?._id) return;
    if (!isClockedIn) {
      alert('Please clock in before submitting work.');
      return;
    }
    setIsSubmittingAudit(true);
    try {
      const { data } = await axios.post(
        `/api/orders/${selectedOrder._id}/submit-to-checker`,
        { notes: auditNotesInput.trim() },
        config
      );
      alert('Work submitted to Checker successfully for Quality Audit!');
      setSubmitAuditModalOpen(false);
      setAuditNotesInput('');
      if (setSelectedOrder) setSelectedOrder(data);
      if (onRefresh) onRefresh();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to submit to checker');
    } finally {
      setIsSubmittingAudit(false);
    }
  };

  // Checker Quality Audit Decision API Call
  const handleCheckerAudit = async () => {
    if (!config || !selectedOrder?._id) return;
    if (!isClockedIn) {
      alert('Please clock in before auditing work.');
      return;
    }
    setIsAuditing(true);
    try {
      const { data } = await axios.post(
        `/api/orders/${selectedOrder._id}/checker-audit`,
        { decision: auditDecision, notes: checkerNotesInput.trim() },
        config
      );
      alert(`Audit recorded successfully: ${auditDecision}!`);
      setCheckerDecisionModalOpen(false);
      setCheckerNotesInput('');
      if (setSelectedOrder) setSelectedOrder(data);
      if (onRefresh) onRefresh();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to submit audit decision');
    } finally {
      setIsAuditing(false);
    }
  };

  // PM / Admin Role Assignment API Call
  const handleSaveAssignments = async () => {
    if (!config || !selectedOrder?._id) return;
    setIsSavingAssignments(true);
    try {
      const { data } = await axios.put(
        `/api/orders/${selectedOrder._id}/assign`,
        {
          projectManagerId: selectedPmId || null,
          makerId: selectedMakerId || null,
          checkerId: selectedCheckerId || null
        },
        config
      );
      alert('Role assignments updated successfully!');
      setAssignModalOpen(false);
      if (setSelectedOrder) setSelectedOrder(data);
      if (onRefresh) onRefresh();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to update assignments');
    } finally {
      setIsSavingAssignments(false);
    }
  };

  useEffect(() => {
    if (selectedOrder?._id) {
      fetchPayments();
      fetchHistory();
      fetchItrAssessment();
    }
  }, [selectedOrder?._id, detailTab, config]);

  const selectedOrderAssignedTasks = useMemo(() => {
    if (!selectedOrder?.tasks) return [];
    if (isAdmin || isPM) return selectedOrder.tasks;
    return (selectedOrder.tasks || []).filter((task) => {
      const taskAssignees = [task.assignedTo, task.assignedMaker, task.assignedChecker]
        .map(normalizeId)
        .filter(Boolean);
      const subtaskAssignees = (task.subtasks || [])
        .flatMap((subtask) => [subtask.assignedToMaker, subtask.assignedToChecker])
        .map(normalizeId)
        .filter(Boolean);
      return [...taskAssignees, ...subtaskAssignees].includes(employeeId);
    });
  }, [selectedOrder, isAdmin, isPM, normalizeId, employeeId]);

  const clientPhone = selectedOrder?.phone || selectedOrder?.user?.phone || '';
  const clientEmail = selectedOrder?.email || selectedOrder?.user?.email || '';

  // Tabs configuration based on financial masking
  const availableTabs = useMemo(() => {
    const baseTabs = ['Tasks', 'Requirements', 'Audit & Review', 'ToDo', 'Docs', 'Activities'];
    if (!isFinancialsHidden) {
      baseTabs.splice(3, 0, 'Invoices', 'Transactions');
    }
    return baseTabs;
  }, [isFinancialsHidden]);

  // Filter history if financials are hidden
  const filteredHistory = useMemo(() => {
    if (!isFinancialsHidden) return history;
    return history.filter((log) => {
      const action = String(log.action || '').toUpperCase();
      const desc = String(log.description || '').toLowerCase();
      if (action.includes('INVOICE') || action.includes('PAYMENT') || action.includes('COMMERCIAL')) return false;
      if (desc.includes('invoice') || desc.includes('payment') || desc.includes('rupees') || desc.includes('inr') || desc.includes('price')) return false;
      return true;
    });
  }, [history, isFinancialsHidden]);

  if (!selectedOrder) {
    return (
      <div className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] p-6 overflow-x-auto">
        <table className="w-full text-left min-w-[760px]">
          <thead className="text-xs uppercase font-bold text-slate-500">
            <tr>
              <th className="p-3">Client</th>
              <th className="p-3">Service</th>
              <th className="p-3">Contact</th>
              <th className="p-3">Audit Stage</th>
              <th className="p-3">Status</th>
              <th className="p-3">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {orders.map((order) => {
              const auditStatus = order.auditStatus || 'Not Submitted';
              return (
                <tr key={order._id} className="hover:bg-indigo-50/40 transition">
                  <td className="p-3 font-semibold">{getOrderClientLabel(order)}</td>
                  <td className="p-3">
                    <p className="font-semibold text-slate-800">{order.serviceName}</p>
                    <p className="text-[10px] text-slate-400 font-bold uppercase">{order.packageName || 'Standard'}</p>
                  </td>
                  <td className="p-3 text-xs">
                    {order.phone ? (
                      <a href={`tel:${order.phone}`} className="text-indigo-700 font-semibold hover:underline">
                        {order.phone}
                      </a>
                    ) : (
                      <span className="text-slate-400">No phone</span>
                    )}
                  </td>
                  <td className="p-3">
                    <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-black uppercase tracking-wider ${
                      auditStatus === 'Approved by Checker' ? 'bg-emerald-100 text-emerald-800' :
                      auditStatus === 'Submitted for Review' ? 'bg-amber-100 text-amber-800 animate-pulse' :
                      auditStatus === 'Changes Requested' ? 'bg-rose-100 text-rose-800' :
                      'bg-slate-100 text-slate-600'
                    }`}>
                      {auditStatus === 'Approved by Checker' && <ShieldCheck size={12} />}
                      {auditStatus === 'Submitted for Review' && <Clock size={12} />}
                      {auditStatus === 'Changes Requested' && <AlertTriangle size={12} />}
                      {auditStatus}
                    </span>
                  </td>
                  <td className="p-3">
                    <StatusBadge status={order.status} />
                  </td>
                  <td className="p-3">
                    <button
                      onClick={() => setSelectedOrder(order)}
                      className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-bold transition shadow-sm"
                    >
                      Open Processing
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    );
  }

  const currentAuditStatus = selectedOrder.auditStatus || 'Not Submitted';
  const isAuditApproved = currentAuditStatus === 'Approved by Checker';
  const isAuditPending = currentAuditStatus === 'Submitted for Review';
  const isChangesRequested = currentAuditStatus === 'Changes Requested';

  // Can upload final certificate if audit is approved or PM/Admin override
  const canUploadDeliverable = isAuditApproved || pmOverrideDeliver || isAdmin || isPM;

  return (
    <div className="space-y-4">
      {/* Top Header Card */}
      <div className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] p-6">
        <div className="flex justify-between items-start gap-4 flex-wrap">
          <div className="flex-1 min-w-[280px]">
            {isEditingName ? (
              <div className="flex items-center gap-2 mt-1 mb-2">
                <input 
                  type="text" 
                  value={editedName} 
                  onChange={(e) => setEditedName(e.target.value)}
                  className="px-3 py-1.5 border border-slate-300 rounded-lg text-sm font-bold text-slate-800 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none min-w-[240px]"
                />
                <button 
                  onClick={async () => {
                    if (!isClockedIn) {
                      alert('Please clock in before starting work.');
                      return;
                    }
                    if (!editedName.trim()) return;
                    await onUpdateOrderName(selectedOrder._id, editedName.trim());
                    setIsEditingName(false);
                  }}
                  className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-bold transition shadow-sm"
                >
                  Save
                </button>
                <button 
                  onClick={() => {
                    setEditedName(selectedOrder.serviceName || '');
                    setIsEditingName(false);
                  }}
                  className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs font-medium transition"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-2.5 mb-1 flex-wrap">
                <h3 className="text-xl font-black text-slate-900">{selectedOrder.serviceName}</h3>
                {(isAdmin || isPM) && (
                  <button 
                    onClick={() => setIsEditingName(true)}
                    className="text-xs text-indigo-600 hover:text-indigo-800 font-bold underline"
                  >
                    Edit Name
                  </button>
                )}
                <span className="px-2.5 py-0.5 rounded-full bg-indigo-50 text-indigo-700 font-black text-[10px] uppercase tracking-wider border border-indigo-100">
                  {currentUserRoleLabel}
                </span>
              </div>
            )}
            <p className="text-sm text-slate-500">
              Client: <span className="font-semibold">{getOrderClientLabel(selectedOrder)}</span>
            </p>
            <div className="mt-1 flex flex-wrap gap-3 text-xs">
              {clientPhone ? (
                <a href={`tel:${clientPhone}`} className="text-indigo-700 font-semibold hover:underline">
                  Call: {clientPhone}
                </a>
              ) : (
                <span className="text-slate-400">Phone not available</span>
              )}
              {clientEmail ? (
                <a href={`mailto:${clientEmail}`} className="text-indigo-700 font-semibold hover:underline">
                  Email: {clientEmail}
                </a>
              ) : (
                <span className="text-slate-400">Email not available</span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            {(isAdmin || isPM) && (
              <button 
                onClick={() => setAssignModalOpen(true)}
                className="px-3 py-2 bg-slate-900 hover:bg-indigo-900 text-white rounded-xl text-xs font-bold flex items-center gap-1.5 transition shadow-sm"
              >
                <Users size={14} /> Assign Team
              </button>
            )}
            <button onClick={() => setSelectedOrder(null)} className="px-3 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-bold transition">
              Back to List
            </button>
          </div>
        </div>
      </div>

      {/* 3-Tier Visual Workflow Execution Pipeline */}
      <div className="rounded-2xl border border-indigo-100 bg-gradient-to-r from-indigo-50/80 via-white to-blue-50/80 p-5 shadow-[0_10px_30px_rgba(15,23,42,0.06)]">
        <div className="flex items-center justify-between mb-3">
          <p className="text-[11px] font-black uppercase text-indigo-900 tracking-wider flex items-center gap-1.5">
            <Sparkles size={14} className="text-indigo-600" /> 3-Tier Work Execution & Quality Assurance Pipeline
          </p>
          <span className={`px-2.5 py-1 rounded-full text-xs font-black uppercase tracking-wider flex items-center gap-1 ${
            isAuditApproved ? 'bg-emerald-100 text-emerald-800' :
            isAuditPending ? 'bg-amber-100 text-amber-800 animate-pulse' :
            isChangesRequested ? 'bg-rose-100 text-rose-800' :
            'bg-slate-200 text-slate-700'
          }`}>
            {isAuditApproved && <ShieldCheck size={14} />}
            {isAuditPending && <Clock size={14} />}
            {isChangesRequested && <AlertTriangle size={14} />}
            Stage: {currentAuditStatus}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          {/* Stage 1: Project Manager */}
          <div className="p-3.5 rounded-xl border border-indigo-100 bg-white/90 shadow-sm flex flex-col justify-between">
            <div>
              <span className="text-[9px] font-black uppercase tracking-widest text-indigo-500">Tier 1 • Project Manager</span>
              <p className="font-bold text-slate-800 text-sm mt-0.5 truncate">
                {selectedOrder.assignedProjectManager?.name || selectedOrder.assignedEmployee?.name || 'Unassigned'}
              </p>
              <p className="text-[10px] text-slate-500 mt-1">
                {(selectedOrder.customerRequirements || []).length} Checklist Requirements
              </p>
            </div>
            <div className="mt-2.5 pt-2 border-t border-slate-100 flex items-center justify-between text-[10px]">
              <span className="text-slate-400 font-bold">Setup & Docs</span>
              <span className="text-emerald-600 font-black flex items-center gap-0.5">
                <CheckCircle2 size={12} /> Ready
              </span>
            </div>
          </div>

          {/* Stage 2: Maker (Execution) */}
          <div className={`p-3.5 rounded-xl border bg-white/90 shadow-sm flex flex-col justify-between ${
            isMaker ? 'border-indigo-400 ring-2 ring-indigo-200' : 'border-slate-200'
          }`}>
            <div>
              <div className="flex items-center justify-between">
                <span className="text-[9px] font-black uppercase tracking-widest text-slate-500">Tier 2 • Maker (Execution)</span>
                {isMaker && <span className="px-1.5 py-0.2 bg-indigo-600 text-white rounded text-[8px] font-black uppercase">You</span>}
              </div>
              <p className="font-bold text-slate-800 text-sm mt-0.5 truncate">
                {selectedOrder.assignedMaker?.name || 'Unassigned'}
              </p>
              <p className="text-[10px] text-slate-500 mt-1">
                {(selectedOrder.tasks || []).length} Workflow Tasks Assigned
              </p>
            </div>
            <div className="mt-2.5 pt-2 border-t border-slate-100 flex items-center justify-between text-[10px]">
              <span className="text-slate-400 font-bold">Execution</span>
              <span className="font-bold text-indigo-600">
                {isAuditPending || isAuditApproved ? 'Completed' : 'In Progress'}
              </span>
            </div>
          </div>

          {/* Stage 3: Checker (Audit) */}
          <div className={`p-3.5 rounded-xl border bg-white/90 shadow-sm flex flex-col justify-between ${
            isChecker ? 'border-indigo-400 ring-2 ring-indigo-200' : 'border-slate-200'
          }`}>
            <div>
              <div className="flex items-center justify-between">
                <span className="text-[9px] font-black uppercase tracking-widest text-slate-500">Tier 3 • Checker (Audit)</span>
                {isChecker && <span className="px-1.5 py-0.2 bg-indigo-600 text-white rounded text-[8px] font-black uppercase">You</span>}
              </div>
              <p className="font-bold text-slate-800 text-sm mt-0.5 truncate">
                {selectedOrder.assignedChecker?.name || 'Unassigned'}
              </p>
              <p className="text-[10px] text-slate-500 mt-1 truncate">
                {selectedOrder.auditNotes ? `"${selectedOrder.auditNotes}"` : 'Audit pending maker submit'}
              </p>
            </div>
            <div className="mt-2.5 pt-2 border-t border-slate-100 flex items-center justify-between text-[10px]">
              <span className="text-slate-400 font-bold">Quality Audit</span>
              <span className={`font-black ${
                isAuditApproved ? 'text-emerald-600' :
                isAuditPending ? 'text-amber-600' :
                isChangesRequested ? 'text-rose-600' : 'text-slate-400'
              }`}>
                {currentAuditStatus}
              </span>
            </div>
          </div>

          {/* Stage 4: Delivery & Close */}
          <div className="p-3.5 rounded-xl border border-slate-200 bg-white/90 shadow-sm flex flex-col justify-between">
            <div>
              <span className="text-[9px] font-black uppercase tracking-widest text-slate-500">Final Deliverable</span>
              <p className="font-bold text-slate-800 text-sm mt-0.5">
                {selectedOrder.finalCertificateUrl ? 'Certificate Issued 🎉' : 'Pending Completion'}
              </p>
              <p className="text-[10px] text-slate-500 mt-1">
                {selectedOrder.status === 'Completed' ? 'Project Closed' : 'Requires Audit Approval'}
              </p>
            </div>
            <div className="mt-2.5 pt-2 border-t border-slate-100 flex items-center justify-between text-[10px]">
              <span className="text-slate-400 font-bold">Status</span>
              <span className={`font-black ${selectedOrder.status === 'Completed' ? 'text-emerald-600' : 'text-slate-500'}`}>
                {selectedOrder.status}
              </span>
            </div>
          </div>
        </div>

        {/* Interactive Action Ribbon based on Role */}
        <div className="mt-4 pt-3 border-t border-indigo-100 flex flex-wrap items-center justify-between gap-3">
          {/* Changes Requested Banner */}
          {isChangesRequested && (
            <div className="w-full bg-rose-50 border border-rose-200 rounded-xl p-3 flex items-start gap-2.5">
              <AlertTriangle className="text-rose-600 shrink-0 mt-0.5" size={18} />
              <div className="text-xs">
                <p className="font-black text-rose-900 uppercase tracking-tight">Changes Requested by Checker</p>
                <p className="text-rose-700 mt-0.5 font-medium">{selectedOrder.auditNotes || 'Please review and update the deliverables before resubmitting.'}</p>
              </div>
            </div>
          )}

          {/* Maker / PM Submission Button */}
          {(isMaker || isPM || isAdmin) && !isAuditApproved && !isAuditPending && (
            <button
              onClick={() => {
                if (!isClockedIn) return alert('Please clock in before submitting work.');
                setSubmitAuditModalOpen(true);
              }}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-black uppercase tracking-wider flex items-center gap-2 shadow-md shadow-indigo-200 transition"
            >
              <Send size={14} /> Submit Work for Checker Quality Audit
            </button>
          )}

          {/* Pending Audit Notice for Maker */}
          {isAuditPending && isMaker && !isChecker && !isPM && (
            <div className="flex items-center gap-2 text-xs font-bold text-amber-700 bg-amber-50 px-3 py-2 rounded-xl border border-amber-200">
              <Clock size={16} className="animate-spin text-amber-600" /> Work submitted to Checker ({selectedOrder.assignedChecker?.name || 'Assigned Checker'}). Waiting for audit review.
            </div>
          )}

          {/* Checker / PM Override Decision Buttons */}
          {(isChecker || isPM || isAdmin) && isAuditPending && (
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-bold text-slate-700 mr-2">Audit Decision:</span>
              <button
                onClick={() => {
                  if (!isClockedIn) return alert('Please clock in before auditing.');
                  setAuditDecision('Approved');
                  setCheckerDecisionModalOpen(true);
                }}
                className="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-xs font-black uppercase tracking-wider flex items-center gap-1.5 shadow-sm transition"
              >
                <CheckCircle size={14} /> Approve Work
              </button>
              <button
                onClick={() => {
                  if (!isClockedIn) return alert('Please clock in before auditing.');
                  setAuditDecision('Changes Requested');
                  setCheckerDecisionModalOpen(true);
                }}
                className="px-3.5 py-2 bg-rose-600 hover:bg-rose-700 text-white rounded-xl text-xs font-black uppercase tracking-wider flex items-center gap-1.5 shadow-sm transition"
              >
                <AlertCircle size={14} /> Request Changes
              </button>
            </div>
          )}

          {/* Approved Celebration */}
          {isAuditApproved && (
            <div className="flex items-center gap-2 text-xs font-bold text-emerald-800 bg-emerald-50 px-3.5 py-2 rounded-xl border border-emerald-200">
              <ShieldCheck size={18} className="text-emerald-600" /> Quality Audit Approved! Ready for final certificate upload and project closing.
            </div>
          )}
        </div>
      </div>

      {/* KPI Tiles */}
      <div className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] p-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
            <p className="text-xs text-slate-500 font-bold uppercase tracking-tight">Status</p>
            <div className="mt-1"><StatusBadge status={selectedOrder.status} /></div>
          </div>
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
            <p className="text-xs text-slate-500 font-bold uppercase tracking-tight">Package</p>
            <p className="font-semibold text-slate-800 mt-1">{selectedOrder.packageName || 'Standard'}</p>
          </div>
          {/* Price Tile masked for Maker & Checker */}
          {!isFinancialsHidden ? (
            <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
              <p className="text-xs text-slate-500 font-bold uppercase tracking-tight">Price</p>
              <p className="font-semibold text-slate-800 mt-1">{rupees(selectedOrder.price)}</p>
            </div>
          ) : (
            <div className="rounded-xl border border-slate-200 bg-indigo-50/40 p-3">
              <p className="text-xs text-indigo-600 font-bold uppercase tracking-tight">Your Execution Role</p>
              <p className="font-bold text-slate-800 mt-1">{currentUserRoleLabel}</p>
            </div>
          )}
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
            <p className="text-xs text-slate-500 font-bold uppercase tracking-tight">Assigned Tasks</p>
            <p className="font-semibold text-slate-800 mt-1">{selectedOrderAssignedTasks.length} Assigned</p>
          </div>
        </div>
      </div>

      {/* Controls Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] p-6">
          <h4 className="font-bold text-slate-800 mb-4">Order Controls</h4>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-500">Update Status</span>
            </div>
            <select
              value={selectedOrder.status}
              onChange={(e) => {
                if (!isClockedIn) {
                  alert('Please clock in before starting work.');
                  return;
                }
                onStatusChange(selectedOrder._id, e.target.value);
              }}
              className="w-full p-3 border border-slate-300 rounded-lg bg-white text-sm outline-none focus:ring-2 focus:ring-indigo-500 font-medium"
            >
              {ORDER_STATUSES.map((status) => (
                <option key={status} value={status}>
                  {status}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Finish & Deliver Guarded Box */}
        <div className={`rounded-2xl border p-6 transition ${
          canUploadDeliverable ? 'bg-emerald-50/70 border-emerald-200' : 'bg-slate-50/90 border-slate-200'
        }`}>
          <div className="flex items-center justify-between mb-3">
            <h4 className={`font-bold text-sm flex items-center ${
              canUploadDeliverable ? 'text-emerald-800' : 'text-slate-700'
            }`}>
              <CheckCircle className="mr-2" size={18} />
              Finish & Deliver (Final Certificate)
            </h4>
            {(isAdmin || isPM) && !isAuditApproved && (
              <button
                onClick={() => setPmOverrideDeliver(!pmOverrideDeliver)}
                className="text-[10px] font-black uppercase text-indigo-700 underline flex items-center gap-1"
              >
                {pmOverrideDeliver ? <Unlock size={12} /> : <Lock size={12} />}
                {pmOverrideDeliver ? 'Lock (Wait for Audit)' : 'PM Override Deliver'}
              </button>
            )}
          </div>

          {selectedOrder.finalCertificateUrl ? (
            <div className="p-3 bg-white border border-emerald-200 rounded-xl flex items-center justify-between">
              <div>
                <p className="text-xs font-bold text-slate-800">Deliverable Uploaded</p>
                <p className="text-[10px] text-slate-400">Status marked Completed</p>
              </div>
              <a
                href={selectedOrder.finalCertificateUrl}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center px-3 py-1.5 bg-emerald-600 text-white rounded-lg font-bold text-xs hover:bg-emerald-700 transition"
              >
                <Download size={14} className="mr-1.5" />
                View Certificate
              </a>
            </div>
          ) : !canUploadDeliverable ? (
            <div className="p-4 bg-white/80 border border-slate-200 rounded-xl text-center space-y-2">
              <Lock size={24} className="mx-auto text-slate-400" />
              <p className="text-xs font-bold text-slate-700">Audit Approval Required</p>
              <p className="text-[11px] text-slate-500">
                The Checker must approve the work submission before the final certificate can be delivered and the project completed.
              </p>
            </div>
          ) : (
            <form onSubmit={handleUploadFinalCertificate} className="space-y-3">
              <input
                type="file"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
                required
                className="w-full text-xs font-semibold"
              />
              <button
                type="submit"
                disabled={isUploadingFinal || !file}
                className="w-full inline-flex items-center justify-center px-4 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-sm disabled:opacity-50 transition shadow-sm"
              >
                <Upload size={14} className="mr-2" />
                {isUploadingFinal ? 'Uploading...' : 'Upload & Deliver Final Certificate'}
              </button>
            </form>
          )}
        </div>
      </div>

      {/* Tabs & Content */}
      <div className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)]">
        <div className="px-4 border-b border-slate-100 flex flex-wrap gap-2">
          {availableTabs.map((tab) => (
            <button
              key={tab}
              onClick={() => setDetailTab(tab)}
              className={`px-4 py-3 text-sm font-medium border-b-2 transition ${detailTab === tab ? 'border-indigo-600 text-indigo-700 font-bold' : 'border-transparent text-slate-500 hover:text-indigo-600'}`}
            >
              {tab}
            </button>
          ))}
        </div>

        <div className="p-5 space-y-4">
          {/* Tasks Tab */}
          {detailTab === 'Tasks' && (
            <div className="space-y-6">
              <div className="space-y-2">
                <p className="text-[10px] font-black uppercase text-slate-400 tracking-widest mb-2">Workflow Assignments</p>
                {selectedOrderAssignedTasks.map((task) => (
                  <div key={task._id} className="rounded-lg border border-slate-200 p-4 bg-slate-50/50">
                    <div className="flex items-center justify-between gap-4">
                      <div>
                        <p className="font-semibold text-slate-800">{task.taskCode ? `${task.taskCode} - ${task.title}` : task.title}</p>
                        <p className="text-[10px] text-slate-500 uppercase font-black">Main Task</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <StatusBadge status={task.status || 'Pending'} />
                        {task.status === 'Pending' && (
                          <button 
                            onClick={() => {
                              if (!isClockedIn) return alert('Please clock in first.');
                              onTaskStatusChange(selectedOrder._id, task._id, 'In Progress');
                            }}
                            className={`px-3 py-1.5 rounded-lg text-[10px] font-black uppercase transition-all shadow-sm ${isClockedIn ? 'bg-white border-indigo-200 text-indigo-600 hover:bg-indigo-600 hover:text-white' : 'bg-slate-100 text-slate-300 opacity-50'}`}
                          >
                            Start
                          </button>
                        )}
                        {task.status !== 'Completed' && (
                          <button 
                            onClick={() => {
                              if (!isClockedIn) return alert('Please clock in first.');
                              onTaskStatusChange(selectedOrder._id, task._id, 'Completed');
                            }}
                            className={`px-3 py-1.5 rounded-lg text-[10px] font-black uppercase transition-all shadow-sm ${isClockedIn ? 'bg-white border-emerald-200 text-emerald-600 hover:bg-emerald-600 hover:text-white' : 'bg-slate-100 text-slate-300 opacity-50'}`}
                          >
                            Done
                          </button>
                        )}
                      </div>
                    </div>
                    
                    {(task.subtasks || []).length > 0 && (
                      <div className="mt-3 space-y-2 border-t border-slate-200 pt-3">
                        <p className="text-[9px] font-black uppercase text-slate-400 tracking-tighter">Sub-steps</p>
                        {task.subtasks.map((subtask) => (
                          <div key={subtask._id} className="flex items-center justify-between bg-white p-2 rounded-lg border border-slate-100">
                            <p className="text-xs text-slate-700 font-medium">
                              • {subtask.subTaskCode ? `${subtask.subTaskCode} - ` : ''}{subtask.title}
                            </p>
                            <div className="flex items-center gap-2">
                               <StatusBadge status={subtask.status || 'Pending'} />
                               {subtask.status !== 'Completed' && (
                                 <button 
                                   onClick={() => {
                                      if (!isClockedIn) return alert('Please clock in first.');
                                      onUpdateSubtask(selectedOrder._id, task._id, subtask._id, { status: 'Completed', isCompleted: true });
                                   }}
                                   className={`p-1 rounded-md transition-all ${isClockedIn ? 'text-emerald-600 hover:bg-emerald-50' : 'text-slate-300'}`}
                                   title="Mark Done"
                                 >
                                    <CheckCircle size={16} />
                                 </button>
                               )}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
                {selectedOrderAssignedTasks.length === 0 && (
                  <div className="text-sm text-slate-500 border border-dashed border-slate-300 rounded-lg p-4 italic">
                    No workflow tasks currently assigned to you.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Requirements Tab */}
          {detailTab === 'Requirements' && (
            <RequirementsModule
              selectedOrder={selectedOrder}
              onUpdateRequirementStatus={onUpdateRequirementStatus}
              onRaiseRequirement={onRaiseRequirement}
              isClockedIn={isClockedIn}
            />
          )}

          {/* Audit & Review Tab */}
          {detailTab === 'Audit & Review' && (
            <div className="space-y-6">
              <div className="rounded-2xl border border-indigo-100 bg-indigo-50/30 p-5 space-y-4">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <h4 className="font-black text-slate-900 text-sm uppercase tracking-tight flex items-center gap-2">
                    <ShieldCheck size={18} className="text-indigo-600" /> Quality Audit Overview
                  </h4>
                  <span className={`px-3 py-1 rounded-full text-xs font-black uppercase tracking-wider ${
                    isAuditApproved ? 'bg-emerald-100 text-emerald-800' :
                    isAuditPending ? 'bg-amber-100 text-amber-800 animate-pulse' :
                    isChangesRequested ? 'bg-rose-100 text-rose-800' : 'bg-slate-200 text-slate-700'
                  }`}>
                    {currentAuditStatus}
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
                  <div className="bg-white p-3.5 rounded-xl border border-slate-200 shadow-sm">
                    <span className="text-[10px] font-bold text-slate-400 uppercase">Assigned Maker</span>
                    <p className="font-bold text-slate-800 text-sm mt-0.5">{selectedOrder.assignedMaker?.name || 'Unassigned'}</p>
                    <p className="text-[10px] text-slate-500 mt-1">
                      Submitted: {selectedOrder.makerSubmittedAt ? new Date(selectedOrder.makerSubmittedAt).toLocaleString() : 'Not submitted yet'}
                    </p>
                  </div>

                  <div className="bg-white p-3.5 rounded-xl border border-slate-200 shadow-sm">
                    <span className="text-[10px] font-bold text-slate-400 uppercase">Assigned Checker</span>
                    <p className="font-bold text-slate-800 text-sm mt-0.5">{selectedOrder.assignedChecker?.name || 'Unassigned'}</p>
                    <p className="text-[10px] text-slate-500 mt-1">
                      Audited: {selectedOrder.checkerAuditedAt ? new Date(selectedOrder.checkerAuditedAt).toLocaleString() : 'Pending audit'}
                    </p>
                  </div>

                  <div className="bg-white p-3.5 rounded-xl border border-slate-200 shadow-sm">
                    <span className="text-[10px] font-bold text-slate-400 uppercase">Project Manager</span>
                    <p className="font-bold text-slate-800 text-sm mt-0.5">
                      {selectedOrder.assignedProjectManager?.name || selectedOrder.assignedEmployee?.name || 'Unassigned'}
                    </p>
                    <p className="text-[10px] text-slate-500 mt-1">Full operational oversight & override</p>
                  </div>
                </div>

                {selectedOrder.auditNotes && (
                  <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm space-y-1">
                    <p className="text-[10px] font-black text-slate-400 uppercase tracking-wider">Latest Notes / Feedback</p>
                    <p className="text-xs font-semibold text-slate-700">{selectedOrder.auditNotes}</p>
                  </div>
                )}
              </div>

              {/* Audit History Timeline */}
              <div className="space-y-3">
                <h4 className="font-black text-slate-900 uppercase tracking-tight text-xs flex items-center gap-1.5">
                  <Clock size={14} /> Audit Trail & Decision Logs
                </h4>
                <div className="relative pl-4 border-l-2 border-indigo-200 space-y-4">
                  {(selectedOrder.auditHistory || []).map((item, idx) => (
                    <div key={idx} className="relative group">
                      <div className={`absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full border-2 border-white ${
                        item.decision === 'Approved' || item.decision === 'Override Approved' ? 'bg-emerald-500' :
                        item.decision === 'Changes Requested' ? 'bg-rose-500' : 'bg-indigo-500'
                      }`} />
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[9px] font-black uppercase tracking-wider ${
                          item.decision === 'Approved' || item.decision === 'Override Approved' ? 'bg-emerald-100 text-emerald-800' :
                          item.decision === 'Changes Requested' ? 'bg-rose-100 text-rose-800' : 'bg-indigo-100 text-indigo-800'
                        }`}>
                          {item.decision}
                        </span>
                        <span className="text-xs font-bold text-slate-800">{item.auditedByName || 'Specialist'}</span>
                        <span className="text-[10px] text-slate-400">{item.timestamp ? new Date(item.timestamp).toLocaleString() : ''}</span>
                      </div>
                      <p className="text-xs font-medium text-slate-600 mt-1 bg-white p-2.5 rounded-lg border border-slate-100 inline-block max-w-xl">
                        {item.notes || 'No notes provided'}
                      </p>
                    </div>
                  ))}
                  {(!selectedOrder.auditHistory || selectedOrder.auditHistory.length === 0) && (
                    <p className="text-xs text-slate-400 italic py-2">No audit logs recorded yet.</p>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Invoices Tab (Excluded for Maker/Checker) */}
          {!isFinancialsHidden && detailTab === 'Invoices' && (
            <div className="space-y-2">
              {(selectedOrder.invoices || []).map((invoice) => (
                <div key={invoice._id} className="rounded-lg border border-slate-200 p-3 flex items-center justify-between bg-white">
                  <div>
                    <p className="font-semibold text-slate-800">{invoice.invoiceNumber || 'Invoice'}</p>
                    <p className="text-xs text-slate-500">{rupees(invoice.amount || 0)}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    {invoice.url && (
                      <a href={invoice.url} target="_blank" rel="noreferrer" className="px-2.5 py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-bold rounded-lg transition shadow-sm">
                        Pay Link
                      </a>
                    )}
                    <StatusBadge status={invoice.status || 'Draft'} />
                  </div>
                </div>
              ))}
              {(selectedOrder.invoices || []).length === 0 && (
                <div className="text-sm text-slate-500 border border-dashed border-slate-300 rounded-lg p-4 italic">
                  No invoices for this project yet.
                </div>
              )}
            </div>
          )}

          {/* ToDo Tab */}
          {detailTab === 'ToDo' && (
            <div className="space-y-4">
              <p className="text-[10px] font-black uppercase text-indigo-500 tracking-widest mb-3">Linked Projects Tasks (TODOs)</p>
              {linkedTodos.map(todo => (
                 <div key={todo._id} className="rounded-xl border border-indigo-100 bg-indigo-50/20 p-4 mb-2 flex items-center justify-between gap-4">
                    <div>
                       <div className="flex items-center gap-2 mb-1">
                          <span className={`px-2 py-0.5 rounded text-[9px] font-black uppercase tracking-wider ${
                             todo.priority === 'Urgent' ? 'bg-rose-100 text-rose-700' : 
                             todo.priority === 'High' ? 'bg-orange-100 text-orange-700' : 'bg-blue-100 text-blue-700'
                          }`}>
                             {todo.priority}
                          </span>
                          <p className="font-bold text-slate-800 text-sm">{todo.title}</p>
                       </div>
                       <p className="text-xs text-slate-500 line-clamp-1">{todo.description || 'No description'}</p>
                    </div>
                    <div className="flex items-center gap-2">
                        {todo.status === 'Pending' && (
                           <button 
                             onClick={() => handleTodoUpdate(todo._id, 'In Progress')}
                             className={`px-3 py-1.5 border rounded-lg text-[10px] font-black uppercase transition-all shadow-sm ${isClockedIn ? 'bg-white border-indigo-200 text-indigo-600 hover:bg-indigo-600 hover:text-white' : 'bg-slate-100 border-slate-200 text-slate-300 opacity-50 cursor-not-allowed'}`}
                           >
                              Start
                           </button>
                        )}
                        {todo.status !== 'Completed' && (
                           <button 
                             onClick={() => handleTodoUpdate(todo._id, 'Completed')}
                             className={`px-3 py-1.5 border rounded-lg text-[10px] font-black uppercase transition-all shadow-sm ${isClockedIn ? 'bg-white border-emerald-200 text-emerald-600 hover:bg-emerald-600 hover:text-white' : 'bg-slate-100 border-slate-200 text-slate-300 opacity-50 cursor-not-allowed'}`}
                           >
                              Done
                           </button>
                        )}
                        {todo.status === 'Completed' && (
                           <div className="text-emerald-500 p-2"><CheckCircle size={18} /></div>
                        )}
                    </div>
                 </div>
              ))}
              {linkedTodos.length === 0 && (
                 <p className="text-xs text-slate-400 italic pl-4">No linked TODO tasks for this project.</p>
              )}
            </div>
          )}

          {/* Transactions Tab (Excluded for Maker/Checker) */}
          {!isFinancialsHidden && detailTab === 'Transactions' && (
            <div className="space-y-4">
              <h4 className="font-black text-slate-900 uppercase tracking-tight text-sm flex items-center gap-2">
                Payments History
              </h4>
              <div className="space-y-2">
                {payments.map((p) => (
                  <div key={p._id} className="p-3 rounded-xl border border-slate-100 bg-white flex items-center justify-between">
                    <div>
                      <p className="text-xs font-black text-slate-800">{p.paymentId}</p>
                      <p className="text-[10px] text-slate-400 font-bold uppercase mt-0.5">{p.method} | {new Date(p.createdAt).toLocaleDateString()}</p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs font-black text-slate-900">{rupees(p.amount)}</p>
                      <span className="px-1.5 py-0.5 rounded text-[8px] font-black uppercase bg-emerald-50 text-emerald-700">
                        {p.status}
                      </span>
                    </div>
                  </div>
                ))}
                {payments.length === 0 && (
                  <p className="text-center text-xs text-slate-400 italic py-4">No transactions recorded yet.</p>
                )}
              </div>
            </div>
          )}

          {/* Activities Tab (Filtered to exclude payment/invoice mentions for Maker/Checker) */}
          {detailTab === 'Activities' && (
            <div className="space-y-4">
              <h4 className="font-black text-slate-900 uppercase tracking-tight text-sm flex items-center gap-2">
                Project Milestones Log
              </h4>
              <div className="relative pl-4 border-l border-slate-100 space-y-4 max-h-[360px] overflow-y-auto pr-1">
                {filteredHistory.map((log) => (
                  <div key={log._id} className="relative group">
                    <div className="absolute -left-[21px] top-1.5 w-2 h-2 rounded-full border-2 border-white bg-indigo-500 group-hover:scale-125 transition-transform" />
                    <p className="text-[10px] font-black text-indigo-600 uppercase tracking-wider">{log.action}</p>
                    <p className="text-xs font-bold text-slate-700 mt-0.5">{log.description}</p>
                    <p className="text-[9px] text-slate-400 mt-0.5">{new Date(log.createdAt).toLocaleString()}</p>
                  </div>
                ))}
                {filteredHistory.length === 0 && (
                  <p className="text-center text-xs text-slate-400 italic py-8">No milestones recorded yet.</p>
                )}
              </div>
            </div>
          )}

          {/* Docs Tab */}
          {detailTab === 'Docs' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between border-b pb-2 mb-4">
                <h4 className="font-black text-slate-900 uppercase tracking-tight text-sm">
                  Documents Vault
                </h4>
                <button
                  onClick={handleDownloadAllDocs}
                  className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-black uppercase tracking-wider transition-all flex items-center gap-1.5 shadow-sm"
                >
                  <Download size={14} /> Download All
                </button>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {selectedOrder.finalCertificateUrl && (
                  <div className="p-4 rounded-xl border border-slate-200 bg-white flex items-center justify-between shadow-sm">
                    <div>
                      <p className="text-xs font-black text-slate-900">Final Incorporation Certificate</p>
                      <p className="text-[9px] text-slate-400 font-bold uppercase mt-0.5">Deliverable</p>
                    </div>
                    <a href={selectedOrder.finalCertificateUrl} target="_blank" rel="noreferrer" className="p-2 bg-indigo-50 hover:bg-indigo-600 hover:text-white rounded-lg text-indigo-600 transition shadow-sm">
                      <Eye size={16} />
                    </a>
                  </div>
                )}
                {(selectedOrder.customerRequirements || []).flatMap((item) => {
                  if (item.documents && item.documents.length > 0) {
                    return item.documents.map((doc, idx) => ({
                      id: `${item._id}-${idx}`,
                      title: `${item.title} - ${doc.name || `File ${idx + 1}`}`,
                      url: doc.url,
                      type: 'Uploaded Requirement'
                    }));
                  } else if (item.uploadedDocumentUrl) {
                    return [{
                      id: item._id,
                      title: item.title,
                      url: item.uploadedDocumentUrl,
                      type: 'Uploaded Requirement'
                    }];
                  }
                  return [];
                }).map((doc) => (
                  <div key={doc.id} className="p-4 rounded-xl border border-slate-200 bg-white flex items-center justify-between shadow-sm">
                    <div>
                      <p className="text-xs font-black text-slate-900 truncate max-w-[200px]">{doc.title}</p>
                      <p className="text-[9px] text-slate-400 font-bold uppercase mt-0.5">{doc.type}</p>
                    </div>
                    <a href={doc.url} target="_blank" rel="noreferrer" className="p-2 bg-indigo-50 hover:bg-indigo-600 hover:text-white rounded-lg text-indigo-600 transition shadow-sm">
                      <Eye size={16} />
                    </a>
                  </div>
                ))}
                {(() => {
                  const requirementUrls = new Set();
                  (selectedOrder.customerRequirements || []).forEach(r => {
                    if (r.documents && r.documents.length > 0) {
                      r.documents.forEach(doc => {
                        if (doc.url) requirementUrls.add(doc.url);
                      });
                    }
                    if (r.uploadedDocumentUrl) {
                      requirementUrls.add(r.uploadedDocumentUrl);
                    }
                  });
                  return (selectedOrder.clientDocuments || [])
                    .filter(doc => !requirementUrls.has(doc.url))
                    .map((doc) => (
                      <div key={doc._id} className="p-4 rounded-xl border border-slate-200 bg-white flex items-center justify-between shadow-sm">
                        <div>
                          <p className="text-xs font-black text-slate-900 truncate max-w-[200px]">{doc.name}</p>
                          <p className="text-[9px] text-slate-400 font-bold uppercase mt-0.5">Client Uploaded Doc</p>
                        </div>
                        <a href={doc.url} target="_blank" rel="noreferrer" className="p-2 bg-indigo-50 hover:bg-indigo-600 hover:text-white rounded-lg text-indigo-600 transition shadow-sm">
                          <Eye size={16} />
                        </a>
                      </div>
                    ));
                })()}

                {/* ITR Checklist Documents */}
                {itrAssessment && itrAssessment.responses?.map((r) => {
                  const docs = [];
                  if (r.documents && r.documents.length > 0) {
                    r.documents.forEach((doc) => {
                      docs.push({ name: `${r.description} - ${doc.originalFileName}`, url: doc.documentUrl });
                    });
                  } else if (r.documentUrl) {
                    docs.push({ name: `${r.description} - ${r.originalFileName || 'Proof'}`, url: r.documentUrl });
                  }
                  return docs.map((doc, idx) => (
                    <div key={`${r._id || r.itemId}-${idx}`} className="p-4 rounded-xl border border-slate-200 bg-white flex items-center justify-between shadow-sm">
                      <div>
                        <p className="text-xs font-black text-slate-900 truncate max-w-[200px]">{doc.name}</p>
                        <p className="text-[9px] text-slate-400 font-bold uppercase mt-0.5">ITR Checklist Upload</p>
                      </div>
                      <a href={doc.url} target="_blank" rel="noreferrer" className="p-2 bg-indigo-50 hover:bg-indigo-600 hover:text-white rounded-lg text-indigo-600 transition shadow-sm">
                        <Eye size={16} />
                      </a>
                    </div>
                  ));
                })}

                {(selectedOrder.adminDocuments || []).map((doc) => (
                  <div key={doc._id} className="p-4 rounded-xl border border-slate-200 bg-white flex items-center justify-between shadow-sm">
                    <div>
                      <p className="text-xs font-black text-slate-900 truncate max-w-[200px]">{doc.name}</p>
                      <p className="text-[9px] text-slate-400 font-bold uppercase mt-0.5">Staff Uploaded Doc</p>
                    </div>
                    <a href={doc.url} target="_blank" rel="noreferrer" className="p-2 bg-indigo-50 hover:bg-indigo-600 hover:text-white rounded-lg text-indigo-600 transition shadow-sm">
                      <Eye size={16} />
                    </a>
                  </div>
                ))}
              </div>

              {/* Upload Controls Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 border-t border-slate-100 pt-5">
                {/* Finish & Deliver Column */}
                <div className="bg-emerald-50/50 border border-emerald-100 rounded-2xl p-4 space-y-3">
                  <h5 className="font-black text-emerald-800 uppercase tracking-tight text-xs flex items-center gap-1.5">
                    <CheckCircle size={14} /> Finish & Deliver (Final Certificate)
                  </h5>
                  {selectedOrder.finalCertificateUrl ? (
                    <div className="p-3 bg-white border border-emerald-100 rounded-xl flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-700">Certificate uploaded</span>
                      <a href={selectedOrder.finalCertificateUrl} target="_blank" rel="noreferrer" className="text-xs font-black text-indigo-600 hover:underline">View File</a>
                    </div>
                  ) : !canUploadDeliverable ? (
                    <div className="p-3 bg-white border border-slate-200 rounded-xl text-xs text-slate-500 text-center font-medium">
                      Requires Checker Audit approval before final certificate delivery.
                    </div>
                  ) : (
                    <form onSubmit={handleUploadFinalCertificate} className="space-y-3">
                      <input 
                        type="file" 
                        required
                        onChange={e => setFile(e.target.files[0])}
                        className="w-full text-xs font-semibold"
                      />
                      <button
                        type="submit"
                        disabled={isUploadingFinal || !file}
                        className="w-full py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-xs font-black uppercase tracking-wider transition-all disabled:opacity-50"
                      >
                        {isUploadingFinal ? 'Uploading...' : 'Upload & Deliver Final Doc'}
                      </button>
                    </form>
                  )}
                </div>

                {/* Send General Doc Column */}
                <div className="bg-indigo-50/40 border border-indigo-100 rounded-2xl p-4 space-y-3">
                  <h5 className="font-black text-indigo-900 uppercase tracking-tight text-xs flex items-center gap-1.5">
                    <Upload size={14} /> Send Document to Customer (for download/signing)
                  </h5>
                  <form onSubmit={handleUploadAdminDoc} className="space-y-3">
                    <input 
                      type="text" 
                      placeholder="Document Name (e.g. Agreement for Sign)"
                      value={adminDocName}
                      onChange={e => setAdminDocName(e.target.value)}
                      className="w-full p-2 border border-slate-200 rounded-xl text-xs font-medium outline-none focus:border-indigo-500"
                    />
                    <input 
                      type="file" 
                      required
                      multiple
                      onChange={e => setAdminDocFiles(Array.from(e.target.files))}
                      className="w-full text-xs font-semibold"
                    />
                    <button
                      type="submit"
                      disabled={isUploadingAdminDoc || adminDocFiles.length === 0}
                      className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-black uppercase tracking-wider transition-all disabled:opacity-50"
                    >
                      {isUploadingAdminDoc ? 'Uploading...' : 'Send Document'}
                    </button>
                  </form>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Modal: Submit to Checker (for Maker / PM) */}
      {submitAuditModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4 animate-in fade-in">
          <div className="bg-white rounded-3xl p-6 max-w-md w-full shadow-2xl border border-slate-100 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-black text-slate-900 flex items-center gap-2">
                <Send size={18} className="text-indigo-600" /> Submit for Quality Audit
              </h3>
              <button onClick={() => setSubmitAuditModalOpen(false)} className="text-slate-400 hover:text-slate-600">
                <XCircle size={20} />
              </button>
            </div>
            <p className="text-xs text-slate-600">
              Submit completed work and deliverables to Checker (<strong>{selectedOrder.assignedChecker?.name || 'Assigned Checker'}</strong>) for quality review.
            </p>
            <div className="space-y-1">
              <label className="text-[10px] font-black uppercase text-slate-400 tracking-wider">Review Remarks / Handover Notes (Optional)</label>
              <textarea
                value={auditNotesInput}
                onChange={(e) => setAuditNotesInput(e.target.value)}
                placeholder="e.g. Completed calculations and drafted filing forms. Please verify PAN and TAN details..."
                rows={3}
                className="w-full p-3 border border-slate-200 rounded-xl text-xs font-medium outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>
            <div className="flex items-center gap-3 pt-2">
              <button
                onClick={() => setSubmitAuditModalOpen(false)}
                className="flex-1 py-2.5 rounded-xl border border-slate-200 text-xs font-bold text-slate-600 hover:bg-slate-50 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmitToChecker}
                disabled={isSubmittingAudit}
                className="flex-1 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-black uppercase tracking-wider transition disabled:opacity-50 shadow-md shadow-indigo-150"
              >
                {isSubmittingAudit ? 'Submitting...' : 'Confirm Submit'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Checker Decision (for Checker / PM / Admin) */}
      {checkerDecisionModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4 animate-in fade-in">
          <div className="bg-white rounded-3xl p-6 max-w-md w-full shadow-2xl border border-slate-100 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-black text-slate-900 flex items-center gap-2">
                {auditDecision === 'Approved' ? (
                  <><ShieldCheck size={20} className="text-emerald-600" /> Approve Work Submission</>
                ) : (
                  <><AlertTriangle size={20} className="text-rose-600" /> Request Changes</>
                )}
              </h3>
              <button onClick={() => setCheckerDecisionModalOpen(false)} className="text-slate-400 hover:text-slate-600">
                <XCircle size={20} />
              </button>
            </div>
            <p className="text-xs text-slate-600">
              {auditDecision === 'Approved' 
                ? 'Approving work will authorize the Maker / PM to upload the final certificate and complete the project.'
                : 'Requesting changes will notify the Maker with your feedback to make necessary revisions.'}
            </p>
            <div className="space-y-1">
              <label className="text-[10px] font-black uppercase text-slate-400 tracking-wider">
                {auditDecision === 'Approved' ? 'Sign-off Remarks (Optional)' : 'Required Corrections / Action Items (Mandatory)'}
              </label>
              <textarea
                value={checkerNotesInput}
                onChange={(e) => setCheckerNotesInput(e.target.value)}
                placeholder={auditDecision === 'Approved' ? 'All calculations verified and accurate.' : 'Please fix the deduction under section 80C and correct the spelling of director name...'}
                rows={3}
                required={auditDecision === 'Changes Requested'}
                className="w-full p-3 border border-slate-200 rounded-xl text-xs font-medium outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>
            <div className="flex items-center gap-3 pt-2">
              <button
                onClick={() => setCheckerDecisionModalOpen(false)}
                className="flex-1 py-2.5 rounded-xl border border-slate-200 text-xs font-bold text-slate-600 hover:bg-slate-50 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleCheckerAudit}
                disabled={isAuditing || (auditDecision === 'Changes Requested' && !checkerNotesInput.trim())}
                className={`flex-1 py-2.5 rounded-xl text-white text-xs font-black uppercase tracking-wider transition disabled:opacity-50 shadow-md ${
                  auditDecision === 'Approved' ? 'bg-emerald-600 hover:bg-emerald-700 shadow-emerald-200' : 'bg-rose-600 hover:bg-rose-700 shadow-rose-200'
                }`}
              >
                {isAuditing ? 'Processing...' : `Confirm ${auditDecision}`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: PM / Admin Assign Team Modal */}
      {assignModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4 animate-in fade-in">
          <div className="bg-white rounded-3xl p-6 max-w-md w-full shadow-2xl border border-slate-100 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-black text-slate-900 flex items-center gap-2">
                <Users size={18} className="text-indigo-600" /> Assign 3-Tier Team
              </h3>
              <button onClick={() => setAssignModalOpen(false)} className="text-slate-400 hover:text-slate-600">
                <XCircle size={20} />
              </button>
            </div>
            <p className="text-xs text-slate-600">
              Assign dedicated Project Manager, Maker (for work execution), and Checker (for quality audit).
            </p>
            <div className="space-y-3">
              <div>
                <label className="text-[10px] font-black uppercase text-slate-400 tracking-wider">Project Manager</label>
                <select
                  value={selectedPmId}
                  onChange={(e) => setSelectedPmId(e.target.value)}
                  className="w-full mt-1 p-2.5 border border-slate-200 rounded-xl text-xs font-bold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500 bg-white"
                >
                  <option value="">Unassigned</option>
                  {staffList.map((st) => (
                    <option key={st._id} value={st._id}>{st.name} ({st.role || 'Employee'})</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-[10px] font-black uppercase text-slate-400 tracking-wider">Maker (Work Execution)</label>
                <select
                  value={selectedMakerId}
                  onChange={(e) => setSelectedMakerId(e.target.value)}
                  className="w-full mt-1 p-2.5 border border-slate-200 rounded-xl text-xs font-bold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500 bg-white"
                >
                  <option value="">Unassigned</option>
                  {staffList.map((st) => (
                    <option key={st._id} value={st._id}>{st.name} ({st.role || 'Employee'})</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-[10px] font-black uppercase text-slate-400 tracking-wider">Checker (Quality Audit)</label>
                <select
                  value={selectedCheckerId}
                  onChange={(e) => setSelectedCheckerId(e.target.value)}
                  className="w-full mt-1 p-2.5 border border-slate-200 rounded-xl text-xs font-bold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500 bg-white"
                >
                  <option value="">Unassigned</option>
                  {staffList.map((st) => (
                    <option key={st._id} value={st._id}>{st.name} ({st.role || 'Employee'})</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="flex items-center gap-3 pt-3">
              <button
                onClick={() => setAssignModalOpen(false)}
                className="flex-1 py-2.5 rounded-xl border border-slate-200 text-xs font-bold text-slate-600 hover:bg-slate-50 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveAssignments}
                disabled={isSavingAssignments}
                className="flex-1 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-black uppercase tracking-wider transition disabled:opacity-50 shadow-md shadow-indigo-150"
              >
                {isSavingAssignments ? 'Saving...' : 'Save Assignments'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default OrderProcessingModule;
