import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Upload, Download, CheckCircle, Eye } from 'lucide-react';
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
  onUpdateSubtask
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

  const [adminDocFile, setAdminDocFile] = useState(null);
  const [adminDocName, setAdminDocName] = useState('');
  const [isUploadingAdminDoc, setIsUploadingAdminDoc] = useState(false);
  const [itrAssessment, setItrAssessment] = useState(null);
  const [isUploadingFinal, setIsUploadingFinal] = useState(false);

  const handleUploadFinalCertificate = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
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
      window.location.reload();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to upload final certificate');
    } finally {
      setIsUploadingFinal(false);
    }
  };

  useEffect(() => {
    if (selectedOrder) {
      setEditedName(selectedOrder.serviceName || '');
    }
  }, [selectedOrder]);

  const [payments, setPayments] = useState([]);
  const [history, setHistory] = useState([]);
  const [isLoadingPayments, setIsLoadingPayments] = useState(false);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);

  const config = React.useMemo(() => {
    const activeToken = userInfo?.token;
    return activeToken ? { headers: { Authorization: `Bearer ${activeToken}` } } : null;
  }, [userInfo]);

  const fetchPayments = async () => {
    if (!config || !selectedOrder?._id) return;
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
    if (!adminDocFile || !config) return;
    setIsUploadingAdminDoc(true);
    const formData = new FormData();
    formData.append('document', adminDocFile);
    formData.append('name', adminDocName.trim() || adminDocFile.name);
    try {
      await axios.post(`/api/orders/${selectedOrder._id}/documents`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          ...config.headers
        }
      });
      alert('Document uploaded successfully to customer portal!');
      setAdminDocFile(null);
      setAdminDocName('');
      window.location.reload();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to upload document');
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
      if (r.uploadedDocumentUrl) {
        urls.push({ name: r.title || 'Requirement', url: r.uploadedDocumentUrl });
      }
    });

    const requirementUrls = new Set(
      (selectedOrder.customerRequirements || [])
        .map(r => r.uploadedDocumentUrl)
        .filter(Boolean)
    );

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

  useEffect(() => {
    if (selectedOrder?._id) {
      fetchPayments();
      fetchHistory();
      fetchItrAssessment();
    }
  }, [selectedOrder?._id, detailTab, config]);

  const normalizeId = (value) => {
    if (!value) return '';
    if (typeof value === 'string') return value;
    if (value?._id) return String(value._id);
    return String(value);
  };

  const employeeId = userInfo?._id ? String(userInfo._id) : '';
  const selectedOrderAssignedTasks = (selectedOrder?.tasks || []).filter((task) => {
    const taskAssignees = [task.assignedTo, task.assignedMaker, task.assignedChecker]
      .map(normalizeId)
      .filter(Boolean);
    const subtaskAssignees = (task.subtasks || [])
      .flatMap((subtask) => [subtask.assignedToMaker, subtask.assignedToChecker])
      .map(normalizeId)
      .filter(Boolean);
    return [...taskAssignees, ...subtaskAssignees].includes(employeeId);
  });

  const clientPhone = selectedOrder?.phone || selectedOrder?.user?.phone || '';
  const clientEmail = selectedOrder?.email || selectedOrder?.user?.email || '';

  if (!selectedOrder) {
    return (
      <div className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] p-6 overflow-x-auto">
        <table className="w-full text-left min-w-[760px]">
          <thead className="text-xs uppercase font-bold text-slate-500">
            <tr>
              <th className="p-3">Client</th>
              <th className="p-3">Service</th>
              <th className="p-3">Contact</th>
              <th className="p-3">Status</th>
              <th className="p-3">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {orders.map((order) => (
              <tr key={order._id}>
                <td className="p-3 font-semibold">{getOrderClientLabel(order)}</td>
                <td className="p-3">{order.serviceName}</td>
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
                  <StatusBadge status={order.status} />
                </td>
                <td className="p-3">
                  <button
                    onClick={() => setSelectedOrder(order)}
                    className="px-3 py-1.5 bg-indigo-50 text-indigo-700 rounded-lg text-xs font-bold hover:bg-indigo-100"
                  >
                    Open Processing
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  const handleUpload = (event) => {
    event.preventDefault();
    handleUploadFinalCertificate(event);
  };

  return (
    <div className="space-y-4">
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
              <div className="flex items-center gap-2.5 mb-1">
                <h3 className="text-xl font-bold text-slate-800">{selectedOrder.serviceName}</h3>
                <button 
                  onClick={() => setIsEditingName(true)}
                  className="text-xs text-indigo-600 hover:text-indigo-800 font-bold underline"
                >
                  Edit Name
                </button>
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
          <button onClick={() => setSelectedOrder(null)} className="text-indigo-600 font-semibold text-sm">
            Back to List
          </button>
        </div>
      </div>

      <div className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] p-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
            <p className="text-xs text-slate-500">Status</p>
            <div className="mt-1"><StatusBadge status={selectedOrder.status} /></div>
          </div>
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
            <p className="text-xs text-slate-500">Package</p>
            <p className="font-semibold text-slate-800 mt-1">{selectedOrder.packageName || '-'}</p>
          </div>
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
            <p className="text-xs text-slate-500">Price</p>
            <p className="font-semibold text-slate-800 mt-1">{rupees(selectedOrder.price)}</p>
          </div>
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
            <p className="text-xs text-slate-500">Assigned Tasks</p>
            <p className="font-semibold text-slate-800 mt-1">{selectedOrderAssignedTasks.length}</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] p-6">
          <h4 className="font-bold text-slate-800 mb-4">Order Controls</h4>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-500">Update Status</span>
            </div>
            <select
              value={selectedOrder.status}
              onChange={(e) => onStatusChange(selectedOrder._id, e.target.value)}
              className="w-full p-3 border border-slate-300 rounded-lg bg-white text-sm outline-none focus:ring-2 focus:ring-indigo-500"
            >
              {ORDER_STATUSES.map((status) => (
                <option key={status} value={status}>
                  {status}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="bg-emerald-50 rounded-2xl border border-emerald-200 p-6">
          <h4 className="font-bold text-emerald-800 mb-3 flex items-center">
            <CheckCircle className="mr-2" size={18} />
            Finish & Deliver
          </h4>
          {selectedOrder.finalCertificateUrl ? (
            <a
              href={selectedOrder.finalCertificateUrl}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center text-indigo-600 font-bold text-sm"
            >
              <Download size={14} className="mr-2" />
              View Uploaded Certificate
            </a>
          ) : (
            <form onSubmit={handleUploadFinalCertificate} className="space-y-3">
              <input
                type="file"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
                required
                className="w-full text-sm"
              />
              <button
                type="submit"
                disabled={isUploadingFinal || !file}
                className="w-full inline-flex items-center justify-center px-4 py-2.5 rounded-lg bg-emerald-600 text-white font-bold text-sm disabled:opacity-50"
              >
                <Upload size={14} className="mr-2" />
                {isUploadingFinal ? 'Uploading...' : 'Upload Final Certificate'}
              </button>
            </form>
          )}
        </div>
      </div>

      <div className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)]">
        <div className="px-4 border-b border-slate-100 flex flex-wrap gap-2">
          {['Tasks', 'Requirements', 'Invoices', 'ToDo', 'Transactions', 'Activities', 'Docs'].map((tab) => (
            <button
              key={tab}
              onClick={() => setDetailTab(tab)}
              className={`px-4 py-3 text-sm font-medium border-b-2 transition ${detailTab === tab ? 'border-indigo-600 text-indigo-700' : 'border-transparent text-slate-500 hover:text-indigo-600'}`}
            >
              {tab}
            </button>
          ))}
        </div>

        <div className="p-5 space-y-4">
          {detailTab === 'Tasks' && (
            <div className="space-y-6">
              {/* Workflow Tasks */}
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

          {detailTab === 'Requirements' && (
            <RequirementsModule
              selectedOrder={selectedOrder}
              onUpdateRequirementStatus={onUpdateRequirementStatus}
              onRaiseRequirement={onRaiseRequirement}
            />
          )}

          {detailTab === 'Invoices' && (
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

          {detailTab === 'Transactions' && (
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

          {detailTab === 'Activities' && (
            <div className="space-y-4">
              <h4 className="font-black text-slate-900 uppercase tracking-tight text-sm flex items-center gap-2">
                Project Milestones Log
              </h4>
              <div className="relative pl-4 border-l border-slate-100 space-y-4 max-h-[360px] overflow-y-auto pr-1">
                {history.map((log) => (
                  <div key={log._id} className="relative group">
                    <div className="absolute -left-[21px] top-1.5 w-2 h-2 rounded-full border-2 border-white bg-indigo-500 group-hover:scale-125 transition-transform" />
                    <p className="text-[10px] font-black text-indigo-600 uppercase tracking-wider">{log.action}</p>
                    <p className="text-xs font-bold text-slate-700 mt-0.5">{log.description}</p>
                    <p className="text-[9px] text-slate-400 mt-0.5">{new Date(log.createdAt).toLocaleString()}</p>
                  </div>
                ))}
                {history.length === 0 && (
                  <p className="text-center text-xs text-slate-400 italic py-8">No milestones recorded yet.</p>
                )}
              </div>
            </div>
          )}

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
                {(selectedOrder.customerRequirements || []).filter(r => r.uploadedDocumentUrl).map((item) => (
                  <div key={item._id} className="p-4 rounded-xl border border-slate-200 bg-white flex items-center justify-between shadow-sm">
                    <div>
                      <p className="text-xs font-black text-slate-900 truncate max-w-[200px]">{item.title}</p>
                      <p className="text-[9px] text-slate-400 font-bold uppercase mt-0.5">Uploaded Requirement</p>
                    </div>
                    <a href={item.uploadedDocumentUrl} target="_blank" rel="noreferrer" className="p-2 bg-indigo-50 hover:bg-indigo-600 hover:text-white rounded-lg text-indigo-600 transition shadow-sm">
                      <Eye size={16} />
                    </a>
                  </div>
                ))}
                {(() => {
                  const requirementUrls = new Set(
                    (selectedOrder.customerRequirements || [])
                      .map(r => r.uploadedDocumentUrl)
                      .filter(Boolean)
                  );
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
                {!selectedOrder.finalCertificateUrl && 
                 (selectedOrder.customerRequirements || []).filter(r => r.uploadedDocumentUrl).length === 0 && 
                 (selectedOrder.clientDocuments || []).length === 0 && 
                 (selectedOrder.adminDocuments || []).length === 0 && 
                 (!itrAssessment || !itrAssessment.responses?.some(r => r.documentUrl || r.documents?.length > 0)) && (
                  <p className="col-span-full text-center text-xs text-slate-400 italic py-4">No documents available inside the vault.</p>
                )}
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
                      onChange={e => setAdminDocFile(e.target.files[0])}
                      className="w-full text-xs font-semibold"
                    />
                    <button
                      type="submit"
                      disabled={isUploadingAdminDoc || !adminDocFile}
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
    </div>
  );
};

export default OrderProcessingModule;
