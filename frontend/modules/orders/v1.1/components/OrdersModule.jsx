import React, { useMemo, useState, useEffect } from 'react';
import axios from 'axios';
import { 
  FileSpreadsheet, Kanban, List, RefreshCcw, Eye, Download, Upload,
  CheckCircle, Plus, CheckSquare, Clock, User, FileText, Send 
} from 'lucide-react';
import {
  INVOICE_STATUSES,
  ORDER_STATUSES,
  PACKAGE_OPTIONS
} from '../constants/constants';
import { exportOrdersToWorkbook } from '../utils/excelParsers';
import { getOrderClientLabel, rupees } from '../utils/helpers';
import OrdersListTable from './OrdersListTable';
import OrdersBoardView from './OrdersBoardView';
import OrderFlowSnapshot from './OrderFlowSnapshot';
import OrderOverviewTab from './OrderOverviewTab';
import OrderTasksTab from './OrderTasksTab';
import OrderRequirementsTab from './OrderRequirementsTab';
import GSTInvoiceTemplate from '../../../../components/admin/finance/GSTInvoiceTemplate';
import { InvoiceAdjustments } from '../../../invoices/v1.1';

const Card = ({ children, className = '' }) => (
  <div className={`rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] ${className}`}>
    {children}
  </div>
);

const OrderInvoicesTab = ({ selectedOrder, onInitiateBilling, billingLoading, onUpdateInvoiceStatus, onSelectInvoiceForPdf }) => (
  <div className="space-y-4">
    <InvoiceAdjustments
      selectedOrder={selectedOrder}
      onInitiateBilling={onInitiateBilling}
      loading={billingLoading}
    />
    <div className="space-y-2">
      {(selectedOrder.invoices || []).map((invoice) => (
        <div key={invoice._id} className="rounded-lg border border-slate-200 p-3 flex flex-wrap items-center justify-between gap-3 bg-white">
          <div>
            <p className="font-medium">{invoice.invoiceNumber}</p>
            <p className="text-xs text-slate-500">{rupees(invoice.amount)}</p>
            {invoice.notes && <p className="text-[10px] text-slate-400 mt-1 italic">{invoice.notes}</p>}
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {invoice.url && (
              <a href={invoice.url} target="_blank" rel="noreferrer" className="px-2.5 py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-bold rounded-lg transition flex items-center gap-1 shadow-sm">
                Pay Link
              </a>
            )}
            <button onClick={() => onSelectInvoiceForPdf(invoice)} className="px-2.5 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-bold rounded-lg transition flex items-center gap-1 shadow-sm">
              GST PDF
            </button>
            <select value={invoice.status} onChange={(event) => onUpdateInvoiceStatus(invoice._id, event.target.value)} className="p-2 border rounded-lg border-slate-300 text-xs">
              {INVOICE_STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}
            </select>
          </div>
        </div>
      ))}
      {(selectedOrder.invoices || []).length === 0 && (
        <p className="text-xs text-slate-400 italic py-4 text-center">No invoices raised yet.</p>
      )}
    </div>
  </div>
);

const OrdersModule = ({
  token,
  setActiveTab,
  orders,
  employees,
  freelancers = [],
  selectedOrderId,
  setSelectedOrderId,
  ordersViewMode,
  setOrdersViewMode,
  orderDetailTab,
  setOrderDetailTab,
  commercialDraft,
  setCommercialDraft,
  invoiceForm,
  setInvoiceForm,
  onSaveCommercials,
  onDeleteOrder,
  onQuickUpdateOrder,
  onUpdateOrderStatus,
  onAssignOrder,
  onImportTaskWorkbook,
  onTaskStatusChange,
  onTaskAssign,
  onSubtaskUpdate,
  onImportRequirementsWorkbook,
  onRaiseRequirement,
  onUpdateRequirementStatus,
  onDeleteRequirement,
  onResetRequirements,
  onAddInvoice,
  onUpdateInvoiceStatus,
  onOpenRecurringModal,
  onAddTask,
  orderFilter = 'All',
  setOrderFilter,
  onRefresh
}) => {
  const filteredOrders = useMemo(() => {
    if (orderFilter === 'All') return orders;
    if (orderFilter === 'Pending') return orders.filter(o => o.status !== 'Completed');
    if (orderFilter === 'Completed') return orders.filter(o => o.status === 'Completed');
    return orders.filter(o => o.status === orderFilter);
  }, [orders, orderFilter]);

  const selectedOrder = useMemo(() => orders.find((order) => order._id === selectedOrderId) || null, [orders, selectedOrderId]);

  const openOrder = (order) => {
    setSelectedOrderId(order._id);
    setOrderDetailTab('Overview');
  };

  const config = useMemo(() => {
    const userInfo = JSON.parse(localStorage.getItem('userInfo') || '{}');
    const activeToken = token || userInfo?.token;
    return activeToken ? { headers: { Authorization: `Bearer ${activeToken}` } } : null;
  }, [token]);

  const [finalCertFile, setFinalCertFile] = useState(null);
  const [adminDocFiles, setAdminDocFiles] = useState([]);
  const [adminDocName, setAdminDocName] = useState('');
  const [isUploadingFinal, setIsUploadingFinal] = useState(false);
  const [isUploadingAdminDoc, setIsUploadingAdminDoc] = useState(false);

  const [billingLoading, setBillingLoading] = useState(false);
  const handleInitiateBilling = async (payload) => {
    setBillingLoading(true);
    try {
      await axios.post(`/api/orders/${selectedOrder._id}/invoices/adjusted`, payload, config);
      alert('Billing initiated successfully! Invoice has been generated and dispatched to both the customer and admin.');
      if (onRefresh) {
        onRefresh();
      } else {
        window.location.reload();
      }
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to initiate billing.');
    } finally {
      setBillingLoading(false);
    }
  };

  const handleUploadFinalCertificate = async (e) => {
    e.preventDefault();
    if (!finalCertFile || !config) return;
    setIsUploadingFinal(true);
    const formData = new FormData();
    formData.append('document', finalCertFile);
    formData.append('isFinalCertificate', 'true');
    try {
      await axios.post(`/api/orders/${selectedOrder._id}/documents`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          ...config.headers
        }
      });
      alert('Final certificate uploaded successfully and project status set to Completed!');
      setFinalCertFile(null);
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

  const handleUploadAdminDoc = async (e) => {
    e.preventDefault();
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

  const [payments, setPayments] = useState([]);
  const [isLoadingPayments, setIsLoadingPayments] = useState(false);
  const fetchPayments = async () => {
    if (!config || !selectedOrderId) return;
    setIsLoadingPayments(true);
    try {
      const { data } = await axios.get(`/api/payments?orderId=${selectedOrderId}`, config);
      setPayments(data || []);
    } catch (err) {
      console.error('Error fetching payments:', err.message);
    } finally {
      setIsLoadingPayments(false);
    }
  };

  const [history, setHistory] = useState([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const fetchHistory = async () => {
    if (!config || !selectedOrderId) return;
    setIsLoadingHistory(true);
    try {
      const { data } = await axios.get(`/api/orders/${selectedOrderId}/history`, config);
      setHistory(data || []);
    } catch (err) {
      console.error('Error fetching history:', err.message);
    } finally {
      setIsLoadingHistory(false);
    }
  };

  const [todos, setTodos] = useState([]);
  const [isLoadingTodos, setIsLoadingTodos] = useState(false);
  const [newTodoTitle, setNewTodoTitle] = useState('');
  const fetchTodos = async () => {
    if (!config || !selectedOrderId) return;
    setIsLoadingTodos(true);
    try {
      const { data } = await axios.get(`/api/todos?orderId=${selectedOrderId}`, config);
      setTodos(data || []);
    } catch (err) {
      console.error('Error fetching todos:', err.message);
    } finally {
      setIsLoadingTodos(false);
    }
  };

  const handleCreateTodo = async (e) => {
    e.preventDefault();
    if (!newTodoTitle.trim() || !config) return;
    try {
      await axios.post('/api/todos', {
        title: newTodoTitle.trim(),
        orderId: selectedOrderId,
        priority: 'Medium'
      }, config);
      setNewTodoTitle('');
      fetchTodos();
    } catch (err) {
      console.error('Error creating todo:', err.message);
    }
  };

  const handleToggleTodo = async (todo) => {
    if (!config) return;
    const newStatus = todo.status === 'Completed' ? 'Pending' : 'Completed';
    try {
      await axios.put(`/api/todos/${todo._id}`, { status: newStatus }, config);
      fetchTodos();
    } catch (err) {
      console.error('Error toggling todo:', err.message);
    }
  };

  const [itrAssessment, setItrAssessment] = useState(null);
  const fetchItrAssessment = async () => {
    if (!config || !selectedOrderId) return;
    const order = orders.find(o => o._id === selectedOrderId);
    const isITR = order?.serviceName?.toLowerCase().includes('income tax') || order?.packageName?.toLowerCase().includes('itr');
    if (!isITR) {
      setItrAssessment(null);
      return;
    }
    try {
      const { data } = await axios.get(`/api/income-tax-assessment?orderId=${selectedOrderId}`, config);
      if (data && data.length > 0) {
        setItrAssessment(data[0]);
      } else {
        setItrAssessment(null);
      }
    } catch (err) {
      console.error('Error fetching ITR assessment:', err.message);
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

    // Trigger download for each URL with a short delay to bypass browser blocking
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
    if (selectedOrderId) {
      fetchPayments();
      fetchHistory();
      fetchTodos();
      fetchItrAssessment();
    }
  }, [selectedOrderId, orderDetailTab, config]);

  const [selectedInvoiceForPdf, setSelectedInvoiceForPdf] = useState(null);

  const constructInvoiceData = (invoice, order) => {
    if (!invoice || !order) return null;
    const amount = invoice.amount || 0;
    const subtotal = Math.round(amount / 1.18);
    const tax = amount - subtotal;
    const halfTax = Math.round(tax / 2);

    return {
      type: 'Tax Invoice',
      number: invoice.invoiceNumber || `INV-${invoice._id?.substring(0, 8) || Date.now()}`,
      date: invoice.createdAt || new Date(),
      dueDate: invoice.dueDate,
      client: {
        name: order.clientName || 'Customer',
        phone: order.phone || '',
        email: order.email || '',
        address: 'Place of Supply: Telangana'
      },
      items: [
        {
          description: `${order.serviceName} - ${order.packageName || 'Package Services'}`,
          qty: 1,
          rate: subtotal,
          taxRate: 18,
          amount: subtotal
        }
      ],
      totals: {
        subtotal: subtotal,
        cgst: halfTax,
        sgst: halfTax,
        igst: 0,
        total: amount
      },
      notes: invoice.notes || 'Thank you for choosing VR Here Business Management Solutions.'
    };
  };

  const topActions = (
    <div className="flex flex-wrap items-center gap-3">
      <select 
        value={orderFilter} 
        onChange={(e) => setOrderFilter(e.target.value)}
        className="px-3 py-2 text-sm rounded-lg border border-slate-200 bg-white font-medium text-slate-600 focus:ring-2 focus:ring-indigo-500/20"
      >
        <option value="All">All Statuses</option>
        <option value="Pending">All Pending</option>
        {ORDER_STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
        <option value="Completed">Completed</option>
      </select>
      <div className="inline-flex rounded-lg border border-slate-200 bg-white overflow-hidden shadow-sm">
        <button onClick={() => setOrdersViewMode('list')} className={`px-3 py-2 text-sm flex items-center gap-1 transition-colors ${ordersViewMode === 'list' ? 'bg-indigo-600 text-white' : 'text-slate-600 hover:bg-slate-50'}`}>
          <List size={14} /> List
        </button>
        <button onClick={() => setOrdersViewMode('board')} className={`px-3 py-2 text-sm flex items-center gap-1 transition-colors ${ordersViewMode === 'board' ? 'bg-indigo-600 text-white' : 'text-slate-600 hover:bg-slate-50'}`}>
          <Kanban size={14} /> Board
        </button>
        <button onClick={() => exportOrdersToWorkbook(filteredOrders)} className="px-3 py-2 text-sm flex items-center gap-1 text-slate-600 border-l border-slate-200 hover:bg-slate-50">
          <FileSpreadsheet size={14} /> Export
        </button>
      </div>
    </div>
  );

  return (
    <div className="space-y-4">
      {!selectedOrder && (
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="text-2xl font-bold text-slate-800">Orders</h2>
            <p className="text-sm text-slate-500">Manage assignments, task imports, requirements, and billing from one flow.</p>
          </div>
          {topActions}
        </div>
      )}

      {!selectedOrder && ordersViewMode === 'list' && (
        <OrdersListTable
          orders={filteredOrders}
          onOpen={openOrder}
          onQuickUpdate={onQuickUpdateOrder}
          onDelete={onDeleteOrder}
        />
      )}

      {!selectedOrder && ordersViewMode === 'board' && (
        <OrdersBoardView orders={filteredOrders} onOpen={openOrder} />
      )}

      {selectedOrder && (
        <div className="space-y-4">
          <Card className="p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-xl font-black text-slate-900">{selectedOrder.serviceName}</h2>
                <p className="text-sm text-slate-500 mt-1">
                  <span 
                    onClick={() => {
                      if (setActiveTab) {
                        setActiveTab('Customers');
                      }
                    }}
                    className="cursor-pointer text-indigo-700 hover:text-indigo-900 font-bold hover:underline"
                    title="View Customer Profile"
                  >
                    {getOrderClientLabel(selectedOrder)}
                  </span>
                  {' '}| {rupees(selectedOrder.price)}
                </p>
                <div className="mt-1 flex flex-wrap gap-3 text-xs">
                  {(selectedOrder.phone || selectedOrder?.user?.phone) ? (
                    <a href={`tel:${selectedOrder.phone || selectedOrder?.user?.phone}`} className="text-indigo-700 font-semibold hover:underline">
                      Call: {selectedOrder.phone || selectedOrder?.user?.phone}
                    </a>
                  ) : (
                    <span className="text-slate-400">Phone not available</span>
                  )}
                  {(selectedOrder.email || selectedOrder?.user?.email) ? (
                    <a href={`mailto:${selectedOrder.email || selectedOrder?.user?.email}`} className="text-indigo-700 font-semibold hover:underline">
                      Email: {selectedOrder.email || selectedOrder?.user?.email}
                    </a>
                  ) : (
                    <span className="text-slate-400">Email not available</span>
                  )}
                </div>
              </div>
              <div className="flex gap-2">
                <button 
                  onClick={onOpenRecurringModal} 
                  className="px-3 py-2 rounded-lg bg-indigo-50 text-indigo-700 text-sm font-bold hover:bg-slate-900 hover:text-white transition-all flex items-center gap-1.5 shadow-sm shadow-indigo-100"
                >
                  <RefreshCcw size={14} /> Make Recurring
                </button>
                <button onClick={() => setSelectedOrderId(null)} className="px-3 py-2 rounded-lg bg-slate-100 text-slate-700 text-sm font-medium hover:bg-slate-200">Back to Orders</button>
              </div>
            </div>

            <div className="mt-4 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-6 gap-3">
              <div className="xl:col-span-2">
                <label className="text-xs text-slate-500">Status</label>
                <select value={selectedOrder.status} onChange={(event) => onUpdateOrderStatus(selectedOrder._id, event.target.value)} className="w-full mt-1 p-2.5 border rounded-lg border-slate-300 bg-white">
                  {ORDER_STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}
                </select>
              </div>
              <div>
                <label className="text-xs text-slate-500 font-semibold">Project Manager</label>
                <select value={selectedOrder.assignedEmployee?._id || selectedOrder.assignedEmployee || ''} onChange={(event) => onAssignOrder(selectedOrder._id, { employeeId: event.target.value || null })} className="w-full mt-1 p-2.5 border rounded-lg border-slate-300 bg-white">
                  <option value="">Unassigned</option>
                  {employees.map((employee) => <option key={employee._id} value={employee._id}>{employee.name}</option>)}
                </select>
              </div>
              <div>
                <label className="text-xs text-slate-500">Maker</label>
                <select value={selectedOrder.assignedMaker?._id || selectedOrder.assignedMaker || ''} onChange={(event) => onAssignOrder(selectedOrder._id, { makerId: event.target.value || null })} className="w-full mt-1 p-2.5 border rounded-lg border-slate-300 bg-white">
                  <option value="">Unassigned</option>
                  {employees.map((employee) => <option key={employee._id} value={employee._id}>{employee.name}</option>)}
                </select>
              </div>
              <div>
                <label className="text-xs text-slate-500">Checker</label>
                <select value={selectedOrder.assignedChecker?._id || selectedOrder.assignedChecker || ''} onChange={(event) => onAssignOrder(selectedOrder._id, { checkerId: event.target.value || null })} className="w-full mt-1 p-2.5 border rounded-lg border-slate-300 bg-white">
                  <option value="">Unassigned</option>
                  {employees.map((employee) => <option key={employee._id} value={employee._id}>{employee.name}</option>)}
                </select>
              </div>
              <div>
                <label className="text-xs text-slate-500">Package</label>
                <select value={commercialDraft.packageName} onChange={(event) => setCommercialDraft((prev) => ({ ...prev, packageName: event.target.value }))} className="w-full mt-1 p-2.5 border rounded-lg border-slate-300 bg-white">
                  <option value="">Select Package</option>
                  {PACKAGE_OPTIONS.map((item) => <option key={item} value={item}>{item}</option>)}
                </select>
              </div>
              <div>
                <label className="text-xs text-slate-500">Price</label>
                <input value={commercialDraft.price} onChange={(event) => setCommercialDraft((prev) => ({ ...prev, price: event.target.value }))} className="w-full mt-1 p-2.5 border rounded-lg border-slate-300" />
              </div>
              <div className="xl:col-span-2">
                <label className="text-xs text-slate-500">Order Name (Service)</label>
                <input value={commercialDraft.serviceName || ''} onChange={(event) => setCommercialDraft((prev) => ({ ...prev, serviceName: event.target.value }))} className="w-full mt-1 p-2.5 border rounded-lg border-slate-300" />
              </div>
            </div>

            <div className="mt-3">
              <button onClick={onSaveCommercials} className="px-3 py-2 rounded-lg bg-indigo-600 text-white text-sm font-semibold hover:bg-indigo-700">Save Package Assignment</button>
            </div>
          </Card>

          <Card>
            <div className="px-4 border-b border-slate-100 flex flex-wrap gap-2">
              {['Overview', 'Tasks', 'Requirements', 'Invoices', 'ToDo', 'Transactions', 'Activities', 'Docs'].map((tab) => (
                <button
                  key={tab}
                  onClick={() => setOrderDetailTab(tab)}
                  className={`px-4 py-3 text-sm font-medium border-b-2 transition ${orderDetailTab === tab ? 'border-indigo-600 text-indigo-700' : 'border-transparent text-slate-500 hover:text-indigo-600'}`}
                >
                  {tab}
                </button>
              ))}
            </div>
            <div className="p-5 space-y-4">
              {orderDetailTab === 'Overview' && <OrderOverviewTab selectedOrder={selectedOrder} token={token} onRefresh={onRefresh} />}
              {orderDetailTab === 'Tasks' && (
                <OrderTasksTab
                  selectedOrder={selectedOrder}
                  employees={employees}
                  freelancers={freelancers}
                  onTaskStatusChange={(taskId, status) => onTaskStatusChange(selectedOrder._id, taskId, status)}
                  onTaskAssign={(taskId, payload) => onTaskAssign(selectedOrder._id, taskId, payload)}
                  onSubtaskUpdate={(taskId, subtaskId, payload) => onSubtaskUpdate(selectedOrder._id, taskId, subtaskId, payload)}
                  onImportTaskWorkbook={(file, replaceExisting) => onImportTaskWorkbook(selectedOrder._id, file, replaceExisting)}
                  onAddTask={onAddTask}
                />
              )}
              {orderDetailTab === 'Requirements' && (
                <OrderRequirementsTab
                  selectedOrder={selectedOrder}
                  onImportRequirementsWorkbook={(file, replaceExisting) => onImportRequirementsWorkbook(selectedOrder._id, file, replaceExisting)}
                  onRaiseRequirement={(payload) => onRaiseRequirement(selectedOrder._id, payload)}
                  onUpdateRequirementStatus={(requirementId, status) => onUpdateRequirementStatus(selectedOrder._id, requirementId, status)}
                  onDeleteRequirement={(requirementId) => onDeleteRequirement(selectedOrder._id, requirementId)}
                  onResetRequirements={(type) => onResetRequirements && onResetRequirements(selectedOrder._id, type)}
                />
              )}
              {orderDetailTab === 'Invoices' && (
                <OrderInvoicesTab
                  selectedOrder={selectedOrder}
                  onInitiateBilling={handleInitiateBilling}
                  billingLoading={billingLoading}
                  onUpdateInvoiceStatus={(invoiceId, status) => onUpdateInvoiceStatus(selectedOrder._id, invoiceId, status)}
                  onSelectInvoiceForPdf={setSelectedInvoiceForPdf}
                />
              )}
              {orderDetailTab === 'ToDo' && (
                <div className="space-y-4">
                  <h4 className="font-black text-slate-900 uppercase tracking-tight text-sm mb-4 flex items-center gap-2">
                    <CheckCircle size={16} className="text-indigo-600" /> To-Dos Checklist
                  </h4>
                  
                  <form onSubmit={handleCreateTodo} className="flex gap-2 mb-4">
                    <input 
                      type="text" 
                      placeholder="Add new order-specific task..."
                      value={newTodoTitle}
                      onChange={e => setNewTodoTitle(e.target.value)}
                      className="flex-1 p-2.5 border border-slate-200 rounded-xl text-sm focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 outline-none"
                    />
                    <button type="submit" className="p-2.5 rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 active:scale-95 transition-transform flex items-center justify-center">
                      <Plus size={18} />
                    </button>
                  </form>

                  <div className="space-y-2 max-h-80 overflow-y-auto">
                    {todos.map(todo => (
                      <div 
                        key={todo._id} 
                        onClick={() => handleToggleTodo(todo)}
                        className="flex items-center gap-3 p-3 rounded-xl border border-slate-100 hover:border-slate-200 bg-slate-50/30 cursor-pointer transition-colors group"
                      >
                        <div className={`w-5 h-5 rounded-md border flex items-center justify-center transition-colors ${
                          todo.status === 'Completed' ? 'bg-indigo-600 border-indigo-600 text-white' : 'border-slate-300 bg-white group-hover:border-indigo-500'
                        }`}>
                          {todo.status === 'Completed' && <CheckSquare size={14} />}
                        </div>
                        <span className={`text-xs font-bold ${
                          todo.status === 'Completed' ? 'line-through text-slate-400' : 'text-slate-700'
                        }`}>
                          {todo.title}
                        </span>
                      </div>
                    ))}
                    {todos.length === 0 && (
                      <p className="text-center text-xs text-slate-400 italic py-4">No task listed. Add one above!</p>
                    )}
                  </div>
                </div>
              )}
              {orderDetailTab === 'Transactions' && (
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
              {orderDetailTab === 'Activities' && (
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
              {orderDetailTab === 'Docs' && (
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
                            onChange={e => setFinalCertFile(e.target.files[0])}
                            className="w-full text-xs font-semibold"
                          />
                          <button
                            type="submit"
                            disabled={isUploadingFinal || !finalCertFile}
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
          </Card>
        </div>
      )}

      {selectedInvoiceForPdf && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-white rounded-2xl max-w-4xl w-full shadow-2xl overflow-hidden border border-slate-100 animate-in fade-in zoom-in-95 duration-200">
            <div className="bg-slate-50 p-4 border-b border-slate-100 flex justify-between items-center sticky top-0 z-10">
              <h3 className="font-bold text-slate-800">GST Invoice View</h3>
              <div className="flex gap-2">
                <button onClick={() => window.print()} className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-bold shadow-md shadow-indigo-100 flex items-center gap-1.5 transition-all">
                  Print / Save PDF
                </button>
                <button onClick={() => setSelectedInvoiceForPdf(null)} className="px-4 py-2 bg-slate-200 hover:bg-slate-300 text-slate-800 rounded-xl text-xs font-bold transition-all">
                  Close
                </button>
              </div>
            </div>
            <div className="p-6 max-h-[80vh] overflow-y-auto">
              <GSTInvoiceTemplate data={constructInvoiceData(selectedInvoiceForPdf, selectedOrder)} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default OrdersModule;


