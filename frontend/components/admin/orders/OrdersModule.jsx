import React, { useMemo } from 'react';
import { FileSpreadsheet, Kanban, List, RefreshCcw } from 'lucide-react';
import {
  INVOICE_STATUSES,
  ORDER_STATUSES,
  PACKAGE_OPTIONS
} from './constants';
import { exportOrdersToWorkbook } from './excelParsers';
import { getOrderClientLabel, rupees } from './helpers';
import OrdersListTable from './OrdersListTable';
import OrdersBoardView from './OrdersBoardView';
import OrderFlowSnapshot from './OrderFlowSnapshot';
import OrderOverviewTab from './OrderOverviewTab';
import OrderTasksTab from './OrderTasksTab';
import OrderRequirementsTab from './OrderRequirementsTab';

const Card = ({ children, className = '' }) => (
  <div className={`rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] ${className}`}>
    {children}
  </div>
);

const OrderInvoicesTab = ({ selectedOrder, invoiceForm, setInvoiceForm, onAddInvoice, onUpdateInvoiceStatus }) => (
  <div className="space-y-4">
    <div className="rounded-xl border border-slate-200 p-4 bg-slate-50">
      <p className="font-semibold text-slate-700 mb-3">Raise Additional Invoice</p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <input value={invoiceForm.invoiceNumber} onChange={(event) => setInvoiceForm((prev) => ({ ...prev, invoiceNumber: event.target.value }))} placeholder="Invoice Number" className="p-2.5 border border-slate-300 rounded-lg text-sm" />
        <input type="number" value={invoiceForm.amount} onChange={(event) => setInvoiceForm((prev) => ({ ...prev, amount: event.target.value }))} placeholder="Amount" className="p-2.5 border border-slate-300 rounded-lg text-sm" />
        <select value={invoiceForm.status} onChange={(event) => setInvoiceForm((prev) => ({ ...prev, status: event.target.value }))} className="p-2.5 border border-slate-300 rounded-lg text-sm">
          {INVOICE_STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}
        </select>
        <input type="date" value={invoiceForm.dueDate} onChange={(event) => setInvoiceForm((prev) => ({ ...prev, dueDate: event.target.value }))} className="p-2.5 border border-slate-300 rounded-lg text-sm" />
      </div>
      <button onClick={onAddInvoice} className="mt-3 px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-semibold">Add Invoice</button>
    </div>
    <div className="space-y-2">
      {(selectedOrder.invoices || []).map((invoice) => (
        <div key={invoice._id} className="rounded-lg border border-slate-200 p-3 flex items-center justify-between">
          <div>
            <p className="font-medium">{invoice.invoiceNumber}</p>
            <p className="text-xs text-slate-500">{rupees(invoice.amount)}</p>
          </div>
          <select value={invoice.status} onChange={(event) => onUpdateInvoiceStatus(invoice._id, event.target.value)} className="p-2 border rounded-lg border-slate-300 text-xs">
            {INVOICE_STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}
          </select>
        </div>
      ))}
    </div>
  </div>
);

const OrdersModule = ({
  orders,
  employees,
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
  onAddInvoice,
  onUpdateInvoiceStatus,
  onOpenRecurringModal,
  onAddTask
}) => {
  const selectedOrder = useMemo(() => orders.find((order) => order._id === selectedOrderId) || null, [orders, selectedOrderId]);

  const openOrder = (order) => {
    setSelectedOrderId(order._id);
    setOrderDetailTab('Overview');
  };

  const topActions = (
    <div className="inline-flex rounded-lg border border-slate-200 bg-white overflow-hidden">
      <button onClick={() => setOrdersViewMode('list')} className={`px-3 py-2 text-sm flex items-center gap-1 ${ordersViewMode === 'list' ? 'bg-indigo-50 text-indigo-700' : 'text-slate-600'}`}>
        <List size={14} /> List
      </button>
      <button onClick={() => setOrdersViewMode('board')} className={`px-3 py-2 text-sm flex items-center gap-1 ${ordersViewMode === 'board' ? 'bg-indigo-50 text-indigo-700' : 'text-slate-600'}`}>
        <Kanban size={14} /> Board
      </button>
      <button onClick={() => exportOrdersToWorkbook(orders)} className="px-3 py-2 text-sm flex items-center gap-1 text-slate-600 border-l border-slate-200">
        <FileSpreadsheet size={14} /> Export
      </button>
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
          orders={orders}
          onOpen={openOrder}
          onQuickUpdate={onQuickUpdateOrder}
          onDelete={onDeleteOrder}
        />
      )}

      {!selectedOrder && ordersViewMode === 'board' && (
        <OrdersBoardView orders={orders} onOpen={openOrder} />
      )}

      {selectedOrder && (
        <div className="space-y-4">
          <Card className="p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-xl font-black text-slate-900">{selectedOrder.serviceName}</h2>
                <p className="text-sm text-slate-500 mt-1">{getOrderClientLabel(selectedOrder)} | {rupees(selectedOrder.price)}</p>
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
                <label className="text-xs text-slate-500">Owner</label>
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
            </div>

            <div className="mt-3">
              <button onClick={onSaveCommercials} className="px-3 py-2 rounded-lg bg-indigo-600 text-white text-sm font-semibold hover:bg-indigo-700">Save Package Assignment</button>
            </div>
          </Card>

          <OrderFlowSnapshot />

          <Card>
            <div className="px-4 border-b border-slate-100 flex flex-wrap gap-2">
              {['Overview', 'Tasks', 'Requirements', 'Invoices'].map((tab) => (
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
              {orderDetailTab === 'Overview' && <OrderOverviewTab selectedOrder={selectedOrder} />}
              {orderDetailTab === 'Tasks' && (
                <OrderTasksTab
                  selectedOrder={selectedOrder}
                  employees={employees}
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
                />
              )}
              {orderDetailTab === 'Invoices' && (
                <OrderInvoicesTab
                  selectedOrder={selectedOrder}
                  invoiceForm={invoiceForm}
                  setInvoiceForm={setInvoiceForm}
                  onAddInvoice={() => onAddInvoice(selectedOrder._id)}
                  onUpdateInvoiceStatus={(invoiceId, status) => onUpdateInvoiceStatus(selectedOrder._id, invoiceId, status)}
                />
              )}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
};

export default OrdersModule;
