import React, { useState } from 'react';
import { Upload, Download, CheckCircle } from 'lucide-react';
import { ORDER_STATUSES } from './constants';
import { getOrderClientLabel, StatusBadge } from './helpers';
import { rupees } from '../admin/orders/helpers';
import RequirementsModule from './RequirementsModule';

const OrderProcessingModule = ({
  orders,
  selectedOrder,
  setSelectedOrder,
  onStatusChange,
  onUploadCertificate,
  isUploading,
  userInfo,
  onUpdateRequirementStatus,
  onRaiseRequirement
}) => {
  const [file, setFile] = useState(null);
  const [detailTab, setDetailTab] = useState('Tasks');

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
    if (!file) return;
    onUploadCertificate(file);
    setFile(null);
  };

  return (
    <div className="space-y-4">
      <div className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] p-6">
        <div className="flex justify-between items-start gap-4 flex-wrap">
          <div>
            <h3 className="text-xl font-bold text-slate-800">{selectedOrder.serviceName}</h3>
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
            <form onSubmit={handleUpload} className="space-y-3">
              <input
                type="file"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
                required
                className="w-full text-sm"
              />
              <button
                type="submit"
                disabled={isUploading || !file}
                className="w-full inline-flex items-center justify-center px-4 py-2.5 rounded-lg bg-emerald-600 text-white font-bold text-sm disabled:opacity-50"
              >
                <Upload size={14} className="mr-2" />
                {isUploading ? 'Uploading...' : 'Upload Final Certificate'}
              </button>
            </form>
          )}
        </div>
      </div>

      <div className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)]">
        <div className="px-4 border-b border-slate-100 flex flex-wrap gap-2">
          {['Tasks', 'Requirements', 'Invoices'].map((tab) => (
            <button
              key={tab}
              onClick={() => setDetailTab(tab)}
              className={`px-4 py-3 text-sm font-medium border-b-2 transition ${detailTab === tab ? 'border-indigo-600 text-indigo-700' : 'border-transparent text-slate-500 hover:text-indigo-600'}`}
            >
              {tab}
            </button>
          ))}
        </div>

        <div className="p-5 space-y-3">
          {detailTab === 'Tasks' && (
            <div className="space-y-2">
              {selectedOrderAssignedTasks.map((task) => (
                <div key={task._id} className="rounded-lg border border-slate-200 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <p className="font-semibold text-slate-800">{task.taskCode ? `${task.taskCode} - ${task.title}` : task.title}</p>
                    <StatusBadge status={task.status || 'Pending'} />
                  </div>
                  {(task.subtasks || []).length > 0 && (
                    <div className="mt-2 space-y-1">
                      {task.subtasks.map((subtask) => (
                        <p key={subtask._id} className="text-xs text-slate-600">
                          • {subtask.subTaskCode ? `${subtask.subTaskCode} - ` : ''}{subtask.title} ({subtask.status || 'Pending'})
                        </p>
                      ))}
                    </div>
                  )}
                </div>
              ))}
              {selectedOrderAssignedTasks.length === 0 && (
                <div className="text-sm text-slate-500 border border-dashed border-slate-300 rounded-lg p-4">
                  No tasks currently assigned to you in this project.
                </div>
              )}
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
                <div key={invoice._id} className="rounded-lg border border-slate-200 p-3 flex items-center justify-between">
                  <div>
                    <p className="font-semibold text-slate-800">{invoice.invoiceNumber || 'Invoice'}</p>
                    <p className="text-xs text-slate-500">{rupees(invoice.amount || 0)}</p>
                  </div>
                  <StatusBadge status={invoice.status || 'Draft'} />
                </div>
              ))}
              {(selectedOrder.invoices || []).length === 0 && (
                <div className="text-sm text-slate-500 border border-dashed border-slate-300 rounded-lg p-4">
                  No invoices for this project yet.
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default OrderProcessingModule;
