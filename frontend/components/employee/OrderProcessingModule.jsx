import React, { useState } from 'react';
import { Upload, Download, CheckCircle } from 'lucide-react';
import { ORDER_STATUSES } from './constants';
import { getOrderClientLabel, StatusBadge } from './helpers';

const OrderProcessingModule = ({
  orders,
  selectedOrder,
  setSelectedOrder,
  onStatusChange,
  onUploadCertificate,
  isUploading
}) => {
  const [file, setFile] = useState(null);

  if (!selectedOrder) {
    return (
      <div className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] p-6 overflow-x-auto">
        <table className="w-full text-left min-w-[760px]">
          <thead className="text-xs uppercase font-bold text-slate-500">
            <tr>
              <th className="p-3">Client</th>
              <th className="p-3">Service</th>
              <th className="p-3">Status</th>
              <th className="p-3">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {orders.map((order) => (
              <tr key={order._id}>
                <td className="p-3 font-semibold">{getOrderClientLabel(order)}</td>
                <td className="p-3">{order.serviceName}</td>
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
        <div className="flex justify-between items-start gap-4">
          <div>
            <h3 className="text-xl font-bold text-slate-800">{selectedOrder.serviceName}</h3>
            <p className="text-sm text-slate-500">
              Client: <span className="font-semibold">{getOrderClientLabel(selectedOrder)}</span>
            </p>
          </div>
          <button onClick={() => setSelectedOrder(null)} className="text-indigo-600 font-semibold text-sm">
            Back to List
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="rounded-2xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] p-6">
          <h4 className="font-bold text-slate-800 mb-4">Order Progress</h4>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-500">Current Status</span>
              <StatusBadge status={selectedOrder.status} />
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
    </div>
  );
};

export default OrderProcessingModule;
