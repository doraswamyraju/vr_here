import React, { useMemo, useState } from 'react';
import { Download, FileText, FolderOpen, Upload } from 'lucide-react';
import axios from 'axios';
import RequirementsWorkspace from './RequirementsWorkspace';

const DocumentsView = ({ orders, refreshOrders, userInfo }) => {
  const [activeOrder, setActiveOrder] = useState(orders[0]?._id || '');
  const [file, setFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [activeTab, setActiveTab] = useState('requirements');

  const selectedOrder = useMemo(() => orders.find((order) => order._id === activeOrder), [orders, activeOrder]);

  const handleUpload = async (event) => {
    event.preventDefault();
    if (!file || !activeOrder) return;

    const formData = new FormData();
    formData.append('document', file);

    setIsUploading(true);
    try {
      await axios.post(`/api/orders/${activeOrder}/documents`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          Authorization: `Bearer ${userInfo.token}`
        }
      });
      setFile(null);
      refreshOrders();
    } catch (error) {
      alert('Error uploading document');
    }
    setIsUploading(false);
  };

  return (
    <div className="space-y-6 pb-20 md:pb-8">
      <div>
        <h1 className="text-2xl font-black text-slate-800 tracking-tight">Project Vault</h1>
        <p className="text-slate-500 text-sm">Manage documents and client requirement submissions.</p>
      </div>

      <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm">
        <label className="block text-[10px] font-black text-slate-400 uppercase tracking-widest mb-2">Active Project</label>
        <select
          value={activeOrder}
          onChange={(event) => setActiveOrder(event.target.value)}
          className="w-full p-3.5 bg-slate-50 border-none rounded-2xl font-black text-slate-800 text-sm"
        >
          {orders.map((order) => (
            <option key={order._id} value={order._id}>{order.serviceName}</option>
          ))}
        </select>
      </div>

      {selectedOrder ? (
        <div className="space-y-4">
          <div className="flex bg-slate-100/50 p-1.5 rounded-2xl gap-1 overflow-x-auto">
            {[
              { key: 'requirements', label: 'Checklist' },
              { key: 'provided', label: 'Admin Docs' },
              { key: 'uploaded', label: 'My uploads' }
            ].map((tab) => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`flex-1 py-3 rounded-xl text-xs font-black transition-all whitespace-nowrap ${activeTab === tab.key ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-400 hover:text-slate-600'}`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {activeTab === 'provided' && (
            <div className="space-y-3">
              {selectedOrder.finalCertificateUrl && (
                <div className="bg-gradient-to-r from-indigo-600 to-indigo-800 rounded-2xl p-4 text-white">
                  <p className="text-sm font-black">Final Certificate Ready</p>
                  <a href={selectedOrder.finalCertificateUrl} target="_blank" rel="noreferrer" className="mt-2 inline-flex items-center gap-2 bg-white text-indigo-700 px-3 py-2 rounded-xl text-xs font-black">
                    <Download size={14} />
                    Download Certificate
                  </a>
                </div>
              )}
              {(selectedOrder.adminDocuments || []).map((doc) => (
                <div key={doc._id} className="bg-white p-4 rounded-2xl border border-slate-100 shadow-sm flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-indigo-50 text-indigo-600 rounded-xl flex items-center justify-center">
                      <FileText size={18} />
                    </div>
                    <div>
                      <p className="font-bold text-sm text-slate-800">{doc.name}</p>
                      <p className="text-[10px] text-slate-400">{new Date(doc.uploadedAt).toLocaleDateString()}</p>
                    </div>
                  </div>
                  <a href={doc.url} target="_blank" rel="noreferrer" className="text-xs font-black text-indigo-700">View</a>
                </div>
              ))}
              {!selectedOrder.adminDocuments?.length && <EmptyDocumentsState text="No admin documents provided yet." />}
            </div>
          )}

          {activeTab === 'uploaded' && (
            <div className="space-y-4">
              <form onSubmit={handleUpload} className="bg-slate-900 rounded-2xl p-5 text-white">
                <p className="font-black text-sm">Upload General Document</p>
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <input type="file" onChange={(event) => setFile(event.target.files?.[0] || null)} className="text-xs" />
                  <button type="submit" disabled={isUploading || !file} className="px-3 py-2 rounded-lg bg-indigo-600 text-white text-xs font-black disabled:opacity-50 inline-flex items-center gap-1">
                    <Upload size={12} />
                    {isUploading ? 'Uploading...' : 'Upload'}
                  </button>
                </div>
              </form>
              {(selectedOrder.clientDocuments || []).map((doc) => (
                <div key={doc._id} className="bg-white p-4 rounded-2xl border border-slate-100 shadow-sm flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-slate-50 text-slate-500 rounded-xl flex items-center justify-center">
                      <FileText size={18} />
                    </div>
                    <div>
                      <p className="font-bold text-sm text-slate-800">{doc.name}</p>
                      <p className="text-[10px] text-slate-400">{new Date(doc.uploadedAt).toLocaleDateString()}</p>
                    </div>
                  </div>
                  <a href={doc.url} target="_blank" rel="noreferrer" className="text-xs font-black text-indigo-700">View</a>
                </div>
              ))}
              {!selectedOrder.clientDocuments?.length && <EmptyDocumentsState text="No client uploads yet." />}
            </div>
          )}

          {activeTab === 'requirements' && (
            <RequirementsWorkspace selectedOrder={selectedOrder} userInfo={userInfo} refreshOrders={refreshOrders} />
          )}
        </div>
      ) : (
        <EmptyDocumentsState text="Please start a project to manage documents." />
      )}
    </div>
  );
};

const EmptyDocumentsState = ({ text }) => (
  <div className="bg-slate-50 border-2 border-dashed border-slate-200 rounded-3xl p-12 text-center text-slate-300">
    <FolderOpen size={48} className="mx-auto mb-4 opacity-30" />
    <p className="text-xs font-bold px-8 leading-relaxed">{text}</p>
  </div>
);

export default DocumentsView;
