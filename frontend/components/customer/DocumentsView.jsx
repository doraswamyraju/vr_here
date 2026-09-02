import React, { useMemo, useState } from 'react';
import { Download, FileText, FolderOpen, Upload, ShieldCheck, CheckCircle2, Clock, AlertTriangle, FileCheck, ExternalLink, Plus, RefreshCw } from 'lucide-react';
import axios from 'axios';
import RequirementsWorkspace from './RequirementsWorkspace';
import ITRAssessmentCustomerView from './ITRAssessmentCustomerView';

const DocumentsView = ({ orders, refreshOrders, userInfo }) => {
  const [activeOrder, setActiveOrder] = useState(orders[0]?._id || '');
  const [files, setFiles] = useState([]);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState('');
  const [activeTab, setActiveTab] = useState('requirements');
  const [isDragging, setIsDragging] = useState(false);

  const selectedOrder = useMemo(() => orders.find((order) => order._id === activeOrder) || orders[0], [orders, activeOrder]);

  const handleUpload = async (event) => {
    event?.preventDefault();
    if (files.length === 0 || !activeOrder) return;

    setIsUploading(true);
    try {
      for (let i = 0; i < files.length; i++) {
        setUploadStatus(`Uploading ${i + 1} of ${files.length}...`);
        const formData = new FormData();
        formData.append('document', files[i]);
        formData.append('name', files[i].name);

        await axios.post(`/api/orders/${activeOrder}/documents`, formData, {
          headers: {
            'Content-Type': 'multipart/form-data',
            Authorization: `Bearer ${userInfo.token}`
          }
        });
      }
      setFiles([]);
      refreshOrders();
      alert('All documents uploaded successfully.');
    } catch (error) {
      alert('Error uploading document(s)');
    } finally {
      setIsUploading(false);
      setUploadStatus('');
    }
  };

  const totalAdminDocs = orders.reduce((acc, curr) => acc + (curr.adminDocuments?.length || 0) + (curr.finalCertificateUrl ? 1 : 0), 0);
  const totalClientDocs = orders.reduce((acc, curr) => acc + (curr.clientDocuments?.length || 0), 0);

  return (
    <div className="space-y-8 pb-24 lg:pb-12 animate-in fade-in slide-in-from-bottom-3 duration-500">
      
      {/* 1. Header & Vault Overview */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl lg:text-3xl font-black text-slate-900 tracking-tight flex items-center gap-2.5">
            <span>Project Vault</span>
            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider bg-emerald-50 text-emerald-700 border border-emerald-200">
              256-Bit Encrypted
            </span>
          </h1>
          <p className="text-slate-500 text-xs sm:text-sm font-medium mt-0.5">
            Secure digital repository for verified government deliverables, KYC proofs, and filings.
          </p>
        </div>
        
        <button
          onClick={refreshOrders}
          className="self-start md:self-auto flex items-center gap-2 px-3.5 py-2 bg-white hover:bg-slate-100 text-slate-700 text-xs font-bold rounded-xl border border-slate-200 transition-colors shadow-2xs"
        >
          <RefreshCw size={14} />
          <span>Refresh Vault</span>
        </button>
      </div>

      {/* 2. Vault KPI Stat Bar */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white rounded-2xl p-5 border border-slate-200/90 shadow-2xs">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Certificates Issued</span>
            <div className="w-8 h-8 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center">
              <FileCheck size={16} />
            </div>
          </div>
          <h3 className="text-2xl font-black text-slate-900">{totalAdminDocs}</h3>
          <p className="text-[11px] text-slate-500 font-medium mt-0.5">Approved deliverables</p>
        </div>

        <div className="bg-white rounded-2xl p-5 border border-slate-200/90 shadow-2xs">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">My Uploads</span>
            <div className="w-8 h-8 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center">
              <Upload size={16} />
            </div>
          </div>
          <h3 className="text-2xl font-black text-slate-900">{totalClientDocs}</h3>
          <p className="text-[11px] text-slate-500 font-medium mt-0.5">Submitted proofs</p>
        </div>

        <div className="bg-white rounded-2xl p-5 border border-slate-200/90 shadow-2xs">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Active Engagements</span>
            <div className="w-8 h-8 rounded-xl bg-red-50 text-red-600 flex items-center justify-center">
              <FolderOpen size={16} />
            </div>
          </div>
          <h3 className="text-2xl font-black text-slate-900">{orders.length}</h3>
          <p className="text-[11px] text-slate-500 font-medium mt-0.5">Linked project vaults</p>
        </div>

        <div className="bg-white rounded-2xl p-5 border border-slate-200/90 shadow-2xs">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Vault Security</span>
            <div className="w-8 h-8 rounded-xl bg-purple-50 text-purple-600 flex items-center justify-center">
              <ShieldCheck size={16} />
            </div>
          </div>
          <h3 className="text-base font-black text-slate-900 mt-1">ISO 27001:2022</h3>
          <p className="text-[11px] text-slate-500 font-medium mt-0.5">Certified Data Vault</p>
        </div>
      </div>

      {/* 3. Interactive Project Selector */}
      {orders.length > 0 ? (
        <div className="bg-white rounded-3xl p-6 border border-slate-200/90 shadow-2xs space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div>
              <p className="text-[10px] font-black uppercase tracking-widest text-slate-400">Current Workspace</p>
              <h3 className="text-lg font-black text-slate-900 tracking-tight">{selectedOrder?.serviceName || 'Project'}</h3>
            </div>
            <div className="flex items-center gap-2">
              <span className="px-3 py-1 bg-red-50 text-red-600 rounded-full text-xs font-black uppercase tracking-wider border border-red-200">
                {selectedOrder?.status || 'Active'}
              </span>
              <span className="text-xs text-slate-400 font-semibold">
                ID: #{String(selectedOrder?._id).slice(-6).toUpperCase()}
              </span>
            </div>
          </div>

          {/* Project Switcher Pills */}
          <div className="flex gap-2 overflow-x-auto pb-1 scrollbar-none pt-2 border-t border-slate-100">
            {orders.map((order) => (
              <button
                key={order._id}
                onClick={() => setActiveOrder(order._id)}
                className={`px-4 py-2 rounded-xl text-xs font-bold whitespace-nowrap transition-all border shrink-0 ${
                  (activeOrder === order._id || (!activeOrder && selectedOrder?._id === order._id))
                    ? 'bg-slate-900 text-white border-slate-900 shadow-sm'
                    : 'bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100'
                }`}
              >
                {order.serviceName}
              </button>
            ))}
          </div>
        </div>
      ) : null}

      {/* 4. Main Vault Content & Tabs */}
      {selectedOrder ? (
        <div className="space-y-6">
          {/* Tab Navigation */}
          <div className="flex bg-slate-200/70 p-1.5 rounded-2xl gap-1.5 overflow-x-auto">
            {[
              { key: 'requirements', label: 'Checklist & KYC Proofs' },
              { key: 'provided', label: `Government Deliverables (${(selectedOrder.adminDocuments?.length || 0) + (selectedOrder.finalCertificateUrl ? 1 : 0)})` },
              { key: 'uploaded', label: `My Vault Uploads (${selectedOrder.clientDocuments?.length || 0})` }
            ].map((tab) => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`flex-1 py-3 px-4 rounded-xl text-xs font-black transition-all whitespace-nowrap text-center ${
                  activeTab === tab.key
                    ? 'bg-white text-red-600 shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab 1: Government Deliverables */}
          {activeTab === 'provided' && (
            <div className="space-y-4">
              {selectedOrder.finalCertificateUrl && (
                <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950 rounded-3xl p-6 text-white border border-slate-800 shadow-xl flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                  <div className="flex items-center gap-4">
                    <div className="w-12 h-12 rounded-2xl bg-emerald-500/20 text-emerald-400 flex items-center justify-center font-bold border border-emerald-500/30 shrink-0">
                      <FileCheck size={24} />
                    </div>
                    <div>
                      <h4 className="text-base font-black text-white">Final Government Certificate Ready</h4>
                      <p className="text-xs text-slate-300 font-medium">Officially issued by Ministry of Corporate Affairs / Govt Dept.</p>
                    </div>
                  </div>
                  <a
                    href={selectedOrder.finalCertificateUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center justify-center gap-2 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-700 hover:to-rose-700 text-white px-5 py-3 rounded-xl text-xs font-bold uppercase tracking-wider shadow-md shrink-0 transition-all"
                  >
                    <Download size={14} />
                    <span>Download Certificate</span>
                  </a>
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {(selectedOrder.adminDocuments || []).map((doc) => (
                  <div key={doc._id} className="bg-white p-5 rounded-2xl border border-slate-200/90 shadow-2xs hover:shadow-md transition-all flex items-center justify-between gap-4">
                    <div className="flex items-center gap-3.5 min-w-0">
                      <div className="w-11 h-11 bg-red-50 text-red-600 border border-red-200/80 rounded-xl flex items-center justify-center shrink-0">
                        <FileText size={20} />
                      </div>
                      <div className="min-w-0">
                        <p className="font-bold text-sm text-slate-900 truncate">{doc.name}</p>
                        <p className="text-[10px] text-slate-400 font-medium">Issued on {new Date(doc.uploadedAt || Date.now()).toLocaleDateString()}</p>
                      </div>
                    </div>
                    <a
                      href={doc.url}
                      target="_blank"
                      rel="noreferrer"
                      className="px-3 py-1.5 bg-slate-100 hover:bg-red-50 hover:text-red-600 text-slate-700 rounded-lg text-xs font-bold transition-colors shrink-0 flex items-center gap-1"
                    >
                      <span>View</span>
                      <ExternalLink size={12} />
                    </a>
                  </div>
                ))}
              </div>

              {!selectedOrder.adminDocuments?.length && !selectedOrder.finalCertificateUrl && (
                <EmptyDocumentsState text="Government certificate & deliverables will appear here once approval is issued by the ministry." />
              )}
            </div>
          )}

          {/* Tab 2: Client Uploaded Vault Files */}
          {activeTab === 'uploaded' && (
            <div className="space-y-6">
              {/* Modern Drag & Drop Upload Card */}
              <div
                onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                onDragLeave={() => setIsDragging(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setIsDragging(false);
                  if (e.dataTransfer.files) {
                    setFiles(Array.from(e.dataTransfer.files));
                  }
                }}
                className={`bg-white rounded-3xl p-6 border-2 border-dashed transition-all ${
                  isDragging ? 'border-red-500 bg-red-50/20' : 'border-slate-300 hover:border-red-300'
                }`}
              >
                <div className="text-center max-w-md mx-auto space-y-3">
                  <div className="w-12 h-12 rounded-2xl bg-red-50 text-red-600 border border-red-200 flex items-center justify-center mx-auto">
                    <Upload size={22} />
                  </div>
                  <div>
                    <h4 className="text-sm font-black text-slate-900">Upload General Documents & KYC</h4>
                    <p className="text-xs text-slate-500 font-medium mt-0.5">Drag and drop files here, or click to browse</p>
                  </div>
                  
                  <input
                    type="file"
                    id="vault-file-input"
                    multiple
                    onChange={(e) => setFiles(Array.from(e.target.files || []))}
                    className="hidden"
                  />
                  <label
                    htmlFor="vault-file-input"
                    className="inline-flex items-center gap-2 px-5 py-2.5 bg-slate-900 hover:bg-slate-800 text-white rounded-xl text-xs font-bold cursor-pointer transition-all shadow-sm"
                  >
                    <Plus size={14} />
                    <span>Select Files</span>
                  </label>
                  <p className="text-[10px] text-slate-400">Supported: PDF, JPG, PNG (Max 15MB per file)</p>
                </div>

                {/* Staged files list */}
                {files.length > 0 && (
                  <div className="mt-6 pt-5 border-t border-slate-100 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-black text-slate-700 uppercase tracking-wider">
                        Files ready to upload ({files.length})
                      </span>
                      <button
                        onClick={handleUpload}
                        disabled={isUploading}
                        className="bg-red-600 hover:bg-red-700 text-white font-bold text-xs px-4 py-2 rounded-xl transition-all shadow-md disabled:opacity-50 flex items-center gap-1.5"
                      >
                        <Upload size={13} />
                        <span>{isUploading ? (uploadStatus || 'Uploading...') : 'Upload All to Vault'}</span>
                      </button>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {files.map((f, idx) => (
                        <div key={idx} className="p-3 bg-slate-50 rounded-xl border border-slate-200 flex items-center justify-between text-xs">
                          <span className="font-semibold text-slate-700 truncate max-w-[200px]">{f.name}</span>
                          <button
                            type="button"
                            onClick={() => setFiles(prev => prev.filter((_, i) => i !== idx))}
                            className="text-red-600 hover:text-red-700 font-bold text-[11px] uppercase tracking-wider ml-2"
                          >
                            Remove
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Uploaded files grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {(selectedOrder.clientDocuments || []).map((doc) => (
                  <div key={doc._id} className="bg-white p-5 rounded-2xl border border-slate-200/90 shadow-2xs flex items-center justify-between gap-4">
                    <div className="flex items-center gap-3.5 min-w-0">
                      <div className="w-11 h-11 bg-slate-100 text-slate-600 rounded-xl flex items-center justify-center shrink-0">
                        <FileText size={20} />
                      </div>
                      <div className="min-w-0">
                        <p className="font-bold text-sm text-slate-900 truncate">{doc.name}</p>
                        <p className="text-[10px] text-slate-400 font-medium">Uploaded on {new Date(doc.uploadedAt || Date.now()).toLocaleDateString()}</p>
                      </div>
                    </div>
                    <a
                      href={doc.url}
                      target="_blank"
                      rel="noreferrer"
                      className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs font-bold transition-colors shrink-0 flex items-center gap-1"
                    >
                      <span>View</span>
                      <ExternalLink size={12} />
                    </a>
                  </div>
                ))}
              </div>

              {!selectedOrder.clientDocuments?.length && (
                <EmptyDocumentsState text="You haven't uploaded any documents to this vault yet. Use the uploader above to securely submit proofs." />
              )}
            </div>
          )}

          {/* Tab 3: Requirements / KYC Checklist */}
          {activeTab === 'requirements' && (
            selectedOrder.serviceName?.toLowerCase().includes('income tax') || selectedOrder.packageName?.toLowerCase().includes('itr') ? (
              <ITRAssessmentCustomerView selectedOrder={selectedOrder} userInfo={userInfo} />
            ) : (
              <div className="bg-white rounded-3xl p-6 border border-slate-200/90 shadow-2xs">
                <RequirementsWorkspace selectedOrder={selectedOrder} userInfo={userInfo} refreshOrders={refreshOrders} />
              </div>
            )
          )}
        </div>
      ) : (
        <EmptyDocumentsState text="Please start a project to manage documents in your secure vault." />
      )}
    </div>
  );
};

const EmptyDocumentsState = ({ text }) => (
  <div className="bg-white border border-slate-200/90 rounded-3xl p-12 text-center text-slate-400 shadow-2xs space-y-3">
    <div className="w-16 h-16 rounded-2xl bg-slate-50 text-slate-300 flex items-center justify-center mx-auto">
      <FolderOpen size={32} />
    </div>
    <p className="text-xs font-semibold max-w-md mx-auto leading-relaxed text-slate-500">{text}</p>
  </div>
);

export default DocumentsView;
