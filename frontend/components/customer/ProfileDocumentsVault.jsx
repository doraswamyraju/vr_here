import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import { 
  FileText, 
  Upload, 
  CheckCircle2, 
  Clock, 
  AlertCircle, 
  Trash2, 
  ExternalLink, 
  ShieldCheck, 
  RefreshCw,
  FolderOpen,
  Download,
  Package
} from 'lucide-react';

const REQUIRED_DOC_TYPES = [
  'Aadhaar Card',
  'PAN Card',
  'GST Certificate',
  'Cancelled Cheque',
  'Business Address Proof',
  'Incorporation Certificate'
];

const DOC_TYPE_KEYWORDS = {
  'Aadhaar Card': ['aadhaar', 'aadhar', 'adhar', 'uidai'],
  'PAN Card': ['pan'],
  'GST Certificate': ['gst'],
  'Cancelled Cheque': ['cheque', 'check', 'bank', 'passbook'],
  'Business Address Proof': ['address', 'proof', 'utility', 'bill', 'rent', 'electricity'],
  'Incorporation Certificate': ['incorporation', 'inc', 'registration', 'coi', 'cert']
};

const ProfileDocumentsVault = ({ token, orders = [] }) => {
  const [documents, setDocuments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploadingDocType, setUploadingDocType] = useState(null);
  const [error, setError] = useState(null);

  const config = useMemo(() => ({
    headers: { Authorization: `Bearer ${token}` }
  }), [token]);

  const fetchDocuments = async () => {
    try {
      setLoading(true);
      const res = await axios.get('/api/documents', config);
      setDocuments(res.data?.data || []);
      setError(null);
    } catch (err) {
      setError('Failed to load profile documents.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDocuments();
  }, [token]);

  // Comprehensive Document Extraction from all past orders
  const existingOrderFiles = useMemo(() => {
    const allFiles = [];
    (orders || []).forEach((order) => {
      const orderTag = order.serviceName || `Order #${order._id?.slice(-6).toUpperCase()}`;

      // 1. Client uploads
      (order.clientDocuments || []).forEach((doc) => {
        if (doc && (doc.url || doc.path)) {
          allFiles.push({
            id: doc._id || doc.url || Math.random(),
            fileName: doc.name || doc.filename || 'Client Uploaded File',
            url: doc.url || doc.path,
            source: orderTag,
            date: doc.uploadedAt || order.createdAt,
            type: 'Order Attachment'
          });
        }
      });

      // 2. Customer requirement uploads
      (order.customerRequirements || []).forEach((req) => {
        const fileUrl = req.uploadedDocumentUrl || req.documentUrl || (req.value && typeof req.value === 'string' && (req.value.startsWith('http') || req.value.startsWith('/uploads')) ? req.value : null);
        const fileName = req.uploadedDocumentName || req.title || req.name || 'Requirement Document';

        if (fileUrl) {
          allFiles.push({
            id: req._id || fileUrl,
            fileName: fileName,
            url: fileUrl,
            source: `${orderTag} (${req.title || req.name || 'Checklist'})`,
            date: req.lastSavedAt || order.createdAt,
            type: 'Requirement File'
          });
        }

        (req.documents || []).forEach((subDoc) => {
          if (subDoc && (subDoc.url || subDoc.path)) {
            allFiles.push({
              id: subDoc._id || subDoc.url,
              fileName: subDoc.name || 'Checklist Document',
              url: subDoc.url || subDoc.path,
              source: orderTag,
              date: order.createdAt,
              type: 'Requirement File'
            });
          }
        });
      });

      // 3. Admin provided documents
      (order.adminDocuments || []).forEach((doc) => {
        if (doc && (doc.url || doc.path)) {
          allFiles.push({
            id: doc._id || doc.url,
            fileName: doc.name || 'Delivered Certificate/Doc',
            url: doc.url || doc.path,
            source: `${orderTag} (Admin Delivered)`,
            date: doc.uploadedAt || order.createdAt,
            type: 'Delivered File'
          });
        }
      });

      // 4. Final Certificate
      if (order.finalCertificateUrl) {
        allFiles.push({
          id: `cert_${order._id}`,
          fileName: `${order.serviceName} - Final Certificate`,
          url: order.finalCertificateUrl,
          source: orderTag,
          date: order.updatedAt || order.createdAt,
          type: 'Final Certificate'
        });
      }
    });

    return allFiles;
  }, [orders]);

  const getFallbackFileForType = (docType) => {
    const keywords = DOC_TYPE_KEYWORDS[docType] || [docType.toLowerCase().split(' ')[0]];
    return existingOrderFiles.find((file) => {
      const nameLower = file.fileName.toLowerCase();
      const sourceLower = file.source.toLowerCase();
      return keywords.some((kw) => nameLower.includes(kw) || sourceLower.includes(kw));
    });
  };

  const handleFileUpload = async (docType, file) => {
    if (!file) return;
    try {
      setUploadingDocType(docType);
      const formData = new FormData();
      formData.append('document', file);
      formData.append('docType', docType);

      await axios.post('/api/documents/upload', formData, {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'multipart/form-data'
        }
      });

      alert(`${docType} uploaded successfully and saved to Google Drive!`);
      fetchDocuments();
    } catch (err) {
      alert(err.response?.data?.message || `Failed to upload ${docType}`);
    } finally {
      setUploadingDocType(null);
    }
  };

  const handleDelete = async (docId) => {
    if (!window.confirm('Are you sure you want to delete this document from your profile?')) return;
    try {
      await axios.delete(`/api/documents/${docId}`, config);
      fetchDocuments();
    } catch (err) {
      alert('Failed to delete document');
    }
  };

  if (loading) {
    return <div className="p-12 text-center text-slate-500 font-bold">Synchronizing Document Vault with Google Drive...</div>;
  }

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      
      {/* Top Hero Banner */}
      <div className="p-6 bg-gradient-to-r from-indigo-900 via-blue-900 to-indigo-950 text-white rounded-3xl shadow-xl flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <span className="px-3 py-1 bg-white/10 text-indigo-200 text-xs font-bold rounded-full uppercase tracking-wider">
            Upload Once, Use Anywhere
          </span>
          <h2 className="text-2xl font-black mt-2 flex items-center gap-2">
            <ShieldCheck size={26} className="text-emerald-400" />
            My Documents Vault
          </h2>
          <p className="text-xs text-slate-300 mt-1 max-w-xl">
            Store your basic verification documents securely in our Google Drive vault. They auto-populate across all your service orders.
          </p>
        </div>

        <button 
          onClick={fetchDocuments} 
          className="p-3 bg-white/10 hover:bg-white/20 text-white rounded-2xl transition-all"
          title="Refresh Vault"
        >
          <RefreshCw size={18} />
        </button>
      </div>

      {error && (
        <div className="p-4 bg-rose-50 text-rose-600 rounded-2xl flex items-center gap-2 font-bold text-sm">
          <AlertCircle size={18} /> {error}
        </div>
      )}

      {/* Grid of Standard Profile Document Types */}
      <div>
        <h3 className="font-black text-slate-800 text-lg mb-4 flex items-center gap-2">
          <ShieldCheck size={20} className="text-indigo-600" /> Standard Verification Documents
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {REQUIRED_DOC_TYPES.map((docType) => {
            const vaultDoc = documents.find((d) => d.docType === docType);
            const fallbackOrderFile = !vaultDoc ? getFallbackFileForType(docType) : null;
            const doc = vaultDoc || fallbackOrderFile;
            const isUploading = uploadingDocType === docType;
            const fileUrl = vaultDoc?.gdriveWebViewLink || doc?.url;

            return (
              <div 
                key={docType}
                className={`p-5 rounded-3xl border transition-all flex flex-col justify-between space-y-4 ${
                  doc 
                    ? 'bg-white border-slate-200/80 shadow-sm hover:shadow-md' 
                    : 'bg-slate-50/60 border-dashed border-slate-300 hover:border-indigo-400'
                }`}
              >
                <div>
                  <div className="flex justify-between items-start">
                    <div className="space-y-1">
                      <h4 className="font-black text-slate-800 text-base">{docType}</h4>
                      <p className="text-xs text-slate-400">
                        {vaultDoc ? vaultDoc.fileName : fallbackOrderFile ? `${fallbackOrderFile.fileName}` : 'Not uploaded yet'}
                      </p>
                    </div>

                    {vaultDoc ? (
                      <span className="px-2.5 py-1 bg-emerald-50 text-emerald-700 border border-emerald-200/80 rounded-full text-[10px] font-black uppercase flex items-center gap-1">
                        <CheckCircle2 size={10} /> Verified
                      </span>
                    ) : fallbackOrderFile ? (
                      <span className="px-2.5 py-1 bg-blue-50 text-blue-700 border border-blue-200/80 rounded-full text-[10px] font-bold uppercase flex items-center gap-1">
                        From Order
                      </span>
                    ) : (
                      <span className="px-2.5 py-1 bg-slate-200 text-slate-600 rounded-full text-[10px] font-bold uppercase">
                        Missing
                      </span>
                    )}
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-100 flex items-center justify-between">
                  {fileUrl ? (
                    <div className="flex items-center gap-2 w-full justify-between">
                      <a
                        href={fileUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="px-3 py-2 bg-indigo-50 text-indigo-700 hover:bg-indigo-600 hover:text-white rounded-xl text-xs font-bold transition-all flex items-center gap-1.5"
                      >
                        <ExternalLink size={12} /> View Document
                      </a>

                      <div className="flex gap-1">
                        <label className="p-2 bg-slate-100 hover:bg-slate-200 text-slate-600 rounded-xl cursor-pointer transition-all" title="Upload new version to Google Drive">
                          <Upload size={14} />
                          <input
                            type="file"
                            className="hidden"
                            onChange={(e) => e.target.files?.[0] && handleFileUpload(docType, e.target.files[0])}
                          />
                        </label>

                        {vaultDoc && (
                          <button
                            onClick={() => handleDelete(vaultDoc._id)}
                            className="p-2 bg-rose-50 text-rose-600 hover:bg-rose-600 hover:text-white rounded-xl transition-all"
                            title="Remove Document"
                          >
                            <Trash2 size={14} />
                          </button>
                        )}
                      </div>
                    </div>
                  ) : (
                    <label className="w-full py-2.5 bg-indigo-600 hover:bg-slate-900 text-white rounded-2xl text-xs font-black text-center cursor-pointer transition-all shadow-md shadow-indigo-100 flex items-center justify-center gap-2">
                      {isUploading ? (
                        'Uploading to Drive...'
                      ) : (
                        <>
                          <Upload size={14} /> Upload {docType}
                        </>
                      )}
                      <input
                        type="file"
                        disabled={isUploading}
                        className="hidden"
                        onChange={(e) => e.target.files?.[0] && handleFileUpload(docType, e.target.files[0])}
                      />
                    </label>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* SECTION: ALL EXISTING ORDER DOCUMENTS */}
      <div className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm space-y-4">
        <div className="flex justify-between items-center">
          <div>
            <h3 className="font-black text-slate-800 text-lg flex items-center gap-2">
              <FolderOpen size={20} className="text-indigo-600" />
              All Order & Service Documents ({existingOrderFiles.length})
            </h3>
            <p className="text-xs text-slate-400 font-medium mt-0.5">
              Documents submitted or delivered across your service orders.
            </p>
          </div>
        </div>

        <div className="space-y-3">
          {existingOrderFiles.map((file, idx) => (
            <div key={idx} className="p-4 bg-slate-50/70 rounded-2xl border border-slate-100 flex items-center justify-between hover:bg-slate-100/60 transition-all">
              <div className="flex items-center gap-3.5">
                <div className="w-10 h-10 bg-indigo-50 text-indigo-600 rounded-xl flex items-center justify-center shrink-0">
                  <FileText size={20} />
                </div>
                <div>
                  <h4 className="font-bold text-slate-800 text-sm">{file.fileName}</h4>
                  <p className="text-[11px] text-slate-400 font-medium">
                    {file.source} • <span className="text-indigo-600 font-bold">{file.type}</span>
                  </p>
                </div>
              </div>

              <a
                href={file.url}
                target="_blank"
                rel="noopener noreferrer"
                className="px-4 py-2 bg-indigo-600 hover:bg-slate-900 text-white rounded-xl text-xs font-bold transition-all flex items-center gap-1.5 shadow-sm"
              >
                <ExternalLink size={14} /> View File
              </a>
            </div>
          ))}

          {existingOrderFiles.length === 0 && (
            <div className="p-10 text-center text-slate-400 bg-slate-50/50 rounded-2xl border border-dashed border-slate-200">
              <FolderOpen size={36} className="mx-auto mb-2 opacity-30 text-slate-400" />
              <p className="text-xs font-bold">No order documents found in current session.</p>
            </div>
          )}
        </div>
      </div>

    </div>
  );
};

export default ProfileDocumentsVault;
