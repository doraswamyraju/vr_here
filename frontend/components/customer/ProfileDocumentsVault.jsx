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
  Plus
} from 'lucide-react';

const REQUIRED_DOC_TYPES = [
  'Aadhaar Card',
  'PAN Card',
  'GST Certificate',
  'Cancelled Cheque',
  'Business Address Proof',
  'Incorporation Certificate'
];

const ProfileDocumentsVault = ({ token }) => {
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
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Top Banner */}
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
            Store your basic verification documents securely in our Google Drive vault. They will auto-populate during order placement so you never have to re-upload them.
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
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {REQUIRED_DOC_TYPES.map((docType) => {
          const doc = documents.find((d) => d.docType === docType);
          const isUploading = uploadingDocType === docType;

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
                    <h3 className="font-black text-slate-800 text-base">{docType}</h3>
                    <p className="text-xs text-slate-400">
                      {doc ? doc.fileName : 'Not uploaded yet'}
                    </p>
                  </div>

                  {doc ? (
                    <span className="px-2.5 py-1 bg-emerald-50 text-emerald-700 border border-emerald-200/80 rounded-full text-[10px] font-black uppercase flex items-center gap-1">
                      <CheckCircle2 size={10} /> Verified
                    </span>
                  ) : (
                    <span className="px-2.5 py-1 bg-slate-200 text-slate-600 rounded-full text-[10px] font-bold uppercase">
                      Missing
                    </span>
                  )}
                </div>
              </div>

              <div className="pt-2 border-t border-slate-100 flex items-center justify-between">
                {doc ? (
                  <div className="flex items-center gap-2 w-full justify-between">
                    <a
                      href={doc.gdriveWebViewLink}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-2 bg-indigo-50 text-indigo-700 hover:bg-indigo-600 hover:text-white rounded-xl text-xs font-bold transition-all flex items-center gap-1.5"
                    >
                      <ExternalLink size={12} /> View in Google Drive
                    </a>

                    <div className="flex gap-1">
                      <label className="p-2 bg-slate-100 hover:bg-slate-200 text-slate-600 rounded-xl cursor-pointer transition-all" title="Replace file">
                        <Upload size={14} />
                        <input
                          type="file"
                          className="hidden"
                          onChange={(e) => e.target.files?.[0] && handleFileUpload(docType, e.target.files[0])}
                        />
                      </label>

                      <button
                        onClick={() => handleDelete(doc._id)}
                        className="p-2 bg-rose-50 text-rose-600 hover:bg-rose-600 hover:text-white rounded-xl transition-all"
                        title="Remove Document"
                      >
                        <Trash2 size={14} />
                      </button>
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
  );
};

export default ProfileDocumentsVault;
