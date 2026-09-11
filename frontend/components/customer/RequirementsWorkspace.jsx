import React, { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import { 
  CheckCircle2, 
  Upload, 
  FileText, 
  Clock, 
  AlertCircle, 
  HelpCircle, 
  Save, 
  Eye, 
  Check, 
  Sparkles,
  Layers,
  FileCheck
} from 'lucide-react';

const RequirementsWorkspace = ({ selectedOrder, userInfo, refreshOrders }) => {
  const requirements = selectedOrder?.customerRequirements || [];
  
  const detailRequirements = useMemo(() => requirements.filter((item) => item.type === 'Detail' && !item.isAdditional), [requirements]);
  const documentRequirements = useMemo(() => requirements.filter((item) => item.type === 'Document' && !item.isAdditional), [requirements]);
  const additionalRequirements = useMemo(() => requirements.filter((item) => item.isAdditional), [requirements]);

  // Set default active tab based on where there are items
  const [activeSubTab, setActiveSubTab] = useState(() => {
    if (documentRequirements.length > 0) return 'uploads';
    if (detailRequirements.length > 0) return 'details';
    if (additionalRequirements.length > 0) return 'additional';
    return 'uploads';
  });

  const [drafts, setDrafts] = useState({});
  const [uploadingId, setUploadingId] = useState('');
  const [savingId, setSavingId] = useState('');

  useEffect(() => {
    const next = {};
    requirements.forEach((item) => {
      next[item._id] = {
        value: item.clientValue || item.value || '',
        notes: item.clientNotes || '',
        isClientCompleted: Boolean(item.isClientCompleted)
      };
    });
    setDrafts(next);
  }, [selectedOrder?._id]);

  const authHeaders = {
    headers: {
      Authorization: `Bearer ${userInfo?.token}`
    }
  };

  const saveDetail = async (requirementId) => {
    const draft = drafts[requirementId] || { value: '', notes: '', isClientCompleted: false };
    setSavingId(requirementId);
    try {
      await axios.put(
        `/api/orders/${selectedOrder._id}/requirements/${requirementId}`,
        {
          clientValue: draft.value,
          clientNotes: draft.notes,
          isClientCompleted: draft.isClientCompleted
        },
        authHeaders
      );
      if (refreshOrders) refreshOrders();
    } catch (err) {
      alert(err.response?.data?.message || 'Error saving detail');
    } finally {
      setSavingId('');
    }
  };

  const uploadForRequirement = async (requirementId, filesList) => {
    if (!filesList || filesList.length === 0) return;
    setUploadingId(requirementId);
    try {
      for (let i = 0; i < filesList.length; i++) {
        const formData = new FormData();
        formData.append('document', filesList[i]);
        formData.append('requirementId', requirementId);
        
        await axios.post(`/api/orders/${selectedOrder._id}/documents`, formData, {
          headers: {
            Authorization: `Bearer ${userInfo?.token}`,
            'Content-Type': 'multipart/form-data'
          }
        });
      }
      if (refreshOrders) refreshOrders();
    } catch (error) {
      console.error('Document Upload Error:', error);
      alert(error?.response?.data?.message || 'Error uploading file(s). Check server log.');
    } finally {
      setUploadingId('');
    }
  };

  if (!selectedOrder) {
    return null;
  }

  // Completion calculation
  const completedCount = requirements.filter(r => {
    if (r.type === 'Document') {
      return r.isClientCompleted || (r.documents && r.documents.length > 0) || Boolean(r.uploadedDocumentUrl) || r.status === 'Received' || r.status === 'Verified';
    }
    return r.isClientCompleted || Boolean(r.clientValue) || Boolean(r.value) || r.status === 'Received' || r.status === 'Verified';
  }).length;

  const totalCount = requirements.length;
  const progressPercent = totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 100;
  const isAllCompleted = totalCount > 0 && completedCount === totalCount;

  // Helper renderers
  const renderDetailItem = (item) => {
    const isSavedAndDone = item.isClientCompleted || Boolean(item.clientValue || item.value);
    const isSaving = savingId === item._id;

    return (
      <div 
        key={item._id} 
        className={`rounded-2xl p-5 border transition-all ${
          isSavedAndDone 
            ? 'bg-white border-slate-200 shadow-2xs hover:border-slate-300' 
            : 'bg-amber-50/20 border-amber-200/80 shadow-2xs hover:border-amber-300'
        }`}
      >
        <div className="flex items-start justify-between gap-3">
          <div>
            <h5 className="text-sm font-black text-slate-900 flex items-center gap-2">
              <span>{item.title}</span>
              {item.required !== false && (
                <span className="text-[10px] font-bold text-red-600 bg-red-50 px-2 py-0.5 rounded-full border border-red-200/60">
                  Required
                </span>
              )}
            </h5>
            <p className="text-xs text-slate-500 font-medium mt-0.5">{item.description || 'Provide requested information for this filing.'}</p>
          </div>

          {isSavedAndDone ? (
            <span className="px-2.5 py-1 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-full text-[10px] font-black uppercase flex items-center gap-1 shrink-0">
              <CheckCircle2 size={11} /> Completed
            </span>
          ) : (
            <span className="px-2.5 py-1 bg-amber-50 text-amber-700 border border-amber-200 rounded-full text-[10px] font-bold uppercase shrink-0">
              Pending Entry
            </span>
          )}
        </div>

        <div className="mt-4 space-y-2.5">
          <input
            value={drafts[item._id]?.value || ''}
            onChange={(event) => setDrafts((prev) => ({ ...prev, [item._id]: { ...(prev[item._id] || {}), value: event.target.value } }))}
            placeholder={item.placeholder || 'Enter value here...'}
            className="w-full p-3 border border-slate-200 rounded-xl text-xs font-medium bg-slate-50/50 focus:bg-white focus:outline-none focus:ring-2 focus:ring-red-500/20 focus:border-red-500 transition-all text-slate-800"
          />
          <textarea
            value={drafts[item._id]?.notes || ''}
            onChange={(event) => setDrafts((prev) => ({ ...prev, [item._id]: { ...(prev[item._id] || {}), notes: event.target.value } }))}
            placeholder="Additional notes / comments for compliance officer (optional)"
            rows={2}
            className="w-full p-3 border border-slate-200 rounded-xl text-xs font-medium bg-slate-50/50 focus:bg-white focus:outline-none focus:ring-2 focus:ring-red-500/20 focus:border-red-500 transition-all text-slate-800"
          />
        </div>

        <div className="mt-4 pt-3 border-t border-slate-100 flex flex-wrap items-center justify-between gap-3">
          <label className="text-xs font-semibold text-slate-700 inline-flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={Boolean(drafts[item._id]?.isClientCompleted)}
              onChange={(event) => setDrafts((prev) => ({ ...prev, [item._id]: { ...(prev[item._id] || {}), isClientCompleted: event.target.checked } }))}
              className="w-4 h-4 rounded border-slate-300 text-red-600 focus:ring-red-500"
            />
            <span>Mark as complete</span>
          </label>

          <button 
            onClick={() => saveDetail(item._id)} 
            disabled={isSaving}
            className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-red-600 active:scale-95 transition-all text-white text-xs font-bold shadow-sm flex items-center gap-1.5 disabled:opacity-50"
          >
            <Save size={13} />
            <span>{isSaving ? 'Saving...' : 'Save Entry'}</span>
          </button>
        </div>
      </div>
    );
  };

  const renderDocumentItem = (item) => {
    const hasUploads = (item.documents && item.documents.length > 0) || Boolean(item.uploadedDocumentUrl) || item.status === 'Received' || item.status === 'Verified';
    const isUploading = uploadingId === item._id;

    return (
      <div 
        key={item._id} 
        className={`rounded-2xl p-5 border transition-all ${
          hasUploads 
            ? 'bg-white border-slate-200 shadow-2xs hover:border-slate-300' 
            : 'bg-amber-50/20 border-amber-200/80 shadow-2xs hover:border-amber-300'
        }`}
      >
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
          <div className="space-y-1">
            <h5 className="text-sm font-black text-slate-900 flex items-center gap-2">
              <span>{item.title}</span>
              {item.required !== false && (
                <span className="text-[10px] font-bold text-red-600 bg-red-50 px-2 py-0.5 rounded-full border border-red-200/60">
                  Required
                </span>
              )}
            </h5>
            <p className="text-xs text-slate-500 font-medium">{item.description || 'Upload the requested document or proof for filing.'}</p>
          </div>

          {hasUploads ? (
            <span className="self-start sm:self-auto px-2.5 py-1 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-full text-[10px] font-black uppercase flex items-center gap-1 shrink-0">
              <CheckCircle2 size={11} /> Uploaded & Ready
            </span>
          ) : (
            <span className="self-start sm:self-auto px-2.5 py-1 bg-rose-50 text-rose-700 border border-rose-200 rounded-full text-[10px] font-bold uppercase shrink-0">
              Upload Needed
            </span>
          )}
        </div>

        {/* Existing uploaded documents display */}
        {hasUploads && (
          <div className="mt-4 p-3.5 bg-slate-50/80 rounded-xl border border-slate-100 flex flex-wrap items-center gap-2">
            <span className="text-[11px] font-bold text-slate-500 uppercase mr-1">Uploaded:</span>
            {item.documents && item.documents.length > 0 ? (
              item.documents.map((doc, idx) => (
                <a 
                  key={idx} 
                  href={doc.url} 
                  target="_blank" 
                  rel="noreferrer" 
                  className="text-xs text-slate-800 font-bold inline-flex items-center gap-1.5 bg-white hover:bg-slate-100 border border-slate-200 px-3 py-1.5 rounded-lg transition-all shadow-2xs"
                >
                  <FileText size={13} className="text-emerald-600" /> 
                  <span className="truncate max-w-[140px]">{doc.name || `File ${idx + 1}`}</span>
                </a>
              ))
            ) : item.uploadedDocumentUrl ? (
              <a 
                href={item.uploadedDocumentUrl} 
                target="_blank" 
                rel="noreferrer" 
                className="text-xs text-slate-800 font-bold inline-flex items-center gap-1.5 bg-white hover:bg-slate-100 border border-slate-200 px-3 py-1.5 rounded-lg transition-all shadow-2xs"
              >
                <FileText size={13} className="text-emerald-600" /> 
                <span>View Uploaded File</span>
              </a>
            ) : null}
          </div>
        )}

        {/* Upload Action */}
        <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between gap-3">
          <p className="text-[11px] text-slate-400 font-medium">Supports PDF, JPG, PNG (Max 25MB)</p>
          
          <div className="relative">
            <input
              type="file"
              multiple
              disabled={isUploading}
              onChange={(event) => uploadForRequirement(item._id, event.target.files)}
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer disabled:pointer-events-none"
            />
            <button
              disabled={isUploading}
              className={`px-4 py-2 rounded-xl text-xs font-bold inline-flex items-center gap-2 shadow-sm transition-all ${
                hasUploads 
                  ? 'bg-slate-100 hover:bg-slate-200 text-slate-800' 
                  : 'bg-red-600 hover:bg-red-700 text-white'
              } disabled:opacity-50`}
            >
              <Upload size={13} />
              <span>{isUploading ? 'Uploading...' : (hasUploads ? 'Replace / Add Files' : 'Upload Document')}</span>
            </button>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      
      {/* Workspace Checklist Header & Progress */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-100">
        <div>
          <h4 className="text-base font-black text-slate-900 flex items-center gap-2">
            <FileCheck size={18} className="text-red-600" />
            Project KYC & Requirements Checklist
          </h4>
          <p className="text-xs text-slate-500 font-medium mt-0.5">
            Submit required director/company details so our compliance experts can prepare portal filings.
          </p>
        </div>

        {totalCount > 0 && (
          <div className="flex items-center gap-3 bg-slate-50 px-4 py-2.5 rounded-2xl border border-slate-100 shrink-0">
            <div className="text-right">
              <p className="text-[10px] font-black uppercase tracking-wider text-slate-400">Checklist Progress</p>
              <p className="text-xs font-black text-slate-900">{completedCount} of {totalCount} Completed ({progressPercent}%)</p>
            </div>
            <div className="w-10 h-10 rounded-xl bg-white border border-slate-200 flex items-center justify-center font-black text-xs text-red-600">
              {progressPercent}%
            </div>
          </div>
        )}
      </div>

      {/* Celebratory Banner when 100% completed */}
      {isAllCompleted && (
        <div className="bg-gradient-to-r from-emerald-50 via-teal-50 to-emerald-50 border border-emerald-200 text-emerald-900 rounded-2xl p-4.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-2xs animate-in fade-in">
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-emerald-500 text-white flex items-center justify-center font-bold shadow-md shadow-emerald-500/20 shrink-0">
              <CheckCircle2 size={22} />
            </div>
            <div>
              <p className="text-xs font-black text-emerald-950">All Checklist Items & KYC Submitted 🎉</p>
              <p className="text-[11px] text-emerald-700 font-medium">Your dedicated specialist is actively preparing the government filing dossier.</p>
            </div>
          </div>
          <span className="self-start sm:self-auto text-[10px] font-black uppercase px-3 py-1.5 bg-emerald-200/80 text-emerald-950 rounded-xl border border-emerald-300">
            Under Review / Processing
          </span>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="flex bg-slate-100 p-1.5 rounded-2xl gap-1.5 overflow-x-auto">
        <button
          onClick={() => setActiveSubTab('uploads')}
          className={`flex-1 py-2.5 px-3 rounded-xl text-xs font-black transition-all whitespace-nowrap flex items-center justify-center gap-1.5 ${
            activeSubTab === 'uploads' 
              ? 'bg-white text-slate-900 shadow-sm border border-slate-200/80' 
              : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          <FileText size={14} className={activeSubTab === 'uploads' ? 'text-red-600' : 'text-slate-400'} />
          <span>Documents ({documentRequirements.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('details')}
          className={`flex-1 py-2.5 px-3 rounded-xl text-xs font-black transition-all whitespace-nowrap flex items-center justify-center gap-1.5 ${
            activeSubTab === 'details' 
              ? 'bg-white text-slate-900 shadow-sm border border-slate-200/80' 
              : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          <Sparkles size={14} className={activeSubTab === 'details' ? 'text-red-600' : 'text-slate-400'} />
          <span>Information & Details ({detailRequirements.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('additional')}
          className={`flex-1 py-2.5 px-3 rounded-xl text-xs font-black transition-all whitespace-nowrap flex items-center justify-center gap-1.5 ${
            activeSubTab === 'additional' 
              ? 'bg-white text-rose-600 shadow-sm border border-slate-200/80' 
              : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          {additionalRequirements.some(r => !r.isClientCompleted) && (
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
          )}
          <span>Additional Queries ({additionalRequirements.length})</span>
        </button>
      </div>

      {/* Tab Content */}
      <div className="space-y-4">
        {activeSubTab === 'uploads' && (
          <div className="space-y-4">
            {documentRequirements.length === 0 ? (
              <div className="p-8 text-center text-slate-400 bg-slate-50/60 rounded-2xl border border-dashed border-slate-200 space-y-2">
                <FileCheck size={32} className="mx-auto text-slate-300" />
                <p className="text-xs font-bold text-slate-700">No specific document uploads required for this stage</p>
                <p className="text-[11px] text-slate-400">Standard documents will be utilized from your Master KYC vault automatically.</p>
              </div>
            ) : (
              documentRequirements.map(renderDocumentItem)
            )}
          </div>
        )}

        {activeSubTab === 'details' && (
          <div className="space-y-4">
            {detailRequirements.length === 0 ? (
              <div className="p-8 text-center text-slate-400 bg-slate-50/60 rounded-2xl border border-dashed border-slate-200 space-y-2">
                <CheckCircle2 size={32} className="mx-auto text-emerald-400" />
                <p className="text-xs font-bold text-slate-700">No text information required</p>
                <p className="text-[11px] text-slate-400">All preliminary details have been recorded.</p>
              </div>
            ) : (
              detailRequirements.map(renderDetailItem)
            )}
          </div>
        )}

        {activeSubTab === 'additional' && (
          <div className="space-y-4">
            {additionalRequirements.length === 0 ? (
              <div className="p-8 text-center text-slate-400 bg-slate-50/60 rounded-2xl border border-dashed border-slate-200 space-y-2">
                <HelpCircle size={32} className="mx-auto text-slate-300" />
                <p className="text-xs font-bold text-slate-700">No pending queries from compliance officer</p>
                <p className="text-[11px] text-slate-400">If our team needs any clarifying information or re-submission, it will appear here.</p>
              </div>
            ) : (
              additionalRequirements.map(item => item.type === 'Document' ? renderDocumentItem(item) : renderDetailItem(item))
            )}
          </div>
        )}
      </div>

    </div>
  );
};

export default RequirementsWorkspace;
