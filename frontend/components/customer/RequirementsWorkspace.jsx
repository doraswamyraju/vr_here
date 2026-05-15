import React, { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import { CheckCircle2, Upload } from 'lucide-react';

const RequirementsWorkspace = ({ selectedOrder, userInfo, refreshOrders }) => {
  const [activeSubTab, setActiveSubTab] = useState('details');
  const [drafts, setDrafts] = useState({});
  const [uploadingId, setUploadingId] = useState('');

  const requirements = selectedOrder?.customerRequirements || [];
  
  const detailRequirements = useMemo(() => requirements.filter((item) => item.type === 'Detail' && !item.isAdditional), [requirements]);
  const documentRequirements = useMemo(() => requirements.filter((item) => item.type === 'Document' && !item.isAdditional), [requirements]);
  const additionalRequirements = useMemo(() => requirements.filter((item) => item.isAdditional), [requirements]);

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
      Authorization: `Bearer ${userInfo.token}`
    }
  };

  const saveDetail = async (requirementId) => {
    const draft = drafts[requirementId] || { value: '', notes: '', isClientCompleted: false };
    await axios.put(
      `/api/orders/${selectedOrder._id}/requirements/${requirementId}`,
      {
        clientValue: draft.value,
        clientNotes: draft.notes,
        isClientCompleted: draft.isClientCompleted
      },
      authHeaders
    );
    refreshOrders();
  };

  const uploadForRequirement = async (requirementId, file) => {
    if (!file) return;
    const formData = new FormData();
    formData.append('document', file);
    formData.append('requirementId', requirementId);
    setUploadingId(requirementId);
    try {
      await axios.post(`/api/orders/${selectedOrder._id}/documents`, formData, {
        headers: {
          Authorization: `Bearer ${userInfo.token}`,
          'Content-Type': 'multipart/form-data'
        }
      });
      refreshOrders();
    } finally {
      setUploadingId('');
    }
  };

  if (!selectedOrder) {
    return null;
  }

  // Helper renderers
  const renderDetailItem = (item) => (
    <div key={item._id} className="bg-white rounded-2xl border border-slate-200 p-4 shadow-sm">
      <p className="text-sm font-black text-slate-700">{item.title}</p>
      <p className="text-xs text-slate-500 mt-1">{item.description || 'Provide requested detail.'}</p>
      <input
        value={drafts[item._id]?.value || ''}
        onChange={(event) => setDrafts((prev) => ({ ...prev, [item._id]: { ...(prev[item._id] || {}), value: event.target.value } }))}
        placeholder={item.placeholder || 'Enter detail'}
        className="mt-3 w-full p-2.5 border border-slate-300 rounded-xl text-sm bg-slate-50 focus:bg-white"
      />
      <textarea
        value={drafts[item._id]?.notes || ''}
        onChange={(event) => setDrafts((prev) => ({ ...prev, [item._id]: { ...(prev[item._id] || {}), notes: event.target.value } }))}
        placeholder="Notes (optional)"
        rows={2}
        className="mt-2 w-full p-2.5 border border-slate-300 rounded-xl text-sm bg-slate-50 focus:bg-white"
      />
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
        <label className="text-xs font-semibold text-slate-600 inline-flex items-center gap-1.5 cursor-pointer">
          <input
            type="checkbox"
            checked={Boolean(drafts[item._id]?.isClientCompleted)}
            onChange={(event) => setDrafts((prev) => ({ ...prev, [item._id]: { ...(prev[item._id] || {}), isClientCompleted: event.target.checked } }))}
            className="w-4 h-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
          />
          Mark as completed
        </label>
        <button onClick={() => saveDetail(item._id)} className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 transition text-white text-xs font-bold shadow-sm">
          Save Entry
        </button>
      </div>
    </div>
  );

  const renderDocumentItem = (item) => (
    <div key={item._id} className="bg-white rounded-2xl border border-slate-200 p-4 shadow-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <p className="text-sm font-black text-slate-700">{item.title}</p>
          <p className="text-xs text-slate-500 mt-1">{item.description || 'Upload requested document.'}</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {item.uploadedDocumentUrl ? (
            <a href={item.uploadedDocumentUrl} target="_blank" rel="noreferrer" className="text-xs text-emerald-700 font-bold inline-flex items-center gap-1 bg-emerald-50 px-3 py-1.5 rounded-lg">
              <CheckCircle2 size={14} /> View Upload
            </a>
          ) : null}
          <div className="relative">
            <input
              type="file"
              onChange={(event) => uploadForRequirement(item._id, event.target.files?.[0])}
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
            />
            <button
              disabled={uploadingId === item._id}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-900 transition text-white text-xs font-bold inline-flex items-center gap-2 shadow-sm disabled:opacity-50"
            >
              <Upload size={14} />
              {uploadingId === item._id ? 'Uploading...' : (item.uploadedDocumentUrl ? 'Replace File' : 'Choose File')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="space-y-4">
      {/* Tab Navigation */}
      <div className="flex bg-slate-100/50 p-1.5 rounded-2xl gap-1 overflow-x-auto">
        <button
          onClick={() => setActiveSubTab('details')}
          className={`flex-1 py-3 rounded-xl text-xs font-black transition-all whitespace-nowrap ${activeSubTab === 'details' ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-500 hover:text-slate-700'}`}
        >
          Text Data ({detailRequirements.length})
        </button>
        <button
          onClick={() => setActiveSubTab('uploads')}
          className={`flex-1 py-3 rounded-xl text-xs font-black transition-all whitespace-nowrap ${activeSubTab === 'uploads' ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-500 hover:text-slate-700'}`}
        >
          Documents ({documentRequirements.length})
        </button>
        <button
          onClick={() => setActiveSubTab('additional')}
          className={`flex-1 py-3 rounded-xl text-xs font-black transition-all whitespace-nowrap flex items-center justify-center gap-1.5 ${activeSubTab === 'additional' ? 'bg-white text-rose-600 shadow-sm' : 'text-slate-500 hover:text-slate-700'}`}
        >
          {additionalRequirements.some(r => !r.isClientCompleted) && (
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
          )}
          Add. Queries ({additionalRequirements.length})
        </button>
      </div>

      {/* Tab Content */}
      <div className="bg-slate-50/50 rounded-3xl border border-slate-100 p-4">
        {activeSubTab === 'details' && (
          <div className="space-y-3">
            {detailRequirements.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-6">No details required.</p>
            ) : (
              detailRequirements.map(renderDetailItem)
            )}
          </div>
        )}

        {activeSubTab === 'uploads' && (
          <div className="space-y-3">
            {documentRequirements.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-6">No document uploads required.</p>
            ) : (
              documentRequirements.map(renderDocumentItem)
            )}
          </div>
        )}

        {activeSubTab === 'additional' && (
          <div className="space-y-3">
            {additionalRequirements.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-6">No additional queries from our team.</p>
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
