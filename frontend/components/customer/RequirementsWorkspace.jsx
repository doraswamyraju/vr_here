import React, { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import { CheckCircle2, Upload } from 'lucide-react';

const RequirementsWorkspace = ({ selectedOrder, userInfo, refreshOrders }) => {
  const [drafts, setDrafts] = useState({});
  const [uploadingId, setUploadingId] = useState('');

  const requirements = selectedOrder?.customerRequirements || [];
  const detailRequirements = useMemo(() => requirements.filter((item) => item.type === 'Detail'), [requirements]);
  const documentRequirements = useMemo(() => requirements.filter((item) => item.type === 'Document'), [requirements]);

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

  return (
    <div className="space-y-4">
      <div className="bg-white rounded-3xl border border-slate-100 shadow-sm p-5">
        <h4 className="font-black text-slate-800 text-sm">Client Details (Save Partially)</h4>
        <p className="text-[11px] text-slate-500 mt-1">You can save each field and complete it later.</p>

        <div className="space-y-3 mt-4">
          {detailRequirements.map((item) => (
            <div key={item._id} className="rounded-2xl border border-slate-200 p-3">
              <p className="text-xs font-black text-slate-700">{item.title}</p>
              <p className="text-[11px] text-slate-500 mt-0.5">{item.description || 'Provide requested detail.'}</p>
              <input
                value={drafts[item._id]?.value || ''}
                onChange={(event) => setDrafts((prev) => ({ ...prev, [item._id]: { ...(prev[item._id] || {}), value: event.target.value } }))}
                placeholder={item.placeholder || 'Enter detail'}
                className="mt-2 w-full p-2.5 border border-slate-300 rounded-xl text-sm"
              />
              <textarea
                value={drafts[item._id]?.notes || ''}
                onChange={(event) => setDrafts((prev) => ({ ...prev, [item._id]: { ...(prev[item._id] || {}), notes: event.target.value } }))}
                placeholder="Notes (optional)"
                rows={2}
                className="mt-2 w-full p-2.5 border border-slate-300 rounded-xl text-sm"
              />
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <label className="text-xs text-slate-600 inline-flex items-center gap-1">
                  <input
                    type="checkbox"
                    checked={Boolean(drafts[item._id]?.isClientCompleted)}
                    onChange={(event) => setDrafts((prev) => ({ ...prev, [item._id]: { ...(prev[item._id] || {}), isClientCompleted: event.target.checked } }))}
                  />
                  Mark as completed
                </label>
                <button onClick={() => saveDetail(item._id)} className="px-3 py-1.5 rounded-lg bg-indigo-600 text-white text-xs font-bold">
                  Save
                </button>
              </div>
            </div>
          ))}
          {!detailRequirements.length && (
            <p className="text-xs text-slate-500">No detail fields imported yet.</p>
          )}
        </div>
      </div>

      <div className="bg-white rounded-3xl border border-slate-100 shadow-sm p-5">
        <h4 className="font-black text-slate-800 text-sm">Required Documents</h4>
        <p className="text-[11px] text-slate-500 mt-1">Upload documents against each item.</p>
        <div className="space-y-3 mt-4">
          {documentRequirements.map((item) => (
            <div key={item._id} className="rounded-2xl border border-slate-200 p-3">
              <p className="text-xs font-black text-slate-700">{item.title}</p>
              <p className="text-[11px] text-slate-500 mt-0.5">{item.description || 'Upload requested document.'}</p>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <input
                  type="file"
                  onChange={(event) => uploadForRequirement(item._id, event.target.files?.[0])}
                  className="text-xs"
                />
                {uploadingId === item._id ? (
                  <span className="text-xs text-indigo-600 font-bold inline-flex items-center gap-1"><Upload size={12} /> Uploading...</span>
                ) : item.uploadedDocumentUrl ? (
                  <a href={item.uploadedDocumentUrl} target="_blank" rel="noreferrer" className="text-xs text-emerald-700 font-bold inline-flex items-center gap-1">
                    <CheckCircle2 size={12} /> Uploaded
                  </a>
                ) : null}
              </div>
            </div>
          ))}
          {!documentRequirements.length && (
            <p className="text-xs text-slate-500">No document requirements imported yet.</p>
          )}
        </div>
      </div>
    </div>
  );
};

export default RequirementsWorkspace;
