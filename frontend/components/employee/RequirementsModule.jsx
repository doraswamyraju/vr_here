import React, { useState, useMemo } from 'react';
import { CheckCircle2 } from 'lucide-react';

const RequirementsModule = ({ selectedOrder, onUpdateRequirementStatus, onRaiseRequirement, isClockedIn }) => {
  const [activeSubTab, setActiveSubTab] = useState('details');
  const [quickRequirementText, setQuickRequirementText] = useState('');
  const [quickRequirementType, setQuickRequirementType] = useState('Detail');

  if (!selectedOrder) {
    return <div className="bg-white rounded-2xl border border-slate-200 p-6 text-sm text-slate-500">Select an order to track customer requirements.</div>;
  }

  const requirements = selectedOrder.customerRequirements || [];

  const detailRequirements = useMemo(() => requirements.filter(r => r.type === 'Detail' && !r.isAdditional), [requirements]);
  const uploadRequirements = useMemo(() => requirements.filter(r => r.type === 'Document' && !r.isAdditional), [requirements]);
  const additionalRequirements = useMemo(() => requirements.filter(r => r.isAdditional), [requirements]);

  const handleRaise = async () => {
    if (!isClockedIn) {
      alert('Please clock in before starting work.');
      return;
    }
    if (!quickRequirementText.trim() || !onRaiseRequirement) return;
    await onRaiseRequirement(selectedOrder._id, {
      title: quickRequirementText,
      description: '',
      type: quickRequirementType
    });
    setQuickRequirementText('');
    setQuickRequirementType('Detail');
  };

  const renderRequirementList = (list) => {
    if (list.length === 0) return <p className="text-xs text-slate-500 p-4 border rounded-xl border-dashed">No requirements in this section.</p>;
    
    return (
      <div className="space-y-2 mt-3">
        {list.map((item) => (
          <div key={item._id} className="rounded-lg border border-slate-200 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <p className="font-medium text-slate-800">{item.title}</p>
                <p className="text-xs text-slate-500">
                  {item.type} {item.description ? `- ${item.description}` : ''}
                </p>
                {(item.clientValue || item.value) && <p className="text-xs text-indigo-700 mt-1 font-semibold">Client Value: {item.clientValue || item.value}</p>}
                {item.clientNotes && <p className="text-xs text-slate-500 mt-1">Client Notes: {item.clientNotes}</p>}
                {item.uploadedDocumentUrl && (
                  <a className="text-xs text-indigo-700 font-semibold underline mt-1 inline-flex items-center gap-1" href={item.uploadedDocumentUrl} target="_blank" rel="noreferrer">
                    <CheckCircle2 size={12} /> View Upload
                  </a>
                )}
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] px-2 py-1 rounded-full bg-slate-100 text-slate-600 font-bold">{item.status || 'Pending'}</span>
                {onUpdateRequirementStatus && (
                  <select
                    value={item.status || 'Pending'}
                    onChange={(event) => {
                      if (!isClockedIn) {
                        alert('Please clock in before starting work.');
                        return;
                      }
                      onUpdateRequirementStatus(selectedOrder._id, item._id, event.target.value);
                    }}
                    className="p-1 border rounded"
                  >
                    <option value="Pending">Pending</option>
                    <option value="Received">Received</option>
                    <option value="Verified">Verified</option>
                    <option value="Rejected">Rejected</option>
                  </select>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="bg-white rounded-2xl border border-slate-200 p-6">
      <h3 className="font-bold text-slate-800 mb-4">Customer Requirements</h3>

      <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 pb-2">
        <button
          onClick={() => setActiveSubTab('details')}
          className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors ${activeSubTab === 'details' ? 'bg-indigo-50 text-indigo-700' : 'text-slate-500 hover:bg-slate-50'}`}
        >
          Details ({detailRequirements.length})
        </button>
        <button
          onClick={() => setActiveSubTab('uploads')}
          className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors ${activeSubTab === 'uploads' ? 'bg-indigo-50 text-indigo-700' : 'text-slate-500 hover:bg-slate-50'}`}
        >
          Customer Uploads ({uploadRequirements.length})
        </button>
        <button
          onClick={() => setActiveSubTab('additional')}
          className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors ${activeSubTab === 'additional' ? 'bg-indigo-50 text-indigo-700' : 'text-slate-500 hover:bg-slate-50'}`}
        >
          Additional Requirements ({additionalRequirements.length})
        </button>
      </div>

      <div className="pt-2">
        {activeSubTab === 'details' && renderRequirementList(detailRequirements)}
        {activeSubTab === 'uploads' && renderRequirementList(uploadRequirements)}
        
        {activeSubTab === 'additional' && (
          <div className="space-y-4 mt-3">
            {onRaiseRequirement && (
              <div className="rounded-xl border border-rose-200 p-3 bg-rose-50 shadow-sm border-dashed">
                <p className="text-xs font-black text-rose-800">Raise Additional Query / Requirement</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  <input
                    value={quickRequirementText}
                    onChange={(event) => setQuickRequirementText(event.target.value)}
                    className="flex-1 min-w-[200px] p-1.5 border border-rose-300 rounded text-xs bg-white"
                    placeholder="Example: Upload clearer GST certificate copy"
                  />
                  <select
                    value={quickRequirementType}
                    onChange={(event) => setQuickRequirementType(event.target.value)}
                    className="p-1.5 border border-rose-300 rounded text-xs bg-white text-rose-800 font-medium"
                  >
                    <option value="Detail">Require Text Input</option>
                    <option value="Document">Require File Upload</option>
                  </select>
                  <button onClick={handleRaise} className="px-3 py-1.5 rounded bg-rose-600 text-white text-xs font-bold shadow-sm hover:bg-rose-700 transition">
                    Raise Query
                  </button>
                </div>
              </div>
            )}
            {renderRequirementList(additionalRequirements)}
          </div>
        )}
      </div>

    </div>
  );
};

export default RequirementsModule;
