import React, { useState, useMemo } from 'react';
import { Upload, Plus, Trash2, FileText, Fingerprint, Send, CheckCircle2 } from 'lucide-react';
import StatusBadge from './StatusBadge';
import { REQUIREMENT_STATUSES } from './constants';

const OrderRequirementsTab = ({
  selectedOrder,
  onImportRequirementsWorkbook,
  onRaiseRequirement,
  onUpdateRequirementStatus
}) => {
  const [activeSubTab, setActiveSubTab] = useState('details');
  const [requirementFile, setRequirementFile] = useState(null);
  const [replaceExisting, setReplaceExisting] = useState(true);
  const [isImporting, setIsImporting] = useState(false);
  const [showManualForm, setShowManualForm] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newType, setNewType] = useState('Document');
  const [manualLoading, setManualLoading] = useState(false);
  const [quickRequirementText, setQuickRequirementText] = useState('');
  const [quickRequirementType, setQuickRequirementType] = useState('Detail');

  const requirements = selectedOrder?.customerRequirements || [];

  const detailRequirements = useMemo(() => requirements.filter(r => r.type === 'Detail' && !r.isAdditional), [requirements]);
  const uploadRequirements = useMemo(() => requirements.filter(r => r.type === 'Document' && !r.isAdditional), [requirements]);
  const additionalRequirements = useMemo(() => requirements.filter(r => r.isAdditional), [requirements]);

  const handleImport = async () => {
    if (!requirementFile) return;
    setIsImporting(true);
    try {
      await onImportRequirementsWorkbook(requirementFile, replaceExisting);
      setRequirementFile(null);
    } catch (error) {
      alert(error?.response?.data?.message || 'Unable to import requirements from this workbook.');
    } finally {
      setIsImporting(false);
    }
  };

  const handleRaise = async () => {
    if (!quickRequirementText.trim()) return;
    try {
      await onRaiseRequirement({
        title: quickRequirementText,
        type: quickRequirementType,
        isAdditional: true
      });
      setQuickRequirementText('');
      setQuickRequirementType('Detail');
    } catch (error) {
      alert(error?.response?.data?.message || 'Unable to raise requirement.');
    }
  };

  const renderRequirementList = (list) => {
    if (list.length === 0) return <p className="text-xs text-slate-500 p-4 border rounded-xl border-dashed">No requirements in this section.</p>;
    
    return (
      <div className="space-y-2">
        {list.map((item) => (
          <div key={item._id} className="rounded-lg border border-slate-200 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <p className="font-medium text-slate-800">{item.title}</p>
                <p className="text-xs text-slate-500">
                  {item.type} {item.description ? `- ${item.description}` : ''}
                  {item.sheetName ? ` | Sheet: ${item.sheetName}` : ''}
                </p>
                {item.clientValue && <p className="text-xs text-indigo-700 mt-1 font-semibold">Client Value: {item.clientValue}</p>}
                {item.uploadedDocumentUrl && (
                  <a className="text-xs text-indigo-700 font-semibold underline mt-1 inline-flex items-center gap-1" href={item.uploadedDocumentUrl} target="_blank" rel="noreferrer">
                    <CheckCircle2 size={12} /> View Upload
                  </a>
                )}
              </div>
              <div className="flex items-center gap-2">
                <StatusBadge status={item.status} />
                <select
                  value={item.status || 'Pending'}
                  onChange={(event) => onUpdateRequirementStatus(item._id, event.target.value)}
                  className="p-2 border rounded-lg border-slate-300 bg-white text-xs"
                >
                  {REQUIREMENT_STATUSES.map((status) => (
                    <option key={status} value={status}>{status}</option>
                  ))}
                </select>
              </div>
            </div>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-slate-200 p-4 bg-slate-50">
        <p className="font-semibold text-slate-700 mb-2">Import Client Details + Document Requirements (Excel)</p>
        <p className="text-xs text-slate-500 mb-3">Upload workbook with 2 sheets: details and documents.</p>
        <div className="flex flex-wrap items-center gap-3">
          <input type="file" accept=".xlsx,.xls" onChange={(event) => setRequirementFile(event.target.files?.[0] || null)} className="text-sm" />
          <label className="text-xs text-slate-600 inline-flex items-center gap-1">
            <input type="checkbox" checked={replaceExisting} onChange={(event) => setReplaceExisting(event.target.checked)} />
            Replace existing requirements
          </label>
          <button
            onClick={handleImport}
            disabled={!requirementFile || isImporting}
            className="px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-semibold disabled:opacity-50 inline-flex items-center gap-1"
          >
            <Upload size={14} />
            {isImporting ? 'Importing...' : 'Import Workbook'}
          </button>

          <div className="h-4 w-px bg-slate-200 mx-1 hidden sm:block"></div>

          <button
            onClick={() => setShowManualForm(!showManualForm)}
            className="px-4 py-2 rounded-lg bg-white border border-indigo-600 text-indigo-700 text-sm font-bold hover:bg-slate-900 hover:text-white transition-all inline-flex items-center gap-1"
          >
            <Plus size={14} />
            {showManualForm ? 'Discard Manual' : 'Add Manual Item'}
          </button>
        </div>

        {showManualForm && (
           <div className="mt-4 p-5 bg-white rounded-2xl border border-indigo-100 space-y-4 animate-fade-in shadow-sm shadow-indigo-100">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                 <div className="space-y-1.5">
                    <label className="text-[10px] uppercase font-black text-slate-400 tracking-widest">Requirement Title</label>
                    <input 
                      value={newTitle}
                      onChange={(e) => setNewTitle(e.target.value)}
                      placeholder="e.g. PAN Card Copy"
                      className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold focus:ring-2 focus:ring-indigo-500 outline-none"
                    />
                 </div>
                 <div className="space-y-1.5">
                    <label className="text-[10px] uppercase font-black text-slate-400 tracking-widest">Type</label>
                    <select 
                      value={newType}
                      onChange={(e) => setNewType(e.target.value)}
                      className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold focus:ring-2 focus:ring-indigo-500 outline-none"
                    >
                       <option value="Document">File Upload (Document)</option>
                       <option value="Detail">Text Input (Detail)</option>
                    </select>
                 </div>
              </div>
              <div className="space-y-1.5">
                 <label className="text-[10px] uppercase font-black text-slate-400 tracking-widest">Instructions (Optional)</label>
                 <textarea 
                   value={newDesc}
                   onChange={(e) => setNewDesc(e.target.value)}
                   placeholder="Add any specific instructions for the client..."
                   className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-sm outline-none resize-none h-20"
                 />
              </div>
              <div className="pt-2">
                 <button 
                    disabled={!newTitle || manualLoading}
                    onClick={async () => {
                       setManualLoading(true);
                       try {
                          await onRaiseRequirement({
                             title: newTitle,
                             description: newDesc,
                             type: newType
                          });
                          setNewTitle('');
                          setNewDesc('');
                          setShowManualForm(false);
                       } finally {
                          setManualLoading(false);
                       }
                    }}
                    className="w-full py-3 bg-indigo-600 text-white rounded-xl font-black text-sm shadow-xl shadow-indigo-100 hover:bg-slate-900 transition-all flex items-center justify-center gap-2"
                 >
                    {manualLoading ? 'Creating...' : <><Send size={18} /> Publish Requirement</>}
                 </button>
              </div>
           </div>
        )}
      </div>

      {/* Sub Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200 pb-2">
        <button
          onClick={() => setActiveSubTab('details')}
          className={`px-4 py-2 text-sm font-semibold rounded-lg transition-colors ${activeSubTab === 'details' ? 'bg-indigo-50 text-indigo-700' : 'text-slate-500 hover:bg-slate-50'}`}
        >
          Details ({detailRequirements.length})
        </button>
        <button
          onClick={() => setActiveSubTab('uploads')}
          className={`px-4 py-2 text-sm font-semibold rounded-lg transition-colors ${activeSubTab === 'uploads' ? 'bg-indigo-50 text-indigo-700' : 'text-slate-500 hover:bg-slate-50'}`}
        >
          Customer Uploads ({uploadRequirements.length})
        </button>
        <button
          onClick={() => setActiveSubTab('additional')}
          className={`px-4 py-2 text-sm font-semibold rounded-lg transition-colors ${activeSubTab === 'additional' ? 'bg-indigo-50 text-indigo-700' : 'text-slate-500 hover:bg-slate-50'}`}
        >
          Additional Requirements ({additionalRequirements.length})
        </button>
      </div>

      {/* Content */}
      <div className="pt-2">
        {activeSubTab === 'details' && renderRequirementList(detailRequirements)}
        {activeSubTab === 'uploads' && renderRequirementList(uploadRequirements)}
        
        {activeSubTab === 'additional' && (
          <div className="space-y-4">
            <div className="rounded-xl border border-rose-200 p-4 bg-rose-50 shadow-sm border-dashed">
              <p className="text-sm font-black text-rose-800">Raise Additional Query / Requirement</p>
              <p className="text-xs text-rose-600 mt-0.5">Determine if you need the client to type an input (Detail) or upload a file (Document).</p>
              <div className="mt-3 flex flex-wrap gap-2">
                <input
                  value={quickRequirementText}
                  onChange={(event) => setQuickRequirementText(event.target.value)}
                  className="flex-1 min-w-[200px] p-2 border border-rose-300 rounded-lg text-sm bg-white"
                  placeholder="Example: Upload clearer GST certificate copy"
                />
                <select
                  value={quickRequirementType}
                  onChange={(event) => setQuickRequirementType(event.target.value)}
                  className="p-2 border border-rose-300 rounded-lg text-sm bg-white font-medium text-rose-800"
                >
                  <option value="Detail">Require Text Input</option>
                  <option value="Document">Require File Upload</option>
                </select>
                <button onClick={handleRaise} className="px-4 py-2 rounded-lg bg-rose-600 text-white text-sm font-bold shadow-sm hover:bg-rose-700 transition">
                  Raise Query
                </button>
              </div>
            </div>

            {renderRequirementList(additionalRequirements)}
          </div>
        )}
      </div>

    </div>
  );
};

export default OrderRequirementsTab;
