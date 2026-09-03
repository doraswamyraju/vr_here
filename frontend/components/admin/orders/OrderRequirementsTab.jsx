import React, { useState, useMemo } from 'react';
import axios from 'axios';
import { Upload, Plus, Trash2, FileText, Fingerprint, Send, CheckCircle2, CreditCard, RefreshCw, AlertTriangle } from 'lucide-react';
import StatusBadge from './StatusBadge';
import { REQUIREMENT_STATUSES } from './constants';
import { InvoiceAdjustments } from '../../../modules/invoices/v1.1';

const OrderRequirementsTab = ({
  selectedOrder,
  onImportRequirementsWorkbook,
  onRaiseRequirement,
  onUpdateRequirementStatus,
  onDeleteRequirement,
  onResetRequirements
}) => {
  const [activeSubTab, setActiveSubTab] = useState('details');
  const [confirmDeleteId, setConfirmDeleteId] = useState(null);
  const [confirmResetType, setConfirmResetType] = useState(null);
  const [isResetting, setIsResetting] = useState(false);
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

  const [showBillingForm, setShowBillingForm] = useState(false);
  const [billingLoading, setBillingLoading] = useState(false);

  const handleInitiateBilling = async (payload) => {
    setBillingLoading(true);
    try {
      const activeToken = JSON.parse(localStorage.getItem('userInfo') || '{}')?.token;
      await axios.post(`/api/orders/${selectedOrder._id}/invoices/adjusted`, payload, {
        headers: { Authorization: `Bearer ${activeToken}` }
      });
      alert('Billing initiated successfully! Invoice has been generated and dispatched to both the customer and admin.');
      setShowBillingForm(false);
      window.location.reload();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to initiate billing.');
    } finally {
      setBillingLoading(false);
    }
  };

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

  const handleReset = async (type = 'Detail') => {
    setIsResetting(true);
    try {
      if (onResetRequirements) {
        await onResetRequirements(type);
      } else {
        const activeToken = JSON.parse(localStorage.getItem('userInfo') || '{}')?.token;
        await axios.delete(`/api/orders/${selectedOrder._id}/requirements?type=${type}`, {
          headers: { Authorization: `Bearer ${activeToken}` }
        });
      }
      setConfirmResetType(null);
    } catch (err) {
      alert(err?.response?.data?.message || `Failed to reset requirements.`);
    } finally {
      setIsResetting(false);
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
          <div key={item._id} className="rounded-lg border border-slate-200 p-3 hover:border-slate-300 transition-colors bg-white">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex-1 min-w-[200px]">
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
                  className="p-2 border rounded-lg border-slate-300 bg-white text-xs font-medium outline-none focus:border-indigo-500"
                >
                  {REQUIREMENT_STATUSES.map((status) => (
                    <option key={status} value={status}>{status}</option>
                  ))}
                </select>
                
                <div className="flex items-center gap-1">
                  {confirmDeleteId === item._id ? (
                    <div className="flex items-center gap-1 animate-fade-in">
                      <button 
                        onClick={() => {
                          onDeleteRequirement(item._id);
                          setConfirmDeleteId(null);
                        }}
                        className="px-2 py-1 text-[9px] font-black uppercase tracking-wider bg-rose-600 text-white rounded hover:bg-rose-700 active:scale-95 transition-all"
                      >
                        Confirm
                      </button>
                      <button 
                        onClick={() => setConfirmDeleteId(null)}
                        className="px-2 py-1 text-[9px] font-black uppercase tracking-wider bg-slate-100 text-slate-600 rounded hover:bg-slate-200 active:scale-95 transition-all"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <button 
                      onClick={() => setConfirmDeleteId(item._id)}
                      className="p-2 text-rose-500 hover:text-rose-700 hover:bg-rose-50 rounded-lg transition-colors"
                      title="Delete Item"
                    >
                      <Trash2 size={16} />
                    </button>
                  )}
                </div>
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
          <label className="text-xs text-slate-600 inline-flex items-center gap-1 cursor-pointer">
            <input type="checkbox" checked={replaceExisting} onChange={(event) => setReplaceExisting(event.target.checked)} />
            Replace existing requirements
          </label>
          <button
            onClick={handleImport}
            disabled={!requirementFile || isImporting}
            className="px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-semibold disabled:opacity-50 inline-flex items-center gap-1 hover:bg-indigo-700 transition"
          >
            <Upload size={14} />
            {isImporting ? 'Importing...' : 'Import Workbook'}
          </button>

          {!selectedOrder?.consultationAdjusted && (
            <>
              <div className="h-4 w-px bg-slate-200 mx-1 hidden sm:block"></div>
              <button
                onClick={() => setShowBillingForm(!showBillingForm)}
                className="px-4 py-2 rounded-lg bg-indigo-50 text-indigo-700 text-sm font-bold hover:bg-slate-900 hover:text-white transition-all inline-flex items-center gap-1.5 shadow-sm shadow-indigo-100"
              >
                <CreditCard size={14} />
                {showBillingForm ? 'Discard Billing' : 'Setup Payments (Single/Split)'}
              </button>
            </>
          )}

          <div className="h-4 w-px bg-slate-200 mx-1 hidden sm:block"></div>

          <button
            onClick={() => setShowManualForm(!showManualForm)}
            className="px-4 py-2 rounded-lg bg-white border border-indigo-600 text-indigo-700 text-sm font-bold hover:bg-slate-900 hover:text-white transition-all inline-flex items-center gap-1"
          >
            <Plus size={14} />
            {showManualForm ? 'Discard Manual' : 'Add Manual Item'}
          </button>

          {detailRequirements.length > 0 && (
            <>
              <div className="h-4 w-px bg-slate-200 mx-1 hidden sm:block"></div>
              {confirmResetType === 'top_Detail' ? (
                <div className="flex items-center gap-1.5 bg-rose-50 px-2.5 py-1.5 border border-rose-200 rounded-lg animate-fade-in">
                  <span className="text-xs font-bold text-rose-700 flex items-center gap-1">
                    <AlertTriangle size={13} /> Reset {detailRequirements.length} details?
                  </span>
                  <button
                    onClick={() => handleReset('Detail')}
                    disabled={isResetting}
                    className="px-2.5 py-1 text-xs font-black uppercase tracking-wider bg-rose-600 text-white rounded hover:bg-rose-700 active:scale-95 disabled:opacity-50 transition"
                  >
                    {isResetting ? 'Resetting...' : 'Yes, Reset All'}
                  </button>
                  <button
                    onClick={() => setConfirmResetType(null)}
                    disabled={isResetting}
                    className="px-2 py-1 text-xs font-bold bg-white border border-slate-200 text-slate-600 rounded hover:bg-slate-100 transition"
                  >
                    Cancel
                  </button>
                </div>
              ) : (
                <button
                  onClick={() => setConfirmResetType('top_Detail')}
                  className="px-3.5 py-2 rounded-lg bg-rose-50 border border-rose-300 text-rose-700 text-sm font-bold hover:bg-rose-600 hover:text-white transition-all inline-flex items-center gap-1.5 shadow-sm"
                  title="Reset all imported client details"
                >
                  <Trash2 size={14} />
                  Reset All Details ({detailRequirements.length})
                </button>
              )}
            </>
          )}
        </div>

        {showBillingForm && (
          <InvoiceAdjustments
            selectedOrder={selectedOrder}
            onInitiateBilling={handleInitiateBilling}
            loading={billingLoading}
          />
        )}

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
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-2">
        <div className="flex flex-wrap items-center gap-2">
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

        {/* Tab specific action buttons */}
        <div className="flex items-center gap-2">
          {activeSubTab === 'details' && detailRequirements.length > 0 && (
            confirmResetType === 'subtab_Detail' ? (
              <div className="flex items-center gap-1.5 bg-rose-50 px-2.5 py-1 border border-rose-200 rounded-lg animate-fade-in">
                <span className="text-xs font-bold text-rose-700">Delete all {detailRequirements.length} details?</span>
                <button
                  onClick={() => handleReset('Detail')}
                  disabled={isResetting}
                  className="px-2.5 py-1 text-xs font-black uppercase tracking-wider bg-rose-600 text-white rounded hover:bg-rose-700 active:scale-95 disabled:opacity-50 transition"
                >
                  {isResetting ? 'Resetting...' : 'Confirm Reset'}
                </button>
                <button
                  onClick={() => setConfirmResetType(null)}
                  disabled={isResetting}
                  className="px-2 py-1 text-xs font-bold bg-white border border-slate-200 text-slate-600 rounded hover:bg-slate-100 transition"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <button
                onClick={() => setConfirmResetType('subtab_Detail')}
                className="px-3 py-1.5 text-xs font-bold rounded-lg bg-rose-50 text-rose-700 border border-rose-200 hover:bg-rose-600 hover:text-white transition-all inline-flex items-center gap-1.5 shadow-sm"
                title="Reset all details for this order"
              >
                <Trash2 size={13} />
                Reset All Details ({detailRequirements.length})
              </button>
            )
          )}

          {activeSubTab === 'uploads' && uploadRequirements.length > 0 && (
            confirmResetType === 'subtab_Document' ? (
              <div className="flex items-center gap-1.5 bg-rose-50 px-2.5 py-1 border border-rose-200 rounded-lg animate-fade-in">
                <span className="text-xs font-bold text-rose-700">Delete all {uploadRequirements.length} documents?</span>
                <button
                  onClick={() => handleReset('Document')}
                  disabled={isResetting}
                  className="px-2.5 py-1 text-xs font-black uppercase tracking-wider bg-rose-600 text-white rounded hover:bg-rose-700 active:scale-95 disabled:opacity-50 transition"
                >
                  {isResetting ? 'Resetting...' : 'Confirm Reset'}
                </button>
                <button
                  onClick={() => setConfirmResetType(null)}
                  disabled={isResetting}
                  className="px-2 py-1 text-xs font-bold bg-white border border-slate-200 text-slate-600 rounded hover:bg-slate-100 transition"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <button
                onClick={() => setConfirmResetType('subtab_Document')}
                className="px-3 py-1.5 text-xs font-bold rounded-lg bg-rose-50 text-rose-700 border border-rose-200 hover:bg-rose-600 hover:text-white transition-all inline-flex items-center gap-1.5 shadow-sm"
                title="Reset all document requirements for this order"
              >
                <Trash2 size={13} />
                Reset All Documents ({uploadRequirements.length})
              </button>
            )
          )}
        </div>
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
