import React, { useState } from 'react';
import { Upload } from 'lucide-react';
import StatusBadge from './StatusBadge';
import { REQUIREMENT_STATUSES } from './constants';

const OrderRequirementsTab = ({
  selectedOrder,
  onImportRequirementsWorkbook,
  onRaiseRequirement,
  onUpdateRequirementStatus
}) => {
  const [requirementFile, setRequirementFile] = useState(null);
  const [replaceExisting, setReplaceExisting] = useState(true);
  const [quickRequirementText, setQuickRequirementText] = useState('');
  const [isImporting, setIsImporting] = useState(false);

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
    await onRaiseRequirement(quickRequirementText);
    setQuickRequirementText('');
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
        </div>
      </div>

      <div className="rounded-xl border border-rose-200 p-4 bg-rose-50">
        <p className="text-sm font-semibold text-rose-800">Raise Additional Requirement</p>
        <div className="mt-2 flex gap-2">
          <input
            value={quickRequirementText}
            onChange={(event) => setQuickRequirementText(event.target.value)}
            className="flex-1 p-2 border border-rose-300 rounded-lg text-sm"
            placeholder="Example: Upload clearer GST certificate copy"
          />
          <button onClick={handleRaise} className="px-3 py-2 rounded bg-rose-600 text-white text-sm">Raise</button>
        </div>
      </div>

      <div className="space-y-2">
        {(selectedOrder.customerRequirements || []).map((item) => (
          <div key={item._id} className="rounded-lg border border-slate-200 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <p className="font-medium text-slate-800">{item.title}</p>
                <p className="text-xs text-slate-500">
                  {item.type} {item.description ? `- ${item.description}` : ''}
                  {item.sheetName ? ` | Sheet: ${item.sheetName}` : ''}
                </p>
                {item.clientValue && <p className="text-xs text-indigo-700 mt-1">Client Value: {item.clientValue}</p>}
                {item.uploadedDocumentUrl && (
                  <a className="text-xs text-indigo-700 underline mt-1 inline-block" href={item.uploadedDocumentUrl} target="_blank" rel="noreferrer">
                    Client Uploaded Document
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
    </div>
  );
};

export default OrderRequirementsTab;
