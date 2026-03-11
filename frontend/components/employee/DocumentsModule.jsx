import React from 'react';
import { Download } from 'lucide-react';

const DocumentsModule = ({ selectedOrder }) => {
  if (!selectedOrder) {
    return (
      <div className="bg-white rounded-2xl border border-slate-200 p-6 text-sm text-slate-500">
        Select an order to view client documents and final delivery files.
      </div>
    );
  }

  const clientDocs = selectedOrder.clientDocuments || [];
  const adminDocs = selectedOrder.adminDocuments || [];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div className="bg-white rounded-2xl border border-slate-200 p-6">
        <h3 className="font-bold text-slate-800 mb-3">Client Uploaded Documents</h3>
        <div className="space-y-2">
          {clientDocs.map((doc) => (
            <div key={doc._id} className="p-3 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between">
              <span className="text-sm text-slate-700 font-medium truncate mr-3">{doc.name}</span>
              <a href={doc.url} target="_blank" rel="noreferrer" className="text-indigo-600">
                <Download size={14} />
              </a>
            </div>
          ))}
          {clientDocs.length === 0 && <p className="text-sm text-slate-500">No client documents yet.</p>}
        </div>
      </div>

      <div className="bg-white rounded-2xl border border-slate-200 p-6">
        <h3 className="font-bold text-slate-800 mb-3">Internal / Final Documents</h3>
        <div className="space-y-2">
          {adminDocs.map((doc) => (
            <div key={doc._id} className="p-3 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between">
              <span className="text-sm text-slate-700 font-medium truncate mr-3">{doc.name}</span>
              <a href={doc.url} target="_blank" rel="noreferrer" className="text-indigo-600">
                <Download size={14} />
              </a>
            </div>
          ))}
          {selectedOrder.finalCertificateUrl && (
            <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 flex items-center justify-between">
              <span className="text-sm text-emerald-700 font-semibold truncate mr-3">Final Certificate</span>
              <a href={selectedOrder.finalCertificateUrl} target="_blank" rel="noreferrer" className="text-indigo-600">
                <Download size={14} />
              </a>
            </div>
          )}
          {adminDocs.length === 0 && !selectedOrder.finalCertificateUrl && (
            <p className="text-sm text-slate-500">No internal/final documents yet.</p>
          )}
        </div>
      </div>
    </div>
  );
};

export default DocumentsModule;

