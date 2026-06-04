import React, { useState } from 'react';
import { CreditCard, RefreshCw, AlertCircle, FileText, Info } from 'lucide-react';

const InvoiceAdjustments = ({ selectedOrder, onInitiateBilling, loading }) => {
  const [packageName, setPackageName] = useState(selectedOrder?.packageName || 'Expert Consultation');
  const [totalPackageAmount, setTotalPackageAmount] = useState(selectedOrder?.price || '');
  const [adjustConsultation, setAdjustConsultation] = useState(!selectedOrder?.consultationAdjusted);
  const [adjustPreviousAmount, setAdjustPreviousAmount] = useState(false);
  const [splitPercentage, setSplitPercentage] = useState('100');
  const [dueDate, setDueDate] = useState('');
  const [notes, setNotes] = useState('');
  const [invoiceNumber, setInvoiceNumber] = useState('');

  const previousInvoicesTotal = (selectedOrder?.invoices || []).reduce((sum, inv) => sum + Number(inv.amount || 0), 0);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!totalPackageAmount) return alert('Please enter final package price.');
    
    onInitiateBilling({
      packageName,
      amount: Number(totalPackageAmount),
      adjustConsultation,
      adjustPreviousAmount,
      splitPercentage: Number(splitPercentage) < 100 ? Number(splitPercentage) : null,
      dueDate,
      notes,
      invoiceNumber: invoiceNumber || undefined
    });
  };

  return (
    <form onSubmit={handleSubmit} className="mt-4 p-6 bg-white rounded-2xl border border-indigo-100/80 space-y-6 animate-fade-in shadow-xl shadow-indigo-100/20">
      <div className="flex items-center justify-between border-b border-slate-100 pb-3">
        <p className="font-bold text-slate-800 text-sm flex items-center gap-1.5">
          <CreditCard size={18} className="text-indigo-600" />
          Setup Payments & Invoice Adjustments
        </p>
        <span className="px-2 py-0.5 rounded-full text-[10px] font-black uppercase bg-indigo-50 text-indigo-700 tracking-wider">
          Invoice Module v1.1
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        {/* Package Name */}
        <div className="space-y-1.5">
          <label className="text-[10px] uppercase font-black text-slate-400 tracking-widest flex items-center gap-1">
            <FileText size={10} /> Package Name
          </label>
          <input 
            type="text"
            value={packageName}
            onChange={(e) => setPackageName(e.target.value)}
            placeholder="e.g. Private Limited Registration"
            className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold focus:ring-2 focus:ring-indigo-500 outline-none transition-all"
          />
        </div>

        {/* Total Price */}
        <div className="space-y-1.5">
          <label className="text-[10px] uppercase font-black text-slate-400 tracking-widest">Total Package Price (INR)</label>
          <input 
            type="number"
            value={totalPackageAmount}
            onChange={(e) => setTotalPackageAmount(e.target.value)}
            placeholder="e.g. 11399"
            className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold focus:ring-2 focus:ring-indigo-500 outline-none transition-all"
          />
        </div>

        {/* Split Percentage */}
        <div className="space-y-1.5">
          <label className="text-[10px] uppercase font-black text-slate-400 tracking-widest">Split % for Milestone 1</label>
          <input 
            type="number"
            value={splitPercentage}
            onChange={(e) => setSplitPercentage(e.target.value)}
            placeholder="100"
            min="1"
            max="100"
            className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold focus:ring-2 focus:ring-indigo-500 outline-none transition-all"
          />
        </div>

        {/* Due Date */}
        <div className="space-y-1.5">
          <label className="text-[10px] uppercase font-black text-slate-400 tracking-widest">Due Date (Optional)</label>
          <input 
            type="date"
            value={dueDate}
            onChange={(e) => setDueDate(e.target.value)}
            className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold focus:ring-2 focus:ring-indigo-500 outline-none transition-all"
          />
        </div>
      </div>

      {/* Adjustments section */}
      <div className="bg-slate-50 p-4 rounded-xl border border-slate-200/60 space-y-3">
        <p className="text-[10px] font-black uppercase text-slate-500 tracking-wider">Adjustment Settings</p>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Option: Adjust 499 Consultation */}
          <label className="flex items-start gap-2.5 cursor-pointer select-none">
            <input 
              type="checkbox" 
              checked={adjustConsultation} 
              disabled={selectedOrder?.consultationAdjusted}
              onChange={(e) => setAdjustConsultation(e.target.checked)} 
              className="mt-1 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
            />
            <div>
              <span className="text-xs font-bold text-slate-700">Auto Adjust 499 Consultation Payment</span>
              <p className="text-[10px] text-slate-500">
                {selectedOrder?.consultationAdjusted 
                  ? 'Adjustment already applied to this order.' 
                  : 'Subtract 499 INR from this invoice automatically.'
                }
              </p>
            </div>
          </label>

          {/* Option: Adjust Previous Invoices */}
          <label className="flex items-start gap-2.5 cursor-pointer select-none">
            <input 
              type="checkbox" 
              checked={adjustPreviousAmount} 
              onChange={(e) => setAdjustPreviousAmount(e.target.checked)} 
              className="mt-1 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
            />
            <div>
              <span className="text-xs font-bold text-slate-700">Adjust Previous Invoice Amount</span>
              <p className="text-[10px] text-slate-500">
                {previousInvoicesTotal > 0 
                  ? `Subtract previously billed/paid amount (INR ${previousInvoicesTotal.toLocaleString()}) from the new total.`
                  : 'No previous invoices raised on this order.'
                }
              </p>
            </div>
          </label>
        </div>
      </div>

      {/* Optional Metadata fields */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="space-y-1.5">
          <label className="text-[10px] uppercase font-black text-slate-400 tracking-widest">Custom Invoice Number (Optional)</label>
          <input 
            type="text"
            value={invoiceNumber}
            onChange={(e) => setInvoiceNumber(e.target.value)}
            placeholder="e.g. INV_CUSTOM_123"
            className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-medium focus:ring-2 focus:ring-indigo-500 outline-none transition-all"
          />
        </div>
        <div className="space-y-1.5">
          <label className="text-[10px] uppercase font-black text-slate-400 tracking-widest">Billing Notes (Optional)</label>
          <input 
            type="text"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="e.g. Part payment for private limited setup"
            className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-medium focus:ring-2 focus:ring-indigo-500 outline-none transition-all"
          />
        </div>
      </div>

      {/* Submit Button */}
      <div className="pt-2">
        <button 
          type="submit"
          disabled={loading}
          className="w-full py-3 bg-indigo-600 text-white rounded-xl font-black text-sm shadow-xl shadow-indigo-100 hover:bg-slate-900 transition-all flex items-center justify-center gap-2 active:scale-95 disabled:opacity-50"
        >
          {loading ? 'Processing...' : <><RefreshCw size={18} /> Generate Invoices & Send Links</>}
        </button>
      </div>
    </form>
  );
};

export default InvoiceAdjustments;
