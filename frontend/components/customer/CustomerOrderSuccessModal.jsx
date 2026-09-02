import React from 'react';
import { CheckCircle2, ArrowRight, ShieldCheck, FileText, Sparkles } from 'lucide-react';

export default function CustomerOrderSuccessModal({ isOpen, orderData, onClose, onGoToWorkspace }) {
  if (!isOpen || !orderData) return null;

  const order = orderData.order || {};
  const payment = orderData.payment || {};
  const serviceName = order.serviceName || 'Legal & Compliance Service';
  const packageName = order.packageName || 'Standard Package';
  const paymentId = payment.paymentId || order.paymentId || 'Verified';
  const price = order.price || payment.amount || 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-sm animate-in fade-in duration-300">
      <div 
        className="w-full max-w-lg bg-white rounded-3xl shadow-2xl border border-slate-200 overflow-hidden animate-in zoom-in-95 duration-300 relative"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Top Header Banner */}
        <div className="bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900 p-6 text-white text-center relative overflow-hidden">
          <div className="absolute top-0 right-0 w-48 h-48 bg-emerald-500/10 rounded-full blur-2xl pointer-events-none"></div>
          
          <div className="w-16 h-16 rounded-2xl bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center justify-center mx-auto mb-3 shadow-lg shadow-emerald-500/10">
            <CheckCircle2 size={32} />
          </div>

          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-300 text-[10px] font-black uppercase tracking-widest border border-emerald-500/30 mb-2">
            <Sparkles size={12} /> Payment Confirmed
          </span>

          <h2 className="text-xl font-black tracking-tight text-white">
            Order Activated Successfully!
          </h2>
          <p className="text-xs text-slate-400 mt-1 font-medium">
            Your filing has been initiated with our CA & CS advisory team.
          </p>
        </div>

        {/* Details Body */}
        <div className="p-6 space-y-4">
          <div className="bg-slate-50 rounded-2xl p-4 border border-slate-200/80 space-y-2.5">
            <div className="flex justify-between items-center text-xs">
              <span className="font-bold text-slate-500">Service</span>
              <span className="font-black text-slate-900 text-right max-w-[60%] truncate">{serviceName}</span>
            </div>

            <div className="flex justify-between items-center text-xs">
              <span className="font-bold text-slate-500">Package Plan</span>
              <span className="font-black text-slate-900">{packageName}</span>
            </div>

            <div className="flex justify-between items-center text-xs">
              <span className="font-bold text-slate-500">Amount Paid</span>
              <span className="font-black text-emerald-600">₹{Number(price).toLocaleString('en-IN')}</span>
            </div>

            <div className="flex justify-between items-center text-[11px] pt-2 border-t border-slate-200/60 text-slate-400 font-medium">
              <span>Transaction ID</span>
              <span className="font-mono font-bold text-slate-600">{paymentId}</span>
            </div>
          </div>

          <div className="p-3.5 bg-blue-50/60 rounded-xl border border-blue-200/70 flex items-start gap-3">
            <ShieldCheck size={18} className="text-blue-600 shrink-0 mt-0.5" />
            <p className="text-xs text-blue-900 font-medium leading-relaxed">
              Official Tax Invoice has been generated in your <strong>Billing & Invoices</strong> vault. You can now complete the required document checklist.
            </p>
          </div>

          <div className="pt-2 flex flex-col gap-2.5">
            <button
              onClick={onGoToWorkspace}
              className="w-full py-3.5 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-700 hover:to-rose-700 text-white rounded-xl text-xs font-black uppercase tracking-wider transition-all shadow-md shadow-red-600/25 flex items-center justify-center gap-2 group"
            >
              <span>Go to Project Workspace & Upload Documents</span>
              <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
            </button>

            <button
              onClick={onClose}
              className="w-full py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-600 rounded-xl text-xs font-bold transition-colors text-center"
            >
              Back to Catalog
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
