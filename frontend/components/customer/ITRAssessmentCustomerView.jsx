import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { FileText, CheckCircle, Clock, AlertCircle, ArrowUpRight } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export default function ITRAssessmentCustomerView({ selectedOrder, userInfo }) {
  const navigate = useNavigate();
  const [assessment, setAssessment] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchAssessment = async () => {
      setLoading(true);
      setError(null);
      try {
        const config = {
          headers: {
            Authorization: `Bearer ${userInfo.token}`
          }
        };
        const { data } = await axios.get(`/api/income-tax-assessment?orderId=${selectedOrder._id}`, config);
        // Returns an array, get the first one if present
        if (data && data.length > 0) {
          setAssessment(data[0]);
        } else {
          setAssessment(null);
        }
      } catch (err) {
        console.error('Failed to fetch ITR assessment:', err);
        setError('Failed to load checklist status.');
      } finally {
        setLoading(false);
      }
    };

    if (selectedOrder?._id) {
      fetchAssessment();
    }
  }, [selectedOrder?._id, userInfo.token]);

  if (loading) {
    return (
      <div className="flex items-center justify-center p-12 bg-slate-50 border border-slate-100 rounded-3xl">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-5 bg-rose-50 border border-rose-100 rounded-3xl flex items-center gap-3 text-rose-700 text-xs font-bold">
        <AlertCircle size={18} />
        {error}
      </div>
    );
  }

  if (!assessment) {
    return (
      <div className="bg-white border border-slate-100 rounded-3xl p-8 text-center space-y-6 shadow-sm">
        <div className="w-16 h-16 bg-amber-50 text-amber-600 rounded-2xl flex items-center justify-center mx-auto">
          <FileText size={32} />
        </div>
        <div className="max-w-md mx-auto space-y-2">
          <h3 className="text-lg font-black text-slate-800 tracking-tight">ITR Assessment Checklist Required</h3>
          <p className="text-slate-500 text-xs leading-relaxed">
            Please complete your interactive income tax checklist. This helps our expert CA team evaluate your deductions, asset holdings, and tax profiles correctly.
          </p>
        </div>
        <button
          onClick={() => navigate(`/income-tax-assessment?orderId=${selectedOrder._id}`)}
          className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-500 hover:to-indigo-600 text-white rounded-xl text-xs font-black uppercase tracking-wider shadow-lg shadow-indigo-500/20 active:scale-95 transition-all"
        >
          Start Checklist Now <ArrowUpRight size={14} />
        </button>
      </div>
    );
  }

  return (
    <div className="bg-white border border-slate-100 rounded-3xl p-6 shadow-sm space-y-6">
      <div className="flex items-center justify-between border-b border-slate-100 pb-4">
        <div>
          <h3 className="text-sm font-black text-slate-800 uppercase tracking-wider flex items-center gap-2">
            <CheckCircle size={18} className="text-emerald-600" /> Checklist Submitted
          </h3>
          <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-1">
            FY {assessment.financialYear} | PAN: {assessment.pan}
          </p>
        </div>
        <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-amber-50 text-amber-700 rounded-lg text-[10px] font-black uppercase tracking-wider">
          <Clock size={12} /> Pending Review
        </span>
      </div>

      <div className="space-y-4">
        <p className="text-xs font-black text-slate-500 uppercase tracking-widest">Your Responses & Attachments</p>
        
        <div className="space-y-3 max-h-[300px] overflow-y-auto pr-1">
          {assessment.responses?.filter(r => r.value === 'Yes').map((r, idx) => (
            <div key={idx} className="p-3.5 bg-slate-50 border border-slate-100 rounded-2xl space-y-2">
              <div className="flex justify-between items-start gap-4">
                <span className="text-xs font-bold text-slate-800 leading-snug">{r.description}</span>
                <span className="bg-emerald-50 text-emerald-700 border border-emerald-100 px-2 py-0.5 rounded text-[8px] font-black uppercase tracking-wider shrink-0">Yes</span>
              </div>
              
              {r.remarks && (
                <p className="text-[10px] text-slate-500 italic mt-1 leading-normal">
                  Note: {r.remarks}
                </p>
              )}

              {((r.documents && r.documents.length > 0) || r.documentUrl) && (
                <div className="flex flex-wrap gap-1.5 pt-1.5 border-t border-slate-150">
                  {r.documents?.map((doc, dIdx) => (
                    <a
                      key={dIdx}
                      href={doc.documentUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1.5 bg-white border border-slate-200 hover:border-indigo-300 hover:text-indigo-700 px-2.5 py-1.5 rounded-xl text-[10px] font-bold text-slate-650 transition"
                    >
                      <FileText size={12} className="text-indigo-500" />
                      <span className="truncate max-w-[120px]">{doc.originalFileName}</span>
                    </a>
                  ))}
                  {r.documentUrl && !r.documents?.length && (
                    <a
                      href={r.documentUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1.5 bg-white border border-slate-200 hover:border-indigo-300 hover:text-indigo-700 px-2.5 py-1.5 rounded-xl text-[10px] font-bold text-slate-650 transition"
                    >
                      <FileText size={12} className="text-indigo-500" />
                      <span className="truncate max-w-[120px]">{r.originalFileName || 'Attachment'}</span>
                    </a>
                  )}
                </div>
              )}
            </div>
          ))}

          {assessment.responses?.filter(r => r.value === 'Yes').length === 0 && (
            <p className="text-slate-400 italic text-center py-6 text-xs">No checklist items were marked "Yes".</p>
          )}
        </div>
      </div>
    </div>
  );
}
