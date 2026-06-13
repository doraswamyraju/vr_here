import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import { 
  Search, FileText, Download, CheckCircle, Clock, AlertTriangle, 
  XCircle, ChevronRight, RefreshCw, User, Calendar, ExternalLink
} from 'lucide-react';

export default function IncomeTaxAssessmentModule({ token }) {
  const [assessments, setAssessments] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedAssessment, setSelectedAssessment] = useState(null);
  const [statusNotes, setStatusNotes] = useState('');
  const [selectedStatus, setSelectedStatus] = useState('');

  const config = useMemo(() => ({
    headers: { Authorization: `Bearer ${token}` }
  }), [token]);

  const fetchAssessments = async () => {
    setLoading(true);
    try {
      const { data } = await axios.get('/api/income-tax-assessment', config);
      setAssessments(data);
    } catch (err) {
      console.error('Failed to fetch assessments:', err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssessments();
  }, [config]);

  const filteredAssessments = useMemo(() => {
    return assessments.filter(a => 
      a.clientName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.pan.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }, [assessments, searchQuery]);

  const handleUpdateStatus = async () => {
    if (!selectedAssessment) return;
    try {
      await axios.put(`/api/income-tax-assessment/${selectedAssessment._id}/status`, {
        status: selectedStatus,
        notes: statusNotes
      }, config);
      
      alert('Status updated successfully!');
      setSelectedAssessment(null);
      fetchAssessments();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to update status');
    }
  };

  const getStatusStyle = (status) => {
    switch (status) {
      case 'Approved': return 'bg-emerald-50 text-emerald-700 border-emerald-200';
      case 'In Progress': return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'Rejected': return 'bg-rose-50 text-rose-700 border-rose-200';
      case 'Pending':
      default: return 'bg-indigo-50 text-indigo-700 border-indigo-200';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'Approved': return <CheckCircle size={12} className="text-emerald-500" />;
      case 'In Progress': return <Clock size={12} className="text-amber-500 animate-pulse" />;
      case 'Rejected': return <XCircle size={12} className="text-rose-500" />;
      case 'Pending':
      default: return <Clock size={12} className="text-indigo-500" />;
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      
      {/* Top Header Card */}
      <div className="bg-white rounded-[32px] p-6 shadow-sm border border-slate-100 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-black text-slate-800 tracking-tight flex items-center gap-3">
            <FileText className="text-indigo-600" />
            Income Tax Assessment Submissions
          </h2>
          <p className="text-slate-500 text-sm font-medium mt-1">
            Review digital checklist replies, verify attachments, and track filing status client-wise.
          </p>
        </div>
        <button 
          onClick={fetchAssessments}
          className="p-3 bg-slate-50 border border-slate-100 hover:border-slate-200 rounded-xl text-slate-500 hover:text-slate-700 transition"
        >
          <RefreshCw size={18} className={loading ? 'animate-spin' : ''} />
        </button>
      </div>

      {/* Control Actions Row */}
      <div className="flex flex-col md:flex-row gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input 
            type="text"
            placeholder="Search by client name or PAN..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-11 pr-4 py-4 rounded-2xl bg-white border border-slate-100 focus:border-indigo-500 outline-none transition-all font-bold text-sm shadow-sm"
          />
        </div>
      </div>

      {/* Table grid */}
      <div className="bg-white rounded-[40px] shadow-sm border border-slate-100 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-50/50">
                <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Client / PAN</th>
                <th className="px-6 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-center">Filing Period</th>
                <th className="px-6 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-center">Submission Date</th>
                <th className="px-6 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-center">Status</th>
                <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50">
              {filteredAssessments.map(item => (
                <tr key={item._id} className="hover:bg-slate-50/30 transition-colors group">
                  <td className="px-8 py-5">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-indigo-50 text-indigo-600 flex items-center justify-center font-black text-xs">
                        {item.clientName.charAt(0).toUpperCase()}
                      </div>
                      <div>
                        <span className="text-sm font-black text-slate-700 block">{item.clientName}</span>
                        <span className="text-[10px] font-bold text-slate-400 tracking-wider uppercase">{item.pan}</span>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-5 text-center">
                    <span className="text-xs font-bold text-slate-600 block">FY {item.financialYear}</span>
                    <span className="text-[9px] font-medium text-slate-400">AY {item.assessmentYear}</span>
                  </td>
                  <td className="px-6 py-5 text-center text-xs font-bold text-slate-500">
                    {new Date(item.createdAt).toLocaleDateString()}
                  </td>
                  <td className="px-6 py-5 text-center">
                    <span className={`inline-flex items-center gap-1 px-3 py-1.5 rounded-full border text-[10px] font-black uppercase tracking-wider ${getStatusStyle(item.status)}`}>
                      {getStatusIcon(item.status)}
                      {item.status}
                    </span>
                  </td>
                  <td className="px-8 py-5 text-right">
                    <button
                      onClick={() => {
                        setSelectedAssessment(item);
                        setSelectedStatus(item.status);
                        setStatusNotes(item.notes || '');
                      }}
                      className="px-4 py-2 bg-indigo-50 hover:bg-indigo-100 text-indigo-600 rounded-xl text-xs font-black transition active:scale-95 flex items-center gap-1.5 ml-auto"
                    >
                      Inspect <ChevronRight size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {filteredAssessments.length === 0 && (
            <div className="py-20 text-center text-slate-400 italic">No checklist submissions found.</div>
          )}
        </div>
      </div>

      {/* Inspect Detail Modal */}
      {selectedAssessment && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-[32px] w-full max-w-4xl max-h-[85vh] overflow-hidden flex flex-col shadow-2xl border border-slate-100">
            
            {/* Modal Header */}
            <div className="p-6 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
              <div>
                <h3 className="text-lg font-black text-slate-800 tracking-tight">
                  {selectedAssessment.clientName} &mdash; ITR Checklist FY {selectedAssessment.financialYear}
                </h3>
                <p className="text-xs font-bold text-slate-400 uppercase tracking-widest mt-0.5">
                  PAN: {selectedAssessment.pan} | submitted: {new Date(selectedAssessment.createdAt).toLocaleString()}
                </p>
              </div>
              <button 
                onClick={() => setSelectedAssessment(null)}
                className="text-slate-400 hover:text-slate-600 text-sm font-black p-2 hover:bg-slate-100 rounded-xl transition"
              >
                Close
              </button>
            </div>

            {/* Modal Scroll Content */}
            <div className="flex-1 overflow-y-auto p-6 md:p-8 space-y-8 bg-slate-50/30">
              
              {/* Status Manager Block */}
              <div className="bg-white rounded-2xl p-5 border border-slate-100 shadow-sm grid grid-cols-1 md:grid-cols-3 gap-5 items-end">
                <div>
                  <label className="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-1.5 block">
                    Filing/Audit Status
                  </label>
                  <select 
                    value={selectedStatus}
                    onChange={e => setSelectedStatus(e.target.value)}
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs font-bold focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500 outline-none text-slate-700"
                  >
                    <option value="Pending">Pending</option>
                    <option value="In Progress">In Progress</option>
                    <option value="Approved">Approved</option>
                    <option value="Rejected">Rejected</option>
                  </select>
                </div>
                <div className="md:col-span-2 flex gap-3 items-end">
                  <div className="flex-grow">
                    <label className="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-1.5 block">
                      Internal CA Notes / Remarks
                    </label>
                    <input 
                      type="text"
                      placeholder="Add status details, references..."
                      value={statusNotes}
                      onChange={e => setStatusNotes(e.target.value)}
                      className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs font-bold focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500 outline-none text-slate-700"
                    />
                  </div>
                  <button 
                    onClick={handleUpdateStatus}
                    className="h-10 px-5 bg-slate-900 text-white rounded-xl text-xs font-black uppercase tracking-widest hover:bg-slate-800 active:scale-95 transition"
                  >
                    Update
                  </button>
                </div>
              </div>

              {/* Answers Breakdown */}
              <div className="space-y-4">
                <h4 className="text-xs font-black text-indigo-600 uppercase tracking-widest border-b border-slate-100 pb-2">
                  ITR Checklist Checklist Reponses (1 to 51)
                </h4>
                
                <div className="space-y-3">
                  {selectedAssessment.responses.map((res) => (
                    <div 
                      key={res.itemId} 
                      className={`p-4 rounded-2xl border bg-white shadow-sm flex flex-col md:flex-row justify-between gap-4 transition ${
                        res.value === 'Yes' ? 'border-indigo-100' : 'border-slate-100'
                      }`}
                    >
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1.5">
                          <span className="w-5 h-5 bg-slate-100 text-[10px] text-slate-500 font-black rounded flex items-center justify-center">
                            {res.itemId}
                          </span>
                          <span className="text-[9px] font-black uppercase tracking-wider bg-slate-50 text-slate-400 px-2 py-0.5 rounded border border-slate-100">
                            {res.section}
                          </span>
                        </div>
                        <p className="text-xs font-bold text-slate-700">{res.description}</p>
                        {res.remarks && (
                          <p className="text-[11px] text-slate-500 font-medium italic mt-1 bg-slate-50 px-2.5 py-1.5 rounded-lg border border-slate-100">
                            Client Remarks: {res.remarks}
                          </p>
                        )}
                      </div>

                      <div className="flex items-center gap-3 self-start md:self-center">
                        <span className={`px-3 py-1 rounded-full text-[9px] font-black uppercase tracking-widest ${
                          res.value === 'Yes' 
                            ? 'bg-emerald-100 text-emerald-700' 
                            : res.value === 'No'
                              ? 'bg-rose-100 text-rose-700'
                              : 'bg-slate-100 text-slate-500'
                        }`}>
                          {res.value}
                        </span>

                        {res.documentUrl && (
                          <a 
                            href={res.documentUrl} 
                            target="_blank" 
                            rel="noreferrer"
                            className="p-2 bg-indigo-50 text-indigo-600 hover:bg-indigo-100 rounded-xl transition flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest"
                          >
                            <ExternalLink size={12} /> View Proof
                          </a>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          </div>
        </div>
      )}

    </div>
  );
}
