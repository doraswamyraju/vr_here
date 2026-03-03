import React, { useState } from 'react';
import {
    Upload, FileText, Download, FolderOpen,
    Search, CheckCircle2, Clock, AlertTriangle, Plus
} from 'lucide-react';
import axios from 'axios';

const DocumentsView = ({ orders, refreshOrders, userInfo }) => {
    const [activeOrder, setActiveOrder] = useState(orders[0]?._id || '');
    const [file, setFile] = useState(null);
    const [isUploading, setIsUploading] = useState(false);
    const [activeTab, setActiveTab] = useState('provided'); // 'provided' or 'uploaded'

    const selectedOrder = orders.find(o => o._id === activeOrder);

    const handleUpload = async (e) => {
        e.preventDefault();
        if (!file || !activeOrder) return;

        const formData = new FormData();
        formData.append('document', file);

        setIsUploading(true);
        try {
            await axios.post(`/api/orders/${activeOrder}/documents`, formData, {
                headers: {
                    'Content-Type': 'multipart/form-data',
                    Authorization: `Bearer ${userInfo.token}`
                }
            });
            alert('Document uploaded successfully!');
            setFile(null);
            refreshOrders();
        } catch (error) {
            console.error(error);
            alert('Error uploading document');
        }
        setIsUploading(false);
    };

    return (
        <div className="space-y-6 pb-20 md:pb-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div className="flex justify-between items-end mb-2 px-1">
                <div>
                    <h1 className="text-2xl font-black text-slate-800 tracking-tight">Your Documents</h1>
                    <p className="text-slate-500 text-sm">Manage all project related files here.</p>
                </div>
            </div>

            {/* Project Selector - Highly Styled */}
            <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm transition-all focus-within:border-indigo-100">
                <label className="block text-[10px] font-black text-slate-400 uppercase tracking-widest mb-2 px-1">Active Project</label>
                <div className="relative group">
                    <select
                        value={activeOrder}
                        onChange={e => setActiveOrder(e.target.value)}
                        className="w-full pl-4 pr-10 py-3.5 bg-slate-50 border-none rounded-2xl outline-none appearance-none font-black text-slate-800 text-sm focus:ring-2 focus:ring-indigo-500/10 transition-all capitalize shadow-inner"
                    >
                        {orders.map(o => (
                            <option key={o._id} value={o._id}>{o.serviceName}</option>
                        ))}
                    </select>
                    <div className="absolute inset-y-0 right-0 pr-4 flex items-center pointer-events-none text-slate-400">
                        <Plus size={18} />
                    </div>
                </div>
            </div>

            {selectedOrder ? (
                <div className="space-y-6">
                    {/* Inner Tabs */}
                    <div className="flex bg-slate-100/50 p-1.5 rounded-2xl gap-1">
                        <button
                            onClick={() => setActiveTab('provided')}
                            className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-xs font-black transition-all \${activeTab === 'provided' ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-400 hover:text-slate-600'}`}
                        >
                            <FolderOpen size={14} />
                            <span>Documents Provided by Admin</span>
                        </button>
                        <button
                            onClick={() => setActiveTab('uploaded')}
                            className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-xs font-black transition-all \${activeTab === 'uploaded' ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-400 hover:text-slate-600'}`}
                        >
                            <Upload size={14} />
                            <span>Documents Uploaded by You</span>
                        </button>
                    </div>

                    {/* Final Certificate Card - Special Attention */}
                    {selectedOrder.finalCertificateUrl && (
                        <div className="bg-gradient-to-br from-indigo-600 to-indigo-800 rounded-3xl p-6 text-white shadow-xl shadow-indigo-100 relative overflow-hidden animate-pulse">
                            <div className="relative z-10 flex flex-col gap-4">
                                <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 bg-white/20 backdrop-blur-md rounded-2xl flex items-center justify-center border border-white/20">
                                        <CheckCircle2 className="text-emerald-400" size={24} />
                                    </div>
                                    <div>
                                        <h4 className="font-black text-lg tracking-tight">Project Completed!</h4>
                                        <p className="text-indigo-100 text-[10px] font-bold uppercase tracking-wider">Final Certificate Ready</p>
                                    </div>
                                </div>
                                <a
                                    href={`${selectedOrder.finalCertificateUrl}`}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="bg-white text-indigo-600 py-3.5 rounded-2xl text-sm font-black transition-all shadow-lg flex items-center justify-center gap-2 active:scale-95 hover:bg-emerald-50 hover:text-emerald-600"
                                >
                                    <Download size={18} /> Download Certificate
                                </a>
                            </div>
                        </div>
                    )}

                    {/* Documents List */}
                    <div className="space-y-4">
                        {activeTab === 'provided' ? (
                            <>
                                {selectedOrder.adminDocuments?.length > 0 ? (
                                    selectedOrder.adminDocuments.map((doc, i) => (
                                        <div key={doc._id} className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between group hover:border-indigo-100 transition-all">
                                            <div className="flex items-center gap-4">
                                                <div className="w-12 h-12 bg-indigo-50 text-indigo-600 rounded-2xl flex items-center justify-center border border-indigo-100/50">
                                                    <FileText size={20} />
                                                </div>
                                                <div>
                                                    <h5 className="font-black text-slate-800 text-sm line-clamp-1">{doc.name}</h5>
                                                    <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">{new Date(doc.uploadedAt).toLocaleDateString()}</p>
                                                </div>
                                            </div>
                                            <a href={`${doc.url}`} target="_blank" rel="noreferrer" className="w-10 h-10 bg-slate-50 text-slate-400 rounded-2xl flex items-center justify-center hover:bg-indigo-600 hover:text-white transition-all">
                                                <Download size={18} />
                                            </a>
                                        </div>
                                    ))
                                ) : (
                                    <EmptyDocumentsState text="The admin hasn't provided any documents yet." />
                                )}
                            </>
                        ) : (
                            <div className="space-y-6">
                                {/* Upload Dropzone (Mock/Mini) */}
                                <form onSubmit={handleUpload} className="bg-slate-900 rounded-3xl p-6 text-white border-2 border-dashed border-indigo-500/30 group">
                                    <div className="text-center space-y-4">
                                        <div className="w-14 h-14 bg-white/10 rounded-2xl flex items-center justify-center mx-auto group-hover:scale-110 transition-transform">
                                            <Upload className="text-indigo-400" size={28} />
                                        </div>
                                        <div>
                                            <h5 className="font-black text-sm mb-1 tracking-tight">Need to upload something?</h5>
                                            <p className="text-slate-400 text-[10px] leading-relaxed mb-4">Click to select files from your gallery or files</p>
                                        </div>
                                        <input
                                            type="file"
                                            onChange={(e) => setFile(e.target.files[0])}
                                            className="hidden"
                                            id="file-upload"
                                        />
                                        <label
                                            htmlFor="file-upload"
                                            className="block w-full bg-white text-slate-900 py-3.5 rounded-2xl text-[10px] font-black uppercase tracking-widest cursor-pointer hover:bg-indigo-50 transition-colors"
                                        >
                                            {file ? file.name : 'Select File'}
                                        </label>
                                        <button
                                            type="submit"
                                            disabled={isUploading || !file}
                                            className="w-full bg-indigo-600 py-3.5 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all shadow-lg active:scale-95 disabled:opacity-30 flex items-center justify-center gap-2"
                                        >
                                            {isUploading ? '📤 Uploading...' : <><CheckCircle2 size={14} /> Confirm Upload</>}
                                        </button>
                                    </div>
                                </form>

                                {selectedOrder.clientDocuments?.length > 0 ? (
                                    <div className="space-y-3">
                                        <h6 className="text-[10px] font-black text-slate-400 uppercase tracking-widest px-2 mb-2">History</h6>
                                        {selectedOrder.clientDocuments.map((doc) => (
                                            <div key={doc._id} className="bg-white p-4 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                                                <div className="flex items-center gap-3">
                                                    <div className="w-10 h-10 bg-slate-50 text-slate-400 rounded-xl flex items-center justify-center border border-slate-100">
                                                        <FileText size={18} />
                                                    </div>
                                                    <div>
                                                        <h5 className="font-bold text-slate-800 text-xs line-clamp-1">{doc.name}</h5>
                                                        <p className="text-[9px] text-slate-400 font-bold tracking-tight">{new Date(doc.uploadedAt).toLocaleDateString()}</p>
                                                    </div>
                                                </div>
                                                <a href={`${doc.url}`} target="_blank" rel="noreferrer" className="text-indigo-600 font-black text-[10px] uppercase tracking-wider px-3 py-1.5 bg-indigo-50 rounded-xl">View</a>
                                            </div>
                                        ))}
                                    </div>
                                ) : (
                                    <p className="text-center text-slate-400 text-[10px] font-medium py-4">No documents uploaded by you for this project yet.</p>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            ) : (
                <EmptyDocumentsState text="Please start a project to manage documents." />
            )}
        </div>
    );
};

const EmptyDocumentsState = ({ text }) => (
    <div className="bg-slate-50 border-2 border-dashed border-slate-200 rounded-3xl p-12 text-center text-slate-300">
        <FolderOpen size={48} className="mx-auto mb-4 opacity-30" />
        <p className="text-xs font-bold px-8 leading-relaxed mb-4">{text}</p>
    </div>
);

export default DocumentsView;
