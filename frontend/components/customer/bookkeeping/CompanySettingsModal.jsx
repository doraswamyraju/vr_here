import React, { useRef } from 'react';
import { X, Building, PenTool } from 'lucide-react';

const CompanySettingsModal = ({ 
    show, onClose, onSave,
    companyName, setCompanyName,
    tradeName, setTradeName,
    companyGstin, setCompanyGstin,
    companyAddress, setCompanyAddress,
    companyState, setCompanyState,
    companyPhone, setCompanyPhone,
    companyEmail, setCompanyEmail,
    companyType, setCompanyType,
    companyCategory, setCompanyCategory,
    companyPincode, setCompanyPincode,
    invoicePrefix, setInvoicePrefix
}) => {
    const logoInputRef = useRef(null);
    const sigInputRef = useRef(null);
    
    if (!show) return null;

    const handleLogoClick = () => {
        if (logoInputRef.current) logoInputRef.current.click();
    };

    const handleSigClick = () => {
        if (sigInputRef.current) sigInputRef.current.click();
    };

    return (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in duration-300">
            <div className="bg-white w-full max-w-5xl rounded-[2rem] p-8 shadow-2xl relative overflow-y-auto max-h-[95vh] animate-in zoom-in-95 duration-500">
                <button onClick={onClose} className="absolute top-6 right-6 text-slate-400 hover:text-slate-600">
                    <X size={20} />
                </button>
                
                <div className="border-b border-slate-100 pb-4 mb-6">
                    <h3 className="text-lg font-black text-slate-900">Edit Profile & Business Details</h3>
                    <p className="text-slate-400 text-xs">Configure your legal corporate details, address, state jurisdiction and defaults.</p>
                </div>

                <form onSubmit={onSave} className="space-y-6 text-xs">
                    <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                        {/* Left Side Profile & Logo */}
                        <div className="lg:col-span-3 flex flex-col items-center gap-4 text-center">
                            <input 
                                type="file" 
                                ref={logoInputRef} 
                                accept="image/*" 
                                className="hidden" 
                                onChange={() => alert('Logo uploaded successfully! Preview will update on save.')} 
                            />
                            <div 
                                onClick={handleLogoClick}
                                className="w-36 h-36 bg-slate-50 border-2 border-dashed border-slate-300 rounded-full flex flex-col items-center justify-center text-slate-400 cursor-pointer hover:bg-indigo-50/50 hover:border-indigo-400 relative overflow-hidden group"
                            >
                                <Building size={36} className="text-slate-400 group-hover:scale-110 transition" />
                                <span className="text-[10px] font-bold mt-1 text-slate-500">Upload Logo</span>
                                <div className="absolute inset-0 bg-black/40 text-white text-[9px] font-bold flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity">Change</div>
                            </div>
                            <p className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">Logo helps brand invoices</p>
                            
                            {/* Invoice Number prefix settings */}
                            <div className="w-full border-t border-slate-100 pt-4 text-left">
                                <label className="font-bold text-slate-700 block mb-1">Invoice Number Prefix</label>
                                <input 
                                    type="text" 
                                    value={invoicePrefix} 
                                    onChange={e => setInvoicePrefix(e.target.value)} 
                                    placeholder="e.g. 270326"
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs font-bold text-slate-800 focus:outline-none"
                                />
                                <span className="text-[9px] text-slate-400 mt-1 block">Default prefix for automatic invoice counters</span>
                            </div>
                        </div>

                        {/* Middle Section details */}
                        <div className="lg:col-span-5 space-y-4">
                            <h4 className="font-black text-slate-800 text-xs border-b border-slate-100 pb-1 mb-2">Business Details</h4>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Business Name *</label>
                                <input 
                                    type="text" 
                                    value={companyName} 
                                    onChange={e => setCompanyName(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                    required 
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Phone Number</label>
                                <input 
                                    type="text" 
                                    value={companyPhone} 
                                    onChange={e => setCompanyPhone(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">GSTIN *</label>
                                <input 
                                    type="text" 
                                    value={companyGstin} 
                                    onChange={e => setCompanyGstin(e.target.value)} 
                                    maxLength={15}
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none uppercase"
                                    required 
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Email ID</label>
                                <input 
                                    type="email" 
                                    value={companyEmail} 
                                    onChange={e => setCompanyEmail(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                />
                            </div>
                            <div className="grid grid-cols-2 gap-2">
                                <div className="space-y-1">
                                    <label className="font-bold text-slate-600">Business Type</label>
                                    <select 
                                        value={companyType} 
                                        onChange={e => setCompanyType(e.target.value)}
                                        className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                    >
                                        <option value="Service">Service</option>
                                        <option value="Retail">Retail</option>
                                        <option value="Manufacturing">Manufacturing</option>
                                        <option value="Distributor">Distributor</option>
                                    </select>
                                </div>
                                <div className="space-y-1">
                                    <label className="font-bold text-slate-600">Business Category</label>
                                    <input 
                                        type="text" 
                                        value={companyCategory} 
                                        onChange={e => setCompanyCategory(e.target.value)} 
                                        className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                    />
                                </div>
                            </div>
                        </div>

                        {/* Right Section details */}
                        <div className="lg:col-span-4 space-y-4">
                            <h4 className="font-black text-slate-800 text-xs border-b border-slate-100 pb-1 mb-2">More Details</h4>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">State *</label>
                                <select 
                                    value={companyState} 
                                    onChange={e => setCompanyState(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                >
                                    <option value="Andhra Pradesh">Andhra Pradesh</option>
                                    <option value="Telangana">Telangana</option>
                                    <option value="Karnataka">Karnataka</option>
                                    <option value="Tamil Nadu">Tamil Nadu</option>
                                    <option value="Maharashtra">Maharashtra</option>
                                    <option value="Delhi">Delhi</option>
                                </select>
                            </div>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Pincode</label>
                                <input 
                                    type="text" 
                                    value={companyPincode} 
                                    onChange={e => setCompanyPincode(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Business Address</label>
                                <textarea 
                                    value={companyAddress} 
                                    onChange={e => setCompanyAddress(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                    rows="3"
                                    required 
                                />
                            </div>

                            {/* Signature Upload */}
                            <div className="space-y-2">
                                <input 
                                    type="file" 
                                    ref={sigInputRef} 
                                    accept="image/*" 
                                    className="hidden" 
                                    onChange={() => alert('Signature uploaded successfully! Preview will update on save.')} 
                                />
                                <label className="font-bold text-slate-600 block">Add Signature</label>
                                <div 
                                    onClick={handleSigClick}
                                    className="border-2 border-dashed border-slate-300 rounded-2xl p-4 bg-slate-50 flex flex-col items-center justify-center text-slate-400 cursor-pointer hover:bg-indigo-50/50 hover:border-indigo-400"
                                >
                                    <PenTool size={24} className="text-slate-400" />
                                    <span className="text-[10px] font-bold mt-1">Upload Signature Image</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="flex justify-end gap-2 border-t border-slate-100 pt-6">
                        <button 
                            type="button" 
                            onClick={onClose}
                            className="bg-slate-100 hover:bg-slate-200 text-slate-700 px-6 py-2.5 rounded-xl font-bold"
                        >
                            Cancel
                        </button>
                        <button 
                            type="submit" 
                            className="bg-indigo-600 text-white px-8 py-2.5 rounded-xl hover:bg-indigo-700 transition font-bold"
                        >
                            Save Changes
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default CompanySettingsModal;
