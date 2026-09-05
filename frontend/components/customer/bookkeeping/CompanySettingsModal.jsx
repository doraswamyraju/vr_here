import React, { useState, useEffect, useRef } from 'react';
import { X, Building, PenTool, Upload, Image as ImageIcon, Save, Check } from 'lucide-react';

const CompanySettingsModal = ({ 
    show, 
    onClose, 
    company, 
    userInfo, 
    onSave 
}) => {
    const logoInputRef = useRef(null);
    const sigInputRef = useRef(null);
    const qrInputRef = useRef(null);

    const [companyName, setCompanyName] = useState('');
    const [tradeName, setTradeName] = useState('');
    const [companyGstin, setCompanyGstin] = useState('');
    const [companyAddress, setCompanyAddress] = useState('');
    const [companyState, setCompanyState] = useState('Andhra Pradesh');
    const [companyPhone, setCompanyPhone] = useState('');
    const [companyEmail, setCompanyEmail] = useState('');
    const [companyType, setCompanyType] = useState('Service');
    const [companyCategory, setCompanyCategory] = useState('');
    const [companyPincode, setCompanyPincode] = useState('');
    const [invoicePrefix, setInvoicePrefix] = useState('INV-');
    const [bankName, setBankName] = useState('');
    const [bankAccount, setBankAccount] = useState('');
    const [bankIfsc, setBankIfsc] = useState('');
    const [bankAccountName, setBankAccountName] = useState('');
    const [logo, setLogo] = useState('');
    const [signature, setSignature] = useState('');
    const [upiId, setUpiId] = useState('');
    const [qrCode, setQrCode] = useState('');

    // Prepopulate data whenever modal is opened or company/userInfo changes
    useEffect(() => {
        if (show) {
            setCompanyName(company?.companyName || userInfo?.companyName || userInfo?.name || '');
            setTradeName(company?.tradeName || '');
            setCompanyGstin(company?.gstin || userInfo?.gstin || '');
            setCompanyAddress(company?.address || userInfo?.address || '');
            setCompanyState(company?.state || 'Andhra Pradesh');
            setCompanyPhone(company?.phone || userInfo?.phone || '');
            setCompanyEmail(company?.email || userInfo?.email || '');
            setCompanyType(company?.companyType || userInfo?.businessType || 'Service');
            setCompanyCategory(company?.companyCategory || '');
            setCompanyPincode(company?.pincode || '');
            setInvoicePrefix(company?.invoicePrefix || 'INV-');
            setBankName(company?.bankDetails?.bankName || '');
            setBankAccount(company?.bankDetails?.accountNumber || '');
            setBankIfsc(company?.bankDetails?.ifscCode || '');
            setBankAccountName(company?.bankDetails?.accountName || '');
            setLogo(company?.logo || userInfo?.companyLogo || '');
            setSignature(company?.signature || '');
            setUpiId(company?.upiId || '');
            setQrCode(company?.qrCode || '');
        }
    }, [show, company, userInfo]);
    
    if (!show) return null;

    const handleFileChange = (e, setter) => {
        const file = e.target.files?.[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onloadend = () => {
            setter(reader.result);
        };
        reader.readAsDataURL(file);
    };

    const handleLogoClick = () => {
        if (logoInputRef.current) logoInputRef.current.click();
    };

    const handleSigClick = () => {
        if (sigInputRef.current) sigInputRef.current.click();
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        const payload = {
            companyName: companyName.trim(),
            tradeName: tradeName.trim(),
            gstin: companyGstin.trim().toUpperCase(),
            address: companyAddress.trim(),
            state: companyState,
            phone: companyPhone.trim(),
            email: companyEmail.trim(),
            companyType,
            companyCategory: companyCategory.trim(),
            pincode: companyPincode.trim(),
            invoicePrefix: invoicePrefix.trim(),
            bankDetails: {
                bankName: bankName.trim(),
                accountNumber: bankAccount.trim(),
                ifscCode: bankIfsc.trim().toUpperCase(),
                accountName: bankAccountName.trim()
            },
            upiId: upiId.trim(),
            logo,
            signature,
            qrCode
        };

        if (onSave) {
            onSave(payload);
        }
    };

    return (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in duration-300">
            <div className="bg-white w-full max-w-5xl rounded-[2rem] p-6 sm:p-8 shadow-2xl relative overflow-y-auto max-h-[95vh] animate-in zoom-in-95 duration-200">
                <button 
                    onClick={onClose} 
                    className="absolute top-6 right-6 text-slate-400 hover:text-slate-600 p-2 rounded-full hover:bg-slate-100 transition"
                >
                    <X size={20} />
                </button>
                
                <div className="border-b border-slate-100 pb-4 mb-6">
                    <h3 className="text-lg font-black text-slate-900">Edit Profile & Business Details</h3>
                    <p className="text-slate-400 text-xs">Configure your legal corporate details, address, state jurisdiction, bank details, and branding.</p>
                </div>

                <form onSubmit={handleSubmit} className="space-y-6 text-xs">
                    <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                        {/* Left Side Profile & Logo */}
                        <div className="lg:col-span-3 flex flex-col items-center gap-4 text-center">
                            <input 
                                type="file" 
                                ref={logoInputRef} 
                                accept="image/*" 
                                className="hidden" 
                                onChange={e => handleFileChange(e, setLogo)} 
                            />
                            <div 
                                onClick={handleLogoClick}
                                className="w-36 h-36 bg-slate-50 border-2 border-dashed border-slate-300 rounded-full flex flex-col items-center justify-center text-slate-400 cursor-pointer hover:bg-indigo-50/50 hover:border-indigo-400 relative overflow-hidden group"
                            >
                                {logo ? (
                                    <img src={logo} className="w-full h-full object-cover animate-in fade-in" alt="Logo" />
                                ) : (
                                    <>
                                        <Building size={36} className="text-slate-400 group-hover:scale-110 transition" />
                                        <span className="text-[10px] font-bold mt-1 text-slate-500">Upload Logo</span>
                                    </>
                                )}
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
                                    placeholder="e.g. INV-"
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs font-bold text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                />
                                <span className="text-[9px] text-slate-400 mt-1 block">Default prefix for automatic invoice counters</span>
                            </div>
                        </div>

                        {/* Middle Section details */}
                        <div className="lg:col-span-5 space-y-4">
                            <h4 className="font-black text-slate-800 text-xs border-b border-slate-100 pb-1 mb-2">Business Details</h4>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Business Legal Name *</label>
                                <input 
                                    type="text" 
                                    value={companyName} 
                                    onChange={e => setCompanyName(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs font-bold text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                    required 
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Trade / Brand Name</label>
                                <input 
                                    type="text" 
                                    value={tradeName} 
                                    onChange={e => setTradeName(e.target.value)} 
                                    placeholder="Optional Trade Name"
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
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
                                    placeholder="e.g. 37AAAAA0000A1Z5"
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none uppercase font-mono font-bold"
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
                                        <option value="Private Limited">Private Limited</option>
                                        <option value="Proprietorship">Proprietorship</option>
                                    </select>
                                </div>
                                <div className="space-y-1">
                                    <label className="font-bold text-slate-600">Business Category</label>
                                    <input 
                                        type="text" 
                                        value={companyCategory} 
                                        onChange={e => setCompanyCategory(e.target.value)} 
                                        placeholder="e.g. IT & Software"
                                        className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                    />
                                </div>
                            </div>
                        </div>

                        {/* Right Section details */}
                        <div className="lg:col-span-4 space-y-4">
                            <h4 className="font-black text-slate-800 text-xs border-b border-slate-100 pb-1 mb-2">Location & Bank Details</h4>
                            <div className="grid grid-cols-2 gap-2">
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
                                        <option value="Gujarat">Gujarat</option>
                                        <option value="Kerala">Kerala</option>
                                        <option value="Uttar Pradesh">Uttar Pradesh</option>
                                        <option value="West Bengal">West Bengal</option>
                                    </select>
                                </div>
                                <div className="space-y-1">
                                    <label className="font-bold text-slate-600">Pincode</label>
                                    <input 
                                        type="text" 
                                        value={companyPincode} 
                                        onChange={e => setCompanyPincode(e.target.value)} 
                                        placeholder="500001"
                                        className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                    />
                                </div>
                            </div>
                            <div className="space-y-1">
                                <label className="font-bold text-slate-600">Business Address</label>
                                <textarea 
                                    value={companyAddress} 
                                    onChange={e => setCompanyAddress(e.target.value)} 
                                    className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                    rows="3"
                                    placeholder="Enter complete office/registered business address..."
                                    required 
                                />
                            </div>

                            {/* Bank Details */}
                            <div className="border-t border-slate-100 pt-4 space-y-3">
                                <h4 className="font-bold text-slate-800 text-xs">Bank Details (For Invoicing)</h4>
                                <div className="grid grid-cols-2 gap-2">
                                    <input 
                                        type="text" 
                                        placeholder="Bank Name" 
                                        value={bankName} 
                                        onChange={e => setBankName(e.target.value)} 
                                        className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs font-bold text-slate-800 focus:outline-none"
                                    />
                                    <input 
                                        type="text" 
                                        placeholder="Account Number" 
                                        value={bankAccount} 
                                        onChange={e => setBankAccount(e.target.value)} 
                                        className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs font-bold text-slate-800 focus:outline-none"
                                    />
                                </div>
                                <div className="grid grid-cols-2 gap-2">
                                    <input 
                                        type="text" 
                                        placeholder="IFSC Code" 
                                        value={bankIfsc} 
                                        onChange={e => setBankIfsc(e.target.value)} 
                                        className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs font-bold text-slate-800 focus:outline-none uppercase"
                                    />
                                    <input 
                                        type="text" 
                                        placeholder="Account Name (A/c Holder)" 
                                        value={bankAccountName} 
                                        onChange={e => setBankAccountName(e.target.value)} 
                                        className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none"
                                    />
                                </div>
                                
                                {/* UPI / QR details */}
                                <div className="pt-2 space-y-2">
                                    <label className="font-bold text-slate-700 block">UPI ID for Payments Collection</label>
                                    <input 
                                        type="text" 
                                        placeholder="e.g. business@upi" 
                                        value={upiId} 
                                        onChange={e => setUpiId(e.target.value)} 
                                        className="w-full bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs font-bold text-slate-800 focus:outline-none"
                                    />
                                    
                                    <label className="font-bold text-slate-700 block">Payment QR Code</label>
                                    <input 
                                        type="file" 
                                        ref={qrInputRef} 
                                        accept="image/*" 
                                        className="hidden" 
                                        onChange={e => handleFileChange(e, setQrCode)} 
                                    />
                                    <div 
                                        onClick={() => qrInputRef.current && qrInputRef.current.click()}
                                        className="border border-slate-300 rounded-2xl p-3 bg-slate-50 flex items-center justify-center text-slate-400 cursor-pointer hover:bg-indigo-50/50 transition"
                                    >
                                        {qrCode ? (
                                            <img src={qrCode} className="w-16 h-16 object-contain" alt="QR Preview" />
                                        ) : (
                                            <span className="text-[10px] font-bold">Upload QR Code Image</span>
                                        )}
                                    </div>
                                </div>
                            </div>

                            {/* Signature Upload */}
                            <div className="space-y-2">
                                <input 
                                    type="file" 
                                    ref={sigInputRef} 
                                    accept="image/*" 
                                    className="hidden" 
                                    onChange={e => handleFileChange(e, setSignature)} 
                                />
                                <label className="font-bold text-slate-600 block">Authorized Signature</label>
                                <div 
                                    onClick={handleSigClick}
                                    className="border-2 border-dashed border-slate-300 rounded-2xl p-3 bg-slate-50 flex flex-col items-center justify-center text-slate-400 cursor-pointer hover:bg-indigo-50/50 hover:border-indigo-400 relative overflow-hidden transition"
                                >
                                    {signature ? (
                                        <img src={signature} className="w-full h-14 object-contain" alt="Signature" />
                                    ) : (
                                        <>
                                            <PenTool size={20} className="text-slate-400" />
                                            <span className="text-[10px] font-bold mt-1">Upload Signature Image</span>
                                        </>
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="flex justify-end gap-2 border-t border-slate-100 pt-6">
                        <button 
                            type="button" 
                            onClick={onClose}
                            className="bg-slate-100 hover:bg-slate-200 text-slate-700 px-6 py-2.5 rounded-xl font-bold transition"
                        >
                            Cancel
                        </button>
                        <button 
                            type="submit" 
                            className="bg-indigo-600 text-white px-8 py-2.5 rounded-xl hover:bg-indigo-700 transition font-bold shadow-md shadow-indigo-100 flex items-center gap-1.5"
                        >
                            <Save size={15} /> Save Changes
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default CompanySettingsModal;
