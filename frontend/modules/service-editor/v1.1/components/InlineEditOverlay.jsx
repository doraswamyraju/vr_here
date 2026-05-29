import React, { useState, useEffect } from 'react';
import { 
    Edit, Save, Plus, Trash2, X, ChevronRight, Check, AlertCircle, 
    Settings, Package, MessageSquare, List, Users, HelpCircle, Layers, Paintbrush 
} from 'lucide-react';
import { fetchServicePageConfig, updateServicePageConfig } from '../services/serviceConfigApi';

const InlineEditOverlay = ({ pageId, onConfigUpdate, config, isOpen: externalIsOpen, setIsOpen: externalSetIsOpen }) => {
    const [isAdminOrStaff, setIsAdminOrStaff] = useState(false);
    const [localIsOpen, setLocalIsOpen] = useState(false);
    const isOpen = externalIsOpen !== undefined ? externalIsOpen : localIsOpen;
    const setIsOpen = externalSetIsOpen !== undefined ? externalSetIsOpen : setLocalIsOpen;
    const [activeSection, setActiveSection] = useState('hero');
    const [localConfig, setLocalConfig] = useState(null);
    const [saving, setSaving] = useState(false);
    const [successMsg, setSuccessMsg] = useState('');
    const [errorMsg, setErrorMsg] = useState('');

    // Check user role on launch to determine if editing is authorized
    useEffect(() => {
        const checkRole = () => {
            const userInfo = JSON.parse(localStorage.getItem('userInfo') || 'null');
            if (userInfo && (userInfo.role === 'admin' || userInfo.role === 'employee')) {
                setIsAdminOrStaff(true);
            }
        };
        checkRole();
    }, []);

    // Set local editor values once configuration is loaded
    useEffect(() => {
        if (config) {
            setLocalConfig(JSON.parse(JSON.stringify(config))); // Deep copy
        }
    }, [config]);

    if (!isAdminOrStaff || !localConfig) return null;

    const handleSave = async () => {
        setSaving(true);
        setErrorMsg('');
        setSuccessMsg('');
        try {
            const data = await updateServicePageConfig(pageId, localConfig);
            setSuccessMsg('All configurations saved successfully!');
            if (onConfigUpdate) {
                onConfigUpdate(data.page);
            }
            setTimeout(() => setSuccessMsg(''), 4000);
        } catch (err) {
            console.error('Save failed:', err);
            setErrorMsg(err.response?.data?.message || 'Failed to commit updates to database.');
        } finally {
            setSaving(false);
        }
    };

    // Generic Array manipulation helpers
    const updateArrayItem = (key, index, field, value) => {
        const copy = { ...localConfig };
        copy[key][index][field] = value;
        setLocalConfig(copy);
    };

    const addArrayItem = (key, defaultObj) => {
        const copy = { ...localConfig };
        copy[key] = [...copy[key], defaultObj];
        setLocalConfig(copy);
    };

    const removeArrayItem = (key, index) => {
        const copy = { ...localConfig };
        copy[key] = copy[key].filter((_, idx) => idx !== index);
        setLocalConfig(copy);
    };

    return (
        <>
            {/* FLOATING ADMIN INLINE ACTION CONTROL BUTTON */}
            {externalIsOpen === undefined && (
                <button
                    onClick={() => setIsOpen(true)}
                    className="fixed bottom-6 right-6 z-[80] bg-indigo-600 hover:bg-indigo-700 text-white border border-indigo-500 py-3.5 px-5 rounded-2xl font-black text-xs uppercase tracking-widest shadow-2xl flex items-center gap-2 transform hover:-translate-y-1 active:scale-95 transition duration-300"
                >
                    <Edit className="w-4 h-4 animate-pulse" />
                    <span>Customize Page Layout</span>
                </button>
            )}

            {/* DRAWER SECTION PANEL */}
            <div className={`fixed top-0 left-0 h-screen w-full md:w-[500px] bg-slate-950/95 backdrop-blur-xl border-r border-slate-900 z-[95] shadow-2xl transform transition-transform duration-500 ease-out flex flex-col ${isOpen ? 'translate-x-0' : '-translate-x-full'}`}>
                {/* Panel Header */}
                <div className="p-6 border-b border-slate-900 flex items-center justify-between">
                    <div>
                        <div className="flex items-center gap-2">
                            <Settings className="w-5 h-5 text-indigo-400" />
                            <h2 className="text-base font-black text-white uppercase tracking-wider">Page Content Customizer</h2>
                        </div>
                        <p className="text-[10px] text-slate-500 font-bold uppercase mt-1">Live context-sensitive page editor</p>
                    </div>
                    <button
                        onClick={() => setIsOpen(false)}
                        className="text-xs uppercase font-black tracking-widest text-slate-500 hover:text-white transition"
                    >
                        Close [x]
                    </button>
                </div>

                {/* Section navigation tabs */}
                <div className="flex overflow-x-auto border-b border-slate-900 scrollbar-none text-[10px] uppercase font-black tracking-wider bg-slate-950/40">
                    {[
                        { id: 'hero', label: 'Hero', icon: Layers },
                        { id: 'packages', label: 'Pricing', icon: Package },
                        { id: 'logos', label: 'Logos', icon: Paintbrush },
                        { id: 'steps', label: 'Steps', icon: List },
                        { id: 'reviews', label: 'Reviews', icon: Users },
                        { id: 'faqs', label: 'FAQs', icon: HelpCircle }
                    ].map(sec => {
                        const Icon = sec.icon;
                        return (
                            <button
                                key={sec.id}
                                onClick={() => setActiveSection(sec.id)}
                                className={`flex items-center gap-1.5 py-3 px-5 border-b-2 whitespace-nowrap transition ${activeSection === sec.id ? 'border-indigo-500 text-white' : 'border-transparent text-slate-500 hover:text-slate-300'}`}
                            >
                                <Icon className="w-3.5 h-3.5" />
                                <span>{sec.label}</span>
                            </button>
                        );
                    })}
                </div>

                {/* SCROLLABLE EDIT FORM */}
                <div className="flex-1 overflow-y-auto p-6 space-y-6 scrollbar-thin scrollbar-thumb-slate-800">
                    
                    {/* HERO SECTION CONFIG */}
                    {activeSection === 'hero' && (
                        <div className="space-y-4">
                            <div>
                                <label className="block text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1.5">Hero Title</label>
                                <textarea
                                    value={localConfig.hero?.title || ''}
                                    onChange={(e) => {
                                        const copy = { ...localConfig };
                                        copy.hero = { ...copy.hero, title: e.target.value };
                                        setLocalConfig(copy);
                                    }}
                                    className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500 transition h-20"
                                />
                            </div>
                            <div>
                                <label className="block text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1.5">Hero Subtitle</label>
                                <textarea
                                    value={localConfig.hero?.subtitle || ''}
                                    onChange={(e) => {
                                        const copy = { ...localConfig };
                                        copy.hero = { ...copy.hero, subtitle: e.target.value };
                                        setLocalConfig(copy);
                                    }}
                                    className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500 transition h-24"
                                />
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1.5">Badge Promo Text</label>
                                    <input
                                        type="text"
                                        value={localConfig.hero?.badgeText || ''}
                                        onChange={(e) => {
                                            const copy = { ...localConfig };
                                            copy.hero = { ...copy.hero, badgeText: e.target.value };
                                            setLocalConfig(copy);
                                        }}
                                        className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500 transition"
                                    />
                                </div>
                                <div>
                                    <label className="block text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1.5">Consultation Price (₹)</label>
                                    <input
                                        type="number"
                                        value={localConfig.hero?.consultationPrice || 499}
                                        onChange={(e) => {
                                            const copy = { ...localConfig };
                                            copy.hero = { ...copy.hero, consultationPrice: Number(e.target.value) };
                                            setLocalConfig(copy);
                                        }}
                                        className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500 transition"
                                    />
                                </div>
                            </div>
                        </div>
                    )}

                    {/* PACKAGES SECTION CONFIG */}
                    {activeSection === 'packages' && (
                        <div className="space-y-6">
                            <div className="flex items-center justify-between">
                                <h3 className="text-xs font-black uppercase text-slate-400 tracking-wider">Packages Cards Manager</h3>
                                <button
                                    onClick={() => addArrayItem('packages', { id: 'new-plan', name: 'New Plan', price: 999, description: '', features: [], buttonText: 'Select Plan', isPopular: false, isAdjustable: false })}
                                    className="text-[10px] font-black tracking-widest text-indigo-400 hover:text-white uppercase flex items-center gap-1 transition"
                                >
                                    <Plus className="w-3.5 h-3.5" />
                                    <span>Add Plan</span>
                                </button>
                            </div>

                            {localConfig.packages.map((pkg, idx) => (
                                <div key={idx} className="bg-slate-900/40 p-4 rounded-2xl border border-slate-900 relative space-y-4">
                                    <button
                                        onClick={() => removeArrayItem('packages', idx)}
                                        className="absolute top-4 right-4 text-slate-500 hover:text-red-400 transition"
                                        title="Delete plan"
                                    >
                                        <Trash2 className="w-4 h-4" />
                                    </button>

                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Plan Identifier (id)</label>
                                            <input
                                                type="text"
                                                value={pkg.id || ''}
                                                onChange={(e) => updateArrayItem('packages', idx, 'id', e.target.value)}
                                                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Plan Name</label>
                                            <input
                                                type="text"
                                                value={pkg.name || ''}
                                                onChange={(e) => updateArrayItem('packages', idx, 'name', e.target.value)}
                                                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white"
                                            />
                                        </div>
                                    </div>

                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Price (INR ₹)</label>
                                            <input
                                                type="number"
                                                value={pkg.price || 0}
                                                onChange={(e) => updateArrayItem('packages', idx, 'price', Number(e.target.value))}
                                                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Action Button Text</label>
                                            <input
                                                type="text"
                                                value={pkg.buttonText || ''}
                                                onChange={(e) => updateArrayItem('packages', idx, 'buttonText', e.target.value)}
                                                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white"
                                            />
                                        </div>
                                    </div>

                                    <div>
                                        <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Description</label>
                                        <textarea
                                            value={pkg.description || ''}
                                            onChange={(e) => updateArrayItem('packages', idx, 'description', e.target.value)}
                                            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white h-16 resize-none"
                                        />
                                    </div>

                                    <div className="flex gap-4">
                                        <label className="flex items-center gap-2 text-[10px] text-slate-300 font-bold uppercase tracking-wider cursor-pointer">
                                            <input
                                                type="checkbox"
                                                checked={pkg.isPopular || false}
                                                onChange={(e) => updateArrayItem('packages', idx, 'isPopular', e.target.checked)}
                                                className="rounded border-slate-800 text-indigo-500 focus:ring-0 bg-slate-950"
                                            />
                                            <span>Recommend (Popular Badge)</span>
                                        </label>

                                        <label className="flex items-center gap-2 text-[10px] text-slate-300 font-bold uppercase tracking-wider cursor-pointer">
                                            <input
                                                type="checkbox"
                                                checked={pkg.isAdjustable || false}
                                                onChange={(e) => updateArrayItem('packages', idx, 'isAdjustable', e.target.checked)}
                                                className="rounded border-slate-800 text-indigo-500 focus:ring-0 bg-slate-950"
                                            />
                                            <span>Adjustable Fee</span>
                                        </label>
                                    </div>

                                    {/* Features bullets */}
                                    <div>
                                        <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Features (One per line)</label>
                                        <textarea
                                            value={pkg.features ? pkg.features.join('\n') : ''}
                                            onChange={(e) => {
                                                const lines = e.target.value.split('\n');
                                                updateArrayItem('packages', idx, 'features', lines);
                                            }}
                                            placeholder="Feature 1&#10;Feature 2&#10;Feature 3"
                                            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white h-24 font-mono leading-relaxed"
                                        />
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}

                    {/* LOGOS TRUST BRANDING CONFIG */}
                    {activeSection === 'logos' && (
                        <div className="space-y-6">
                            <div className="flex items-center justify-between">
                                <h3 className="text-xs font-black uppercase text-slate-400 tracking-wider">Customer Trust Logos</h3>
                                <button
                                    onClick={() => addArrayItem('logos', { name: 'Brand Name', iconKey: 'Globe', colorClass: 'text-slate-500' })}
                                    className="text-[10px] font-black tracking-widest text-indigo-400 hover:text-white uppercase flex items-center gap-1 transition"
                                >
                                    <Plus className="w-3.5 h-3.5" />
                                    <span>Add Logo</span>
                                </button>
                            </div>

                            {localConfig.logos.map((logo, idx) => (
                                <div key={idx} className="bg-slate-900/40 p-4 rounded-xl border border-slate-900 relative grid grid-cols-3 gap-3 items-center">
                                    <div className="col-span-2 space-y-3">
                                        <div>
                                            <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Brand Name</label>
                                            <input
                                                type="text"
                                                value={logo.name || ''}
                                                onChange={(e) => updateArrayItem('logos', idx, 'name', e.target.value)}
                                                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-xs text-white"
                                            />
                                        </div>
                                        <div className="grid grid-cols-2 gap-2">
                                            <div>
                                                <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Lucide Icon Key</label>
                                                <input
                                                    type="text"
                                                    value={logo.iconKey || 'Globe'}
                                                    onChange={(e) => updateArrayItem('logos', idx, 'iconKey', e.target.value)}
                                                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-xs text-white"
                                                />
                                            </div>
                                            <div>
                                                <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Color Class</label>
                                                <input
                                                    type="text"
                                                    value={logo.colorClass || 'text-slate-500'}
                                                    onChange={(e) => updateArrayItem('logos', idx, 'colorClass', e.target.value)}
                                                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-xs text-white"
                                                />
                                            </div>
                                        </div>
                                    </div>
                                    <div className="flex flex-col items-center justify-center p-2 bg-slate-950 rounded-xl border border-slate-900 h-full relative">
                                        <button
                                            onClick={() => removeArrayItem('logos', idx)}
                                            className="absolute top-1 right-1 text-slate-500 hover:text-red-400 transition"
                                        >
                                            <Trash2 className="w-3.5 h-3.5" />
                                        </button>
                                        <div className="text-[10px] text-slate-400 font-bold uppercase mb-2">Preview</div>
                                        <div className="text-xs font-black tracking-tight text-slate-300">{logo.name}</div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}

                    {/* STEPS TIMELINE CONFIG */}
                    {activeSection === 'steps' && (
                        <div className="space-y-6">
                            <div className="flex items-center justify-between">
                                <h3 className="text-xs font-black uppercase text-slate-400 tracking-wider">Step Timeline Flow</h3>
                                <button
                                    onClick={() => addArrayItem('steps', { number: '01', title: 'New Step', desc: '', badge: '' })}
                                    className="text-[10px] font-black tracking-widest text-indigo-400 hover:text-white uppercase flex items-center gap-1 transition"
                                >
                                    <Plus className="w-3.5 h-3.5" />
                                    <span>Add Step</span>
                                </button>
                            </div>

                            {localConfig.steps.map((step, idx) => (
                                <div key={idx} className="bg-slate-900/40 p-4 rounded-xl border border-slate-900 relative space-y-3">
                                    <button
                                        onClick={() => removeArrayItem('steps', idx)}
                                        className="absolute top-4 right-4 text-slate-500 hover:text-red-400 transition"
                                    >
                                        <Trash2 className="w-4 h-4" />
                                    </button>

                                    <div className="grid grid-cols-3 gap-3">
                                        <div>
                                            <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Index Number</label>
                                            <input
                                                type="text"
                                                value={step.number || ''}
                                                onChange={(e) => updateArrayItem('steps', idx, 'number', e.target.value)}
                                                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-xs text-white"
                                            />
                                        </div>
                                        <div className="col-span-2">
                                            <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Badge Tag</label>
                                            <input
                                                type="text"
                                                value={step.badge || ''}
                                                onChange={(e) => updateArrayItem('steps', idx, 'badge', e.target.value)}
                                                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-xs text-white"
                                            />
                                        </div>
                                    </div>

                                    <div>
                                        <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Step Title</label>
                                        <input
                                            type="text"
                                            value={step.title || ''}
                                            onChange={(e) => updateArrayItem('steps', idx, 'title', e.target.value)}
                                            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-white"
                                        />
                                    </div>

                                    <div>
                                        <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Step description</label>
                                        <textarea
                                            value={step.desc || ''}
                                            onChange={(e) => updateArrayItem('steps', idx, 'desc', e.target.value)}
                                            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-white h-16 resize-none"
                                        />
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}

                    {/* REVIEWS TESTIMONIALS CONFIG */}
                    {activeSection === 'reviews' && (
                        <div className="space-y-6">
                            <div className="flex items-center justify-between">
                                <h3 className="text-xs font-black uppercase text-slate-400 tracking-wider">Reviews Manager</h3>
                                <button
                                    onClick={() => addArrayItem('reviews', { name: 'Customer Name', company: 'Company Pvt Ltd', rating: 5, date: 'Today', text: '', avatar: 'C', verified: true })}
                                    className="text-[10px] font-black tracking-widest text-indigo-400 hover:text-white uppercase flex items-center gap-1 transition"
                                >
                                    <Plus className="w-3.5 h-3.5" />
                                    <span>Add Review</span>
                                </button>
                            </div>

                            {localConfig.reviews.map((rev, idx) => (
                                <div key={idx} className="bg-slate-900/40 p-4 rounded-xl border border-slate-900 relative space-y-3">
                                    <button
                                        onClick={() => removeArrayItem('reviews', idx)}
                                        className="absolute top-4 right-4 text-slate-500 hover:text-red-400 transition"
                                    >
                                        <Trash2 className="w-4 h-4" />
                                    </button>

                                    <div className="grid grid-cols-2 gap-3">
                                        <div>
                                            <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Reviewer Name</label>
                                            <input
                                                type="text"
                                                value={rev.name || ''}
                                                onChange={(e) => updateArrayItem('reviews', idx, 'name', e.target.value)}
                                                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-white"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Company / Organization</label>
                                            <input
                                                type="text"
                                                value={rev.company || ''}
                                                onChange={(e) => updateArrayItem('reviews', idx, 'company', e.target.value)}
                                                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-white"
                                            />
                                        </div>
                                    </div>

                                    <div className="grid grid-cols-3 gap-3">
                                        <div>
                                            <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Avatar Letter</label>
                                            <input
                                                type="text"
                                                value={rev.avatar || ''}
                                                onChange={(e) => updateArrayItem('reviews', idx, 'avatar', e.target.value)}
                                                maxLength={2}
                                                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-white text-center font-bold"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Review Rating</label>
                                            <input
                                                type="number"
                                                value={rev.rating || 5}
                                                onChange={(e) => updateArrayItem('reviews', idx, 'rating', Number(e.target.value))}
                                                min={1}
                                                max={5}
                                                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-white"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Date</label>
                                            <input
                                                type="text"
                                                value={rev.date || ''}
                                                onChange={(e) => updateArrayItem('reviews', idx, 'date', e.target.value)}
                                                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-white"
                                            />
                                        </div>
                                    </div>

                                    <label className="flex items-center gap-2 text-[9.5px] text-slate-400 font-bold uppercase tracking-wider cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={rev.verified || false}
                                            onChange={(e) => updateArrayItem('reviews', idx, 'verified', e.target.checked)}
                                            className="rounded border-slate-800 text-indigo-500 bg-slate-950 focus:ring-0"
                                        />
                                        <span>Verified Customer Badge</span>
                                    </label>

                                    <div>
                                        <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Review Statement</label>
                                        <textarea
                                            value={rev.text || ''}
                                            onChange={(e) => updateArrayItem('reviews', idx, 'text', e.target.value)}
                                            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white h-20"
                                        />
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}

                    {/* FAQS ACCORDION LIST CONFIG */}
                    {activeSection === 'faqs' && (
                        <div className="space-y-6">
                            <div className="flex items-center justify-between">
                                <h3 className="text-xs font-black uppercase text-slate-400 tracking-wider">Frequently Asked Questions</h3>
                                <button
                                    onClick={() => addArrayItem('faqs', { q: 'Question?', a: 'Answer.' })}
                                    className="text-[10px] font-black tracking-widest text-indigo-400 hover:text-white uppercase flex items-center gap-1 transition"
                                >
                                    <Plus className="w-3.5 h-3.5" />
                                    <span>Add FAQ</span>
                                </button>
                            </div>

                            {localConfig.faqs.map((faq, idx) => (
                                <div key={idx} className="bg-slate-900/40 p-4 rounded-xl border border-slate-900 relative space-y-3">
                                    <button
                                        onClick={() => removeArrayItem('faqs', idx)}
                                        className="absolute top-4 right-4 text-slate-500 hover:text-red-400 transition"
                                    >
                                        <Trash2 className="w-4 h-4" />
                                    </button>

                                    <div>
                                        <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Question</label>
                                        <input
                                            type="text"
                                            value={faq.q || ''}
                                            onChange={(e) => updateArrayItem('faqs', idx, 'q', e.target.value)}
                                            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-white"
                                        />
                                    </div>

                                    <div>
                                        <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Answer Statement</label>
                                        <textarea
                                            value={faq.a || ''}
                                            onChange={(e) => updateArrayItem('faqs', idx, 'a', e.target.value)}
                                            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white h-20"
                                        />
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* Status Banners */}
                {successMsg && (
                    <div className="mx-6 mb-3 p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-xl flex items-center gap-2 text-xs font-semibold animate-fade-in">
                        <Check className="w-4 h-4" />
                        <span>{successMsg}</span>
                    </div>
                )}
                {errorMsg && (
                    <div className="mx-6 mb-3 p-3 bg-red-500/10 border border-red-500/20 text-red-400 rounded-xl flex items-center gap-2 text-xs font-semibold animate-fade-in">
                        <AlertCircle className="w-4.5 h-4.5" />
                        <span>{errorMsg}</span>
                    </div>
                )}

                {/* BOTTOM SAVE BAR */}
                <div className="p-6 border-t border-slate-900 bg-slate-950 flex items-center gap-4">
                    <button
                        onClick={handleSave}
                        disabled={saving}
                        className="flex-1 bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3.5 px-4 rounded-xl text-xs uppercase tracking-widest shadow-lg shadow-indigo-600/25 active:scale-95 transform transition-all flex items-center justify-center gap-2"
                    >
                        {saving ? (
                            <span>Committing updates...</span>
                        ) : (
                            <>
                                <Save className="w-4 h-4" />
                                <span>Save Changes</span>
                            </>
                        )}
                    </button>
                </div>
            </div>
        </>
    );
};

export default InlineEditOverlay;
