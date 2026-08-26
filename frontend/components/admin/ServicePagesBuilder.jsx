import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { 
    Plus, Trash2, Save, Loader2, Sparkles, AlertCircle, 
    CheckCircle2, Eye, ShieldAlert, Award, Zap, Globe, Search, Link, Edit3, Settings2 
} from 'lucide-react';
import { analyzeSeo } from '../../modules/seo-aeo-analyzer/v1.1/core/seoEngine';
import { analyzeAeo } from '../../modules/seo-aeo-analyzer/v1.1/core/aeoEngine';

const ServicePagesBuilder = ({ token }) => {
    const [pages, setPages] = useState([]);
    const [selectedPageId, setSelectedPageId] = useState('');
    const [selectedPage, setSelectedPage] = useState(null);
    const [activeEditorTab, setActiveEditorTab] = useState('hero'); // 'hero', 'packages', 'steps', 'reviews', 'faqs', 'seo'
    const [isLoading, setIsLoading] = useState(true);
    const [isSaving, setIsSaving] = useState(false);
    const [message, setMessage] = useState('');
    const [messageType, setMessageType] = useState('success');

    // SEO/AEO Grades state
    const [seoResult, setSeoResult] = useState({ score: 0, diagnostics: [] });
    const [aeoResult, setAeoResult] = useState({ score: 0, diagnostics: [] });

    const authConfig = { headers: { Authorization: `Bearer ${token}` } };

    const fetchPages = async () => {
        setIsLoading(true);
        try {
            const { data } = await axios.get('/api/service-pages', authConfig);
            setPages(data || []);
            if (data && data.length > 0) {
                // Default to private-limited or first available page
                const pvtLtd = data.find(p => p.pageId === 'private-limited');
                const defaultPageId = pvtLtd ? 'private-limited' : data[0].pageId;
                setSelectedPageId(defaultPageId);
                await fetchPageDetail(defaultPageId);
            } else {
                setIsLoading(false);
            }
        } catch (error) {
            console.error('Failed to load service pages list', error);
            setIsLoading(false);
        }
    };

    const fetchPageDetail = async (pageId) => {
        setIsLoading(true);
        try {
            const { data } = await axios.get(`/api/service-pages/${pageId}`, authConfig);
            setSelectedPage(data);
        } catch (error) {
            console.error('Failed to load service page configuration details', error);
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchPages();
    }, []);

    // Perform live grading analysis whenever selectedPage state modifications occur
    useEffect(() => {
        if (!selectedPage) return;
        
        // Mock current html content by serializing active page elements
        const mockHtml = `
            <div id="hero">
                <h1>${selectedPage.hero?.title || ''}</h1>
                <p>${selectedPage.hero?.subtitle || ''}</p>
                <div class="badge">${selectedPage.hero?.badgeText || ''}</div>
            </div>
            <div id="stats">
                ${(selectedPage.stats || []).map(s => `<div>${s.value} ${s.label}</div>`).join('')}
            </div>
            <div id="packages">
                ${(selectedPage.packages || []).map(p => `
                    <h2>${p.name}</h2>
                    <p>${p.description}</p>
                    <ul>${(p.features || []).map(f => `<li>${f}</li>`).join('')}</ul>
                `).join('')}
            </div>
            <div id="timeline">
                ${(selectedPage.steps || []).map(st => `
                    <h3>${st.title}</h3>
                    <p>${st.desc}</p>
                `).join('')}
            </div>
            <div id="reviews">
                ${(selectedPage.reviews || []).map(r => `<p>${r.text}</p>`).join('')}
            </div>
        `;

        const keywords = selectedPage.seoSettings?.focusKeywords || [];
        const faqList = selectedPage.faqs || [];
        const seoSettings = selectedPage.seoSettings || {};

        const seoRes = analyzeSeo(mockHtml, keywords, seoSettings);
        const aeoRes = analyzeAeo(mockHtml, keywords, faqList, seoSettings);

        setSeoResult(seoRes);
        setAeoResult(aeoRes);
    }, [selectedPage]);

    const handlePageChange = async (e) => {
        const pageId = e.target.value;
        setSelectedPageId(pageId);
        if (pageId) {
            await fetchPageDetail(pageId);
        } else {
            setSelectedPage(null);
        }
    };

    const handleCreateNewPage = async () => {
        const newPageId = prompt("Enter a unique Page ID (e.g. 'gst-registration', 'llp-registration'):");
        if (!newPageId) return;
        
        const cleanId = newPageId.trim().toLowerCase().replace(/\s+/g, '-');
        if (pages.some(p => p.pageId === cleanId)) {
            alert('A page with this ID already exists!');
            return;
        }

        setIsLoading(true);
        try {
            // Seed a new empty configuration document in the DB
            const { data } = await axios.get(`/api/service-pages/${cleanId}`, authConfig);
            setPages(prev => [...prev, data]);
            setSelectedPageId(cleanId);
            setSelectedPage(data);
            setMessage(`Page '${cleanId}' initialized successfully!`);
            setMessageType('success');
        } catch (error) {
            console.error('Failed to create service page', error);
            setMessage('Failed to initialize service page.');
            setMessageType('error');
        } finally {
            setIsLoading(false);
        }
    };

    const handleSaveConfig = async () => {
        if (!selectedPage || !selectedPageId) return;
        setIsSaving(true);
        setMessage('');
        try {
            const { data } = await axios.post(`/api/service-pages/${selectedPageId}`, selectedPage, authConfig);
            setSelectedPage(data.page);
            setMessage('Service page configuration saved successfully!');
            setMessageType('success');
            setTimeout(() => setMessage(''), 3000);
        } catch (error) {
            console.error('Failed to save page configs', error);
            setMessage(error?.response?.data?.message || 'Failed to save service page details.');
            setMessageType('error');
        } finally {
            setIsSaving(false);
        }
    };

    if (isLoading && pages.length === 0) {
        return (
            <div className="h-64 flex items-center justify-center text-slate-500">
                <Loader2 className="w-5 h-5 animate-spin mr-2" /> Loading service pages builder...
            </div>
        );
    }

    // Diagnostics filtering
    const allDiagnostics = [...seoResult.diagnostics, ...aeoResult.diagnostics];
    const errors = allDiagnostics.filter(d => d.type === 'error');
    const warnings = allDiagnostics.filter(d => d.type === 'warning');
    const passes = allDiagnostics.filter(d => d.type === 'success');

    // Score radial values
    const seoCircumference = 2 * Math.PI * 24;
    const aeoCircumference = 2 * Math.PI * 24;
    const seoOffset = seoCircumference - (seoResult.score / 100) * seoCircumference;
    const aeoOffset = aeoCircumference - (aeoResult.score / 100) * aeoCircumference;

    return (
        <div className="animate-in fade-in duration-300">
            {/* Page Header */}
            <div className="mb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="text-left">
                    <h2 className="text-2xl font-bold text-slate-800 flex items-center gap-2">
                        <Edit3 className="w-6 h-6 text-indigo-600 animate-pulse" />
                        Dynamic Page Builder & SEO/AEO Studio
                    </h2>
                    <p className="text-slate-500 text-xs">Configure landing layouts, custom packages, steps, FAQs, and real-time Answer Engine metrics.</p>
                </div>
                <div className="flex items-center gap-3">
                    <select 
                        value={selectedPageId}
                        onChange={handlePageChange}
                        className="bg-white border border-slate-300 rounded-xl px-4 py-2 text-sm font-semibold outline-none focus:border-indigo-500 shadow-sm"
                    >
                        {pages.map(p => (
                            <option key={p.pageId} value={p.pageId}>{p.title || p.pageId}</option>
                        ))}
                    </select>
                    <button
                        onClick={handleCreateNewPage}
                        className="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-xl font-bold text-sm shadow-sm transition active:scale-95 inline-flex items-center gap-1.5"
                    >
                        <Plus className="w-4 h-4" /> New Page
                    </button>
                    <button
                        onClick={handleSaveConfig}
                        disabled={isSaving || !selectedPage}
                        className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2.5 rounded-xl font-bold text-sm shadow-md disabled:opacity-60 transition active:scale-95 inline-flex items-center gap-2"
                    >
                        {isSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                        Save Configurations
                    </button>
                </div>
            </div>

            {/* Alert Message */}
            {message && (
                <div className={`mb-4 px-4 py-3 border rounded-xl text-sm font-semibold flex items-center gap-2 ${messageType === 'success' ? 'bg-emerald-50 border-emerald-200 text-emerald-800' : 'bg-rose-50 border-rose-200 text-rose-800'}`}>
                    {messageType === 'success' ? <CheckCircle2 className="w-4 h-4 text-emerald-600" /> : <AlertCircle className="w-4 h-4 text-rose-600" />}
                    {message}
                </div>
            )}

            {selectedPage && (
                <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
                    {/* Left: Tabbed configuration builder fields */}
                    <div className="xl:col-span-8 space-y-6">
                        <div className="bg-white border border-slate-200 rounded-2xl shadow-sm overflow-hidden">
                            {/* Editor Tab items */}
                            <div className="flex border-b border-slate-200 text-xs font-bold bg-slate-50/50 overflow-x-auto">
                                {[
                                    { key: 'hero', label: 'Hero & Stats' },
                                    { key: 'packages', label: 'Pricing Packages' },
                                    { key: 'steps', label: 'Timeline & Flow' },
                                    { key: 'reviews', label: 'Reviews & Stories' },
                                    { key: 'faqs', label: 'FAQs List' },
                                    { key: 'seo', label: 'SEO & Tracking Config' }
                                ].map(tab => (
                                    <button
                                        key={tab.key}
                                        onClick={() => setActiveEditorTab(tab.key)}
                                        className={`px-5 py-4 border-b-2 whitespace-nowrap transition ${activeEditorTab === tab.key ? 'border-indigo-500 text-indigo-600 bg-white' : 'border-transparent text-slate-500 hover:text-slate-700 hover:bg-slate-50/40'}`}
                                    >
                                        {tab.label}
                                    </button>
                                ))}
                            </div>

                            {/* Editor Panel content */}
                            <div className="p-6">
                                {/* TAB 1: HERO & STATS */}
                                {activeEditorTab === 'hero' && (
                                    <div className="space-y-6">
                                        <div className="grid md:grid-cols-2 gap-4">
                                            <div>
                                                <label className="block text-xs font-black uppercase text-slate-400 tracking-wider mb-2">Service title</label>
                                                <input 
                                                    value={selectedPage.title || ''}
                                                    onChange={e => setSelectedPage({ ...selectedPage, title: e.target.value })}
                                                    className="w-full border border-slate-350 rounded-xl px-4 py-2.5 text-sm font-semibold"
                                                    placeholder="e.g. Private Limited Registration"
                                                />
                                            </div>
                                            <div>
                                                <label className="block text-xs font-black uppercase text-slate-400 tracking-wider mb-2">Badge text</label>
                                                <input 
                                                    value={selectedPage.hero?.badgeText || ''}
                                                    onChange={e => setSelectedPage({ ...selectedPage, hero: { ...selectedPage.hero, badgeText: e.target.value } })}
                                                    className="w-full border border-slate-350 rounded-xl px-4 py-2.5 text-sm"
                                                    placeholder="India's #1 Secure Registration Platform"
                                                />
                                            </div>
                                        </div>

                                        <div className="grid md:grid-cols-2 gap-4">
                                            <div className="md:col-span-2">
                                                <label className="block text-xs font-black uppercase text-slate-400 tracking-wider mb-2">Hero Headline</label>
                                                <input 
                                                    value={selectedPage.hero?.title || ''}
                                                    onChange={e => setSelectedPage({ ...selectedPage, hero: { ...selectedPage.hero, title: e.target.value } })}
                                                    className="w-full border border-slate-350 rounded-xl px-4 py-2.5 text-sm font-bold text-slate-900"
                                                    placeholder="Hero Title"
                                                />
                                            </div>
                                            <div className="md:col-span-2">
                                                <label className="block text-xs font-black uppercase text-slate-400 tracking-wider mb-2">Hero Subtitle</label>
                                                <textarea 
                                                    value={selectedPage.hero?.subtitle || ''}
                                                    onChange={e => setSelectedPage({ ...selectedPage, hero: { ...selectedPage.hero, subtitle: e.target.value } })}
                                                    className="w-full border border-slate-350 rounded-xl px-4 py-2.5 text-sm h-20 outline-none resize-none"
                                                    placeholder="Hero Subtitle Tagline"
                                                />
                                            </div>
                                        </div>

                                        {/* Performance statistics */}
                                        <div>
                                            <h4 className="font-bold text-slate-800 text-sm mb-3">Core Performance Stats (Horizontal Grid)</h4>
                                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                                {(selectedPage.stats || [
                                                    { value: '7 Days', label: 'Avg. Turnaround' },
                                                    { value: '5000+', label: 'Happy Founders' },
                                                    { value: '4.9/5', label: 'Google Rating' },
                                                    { value: '100%', label: 'Online Process' }
                                                ]).map((stat, idx) => (
                                                    <div key={idx} className="bg-slate-50 p-4 border border-slate-200 rounded-2xl text-center space-y-2">
                                                        <input 
                                                            value={stat.value}
                                                            onChange={e => {
                                                                const newStats = [...(selectedPage.stats || [])];
                                                                newStats[idx] = { ...newStats[idx], value: e.target.value };
                                                                setSelectedPage({ ...selectedPage, stats: newStats });
                                                            }}
                                                            className="w-full border border-slate-300 rounded-lg px-2 py-1 text-xs font-black text-center"
                                                            placeholder="Stat Value (e.g. 7 Days)"
                                                        />
                                                        <input 
                                                            value={stat.label}
                                                            onChange={e => {
                                                                const newStats = [...(selectedPage.stats || [])];
                                                                newStats[idx] = { ...newStats[idx], label: e.target.value };
                                                                setSelectedPage({ ...selectedPage, stats: newStats });
                                                            }}
                                                            className="w-full border border-slate-300 rounded-lg px-2 py-1 text-[10px] text-slate-500 font-bold text-center"
                                                            placeholder="Stat Label (e.g. Turnaround)"
                                                        />
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    </div>
                                )}

                                {/* TAB 2: PRICING PACKAGES */}
                                {activeEditorTab === 'packages' && (
                                    <div className="space-y-6">
                                        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                                            <div>
                                                <h3 className="font-bold text-slate-800 text-sm">Interactive Service Packages</h3>
                                                <p className="text-slate-500 text-[11px] mt-0.5">Customize price points and features. All price alterations auto-update web and Android app layouts instantly.</p>
                                            </div>
                                            <button
                                                onClick={() => {
                                                    const newPkgs = [...(selectedPage.packages || [])];
                                                    newPkgs.push({
                                                        id: `pkg-${Date.now()}`,
                                                        name: 'Custom Tier',
                                                        price: 999,
                                                        description: 'Brand new package description',
                                                        features: ['Feature 1', 'Feature 2'],
                                                        buttonText: 'Get Started'
                                                    });
                                                    setSelectedPage({ ...selectedPage, packages: newPkgs });
                                                }}
                                                className="bg-indigo-50 border border-indigo-150 text-indigo-700 px-3.5 py-1.5 rounded-lg text-xs font-bold inline-flex items-center gap-1"
                                            >
                                                <Plus className="w-3.5 h-3.5" /> Add Package
                                            </button>
                                        </div>

                                        <div className="space-y-4">
                                            {(selectedPage.packages || []).map((pkg, idx) => (
                                                <div key={pkg.id || idx} className="bg-slate-50 border border-slate-200 rounded-2xl p-5 relative hover:border-indigo-300 transition duration-300">
                                                    <button
                                                        onClick={() => {
                                                            const newPkgs = (selectedPage.packages || []).filter((_, i) => i !== idx);
                                                            setSelectedPage({ ...selectedPage, packages: newPkgs });
                                                        }}
                                                        className="absolute top-4 right-4 text-xs font-bold text-rose-600 hover:underline"
                                                    >
                                                        Delete
                                                    </button>

                                                    <div className="grid md:grid-cols-3 gap-4 mb-4">
                                                        <div>
                                                            <label className="block text-[10px] font-black uppercase text-slate-500 tracking-wider mb-1.5">Package Name</label>
                                                            <input 
                                                                value={pkg.name}
                                                                onChange={e => {
                                                                    const newPkgs = [...(selectedPage.packages || [])];
                                                                    newPkgs[idx] = { ...newPkgs[idx], name: e.target.value };
                                                                    setSelectedPage({ ...selectedPage, packages: newPkgs });
                                                                }}
                                                                className="w-full border border-slate-300 rounded-lg px-3 py-1.5 text-xs font-bold text-slate-800"
                                                            />
                                                        </div>
                                                        <div>
                                                            <label className="block text-[10px] font-black uppercase text-slate-500 tracking-wider mb-1.5">Pricing (₹)</label>
                                                            <input 
                                                                type="number"
                                                                value={pkg.price}
                                                                onChange={e => {
                                                                    const newPkgs = [...(selectedPage.packages || [])];
                                                                    newPkgs[idx] = { ...newPkgs[idx], price: Number(e.target.value) };
                                                                    setSelectedPage({ ...selectedPage, packages: newPkgs });
                                                                }}
                                                                className="w-full border border-slate-300 rounded-lg px-3 py-1.5 text-xs font-black text-slate-800"
                                                            />
                                                        </div>
                                                        <div>
                                                            <label className="block text-[10px] font-black uppercase text-slate-500 tracking-wider mb-1.5">CTA Button Text</label>
                                                            <input 
                                                                value={pkg.buttonText || 'Select Plan'}
                                                                onChange={e => {
                                                                    const newPkgs = [...(selectedPage.packages || [])];
                                                                    newPkgs[idx] = { ...newPkgs[idx], buttonText: e.target.value };
                                                                    setSelectedPage({ ...selectedPage, packages: newPkgs });
                                                                }}
                                                                className="w-full border border-slate-300 rounded-lg px-3 py-1.5 text-xs text-slate-700"
                                                            />
                                                        </div>
                                                    </div>

                                                    <div className="grid md:grid-cols-2 gap-4 mb-4">
                                                        <div className="md:col-span-2">
                                                            <label className="block text-[10px] font-black uppercase text-slate-500 tracking-wider mb-1.5">Tier Description</label>
                                                            <input 
                                                                value={pkg.description || ''}
                                                                onChange={e => {
                                                                    const newPkgs = [...(selectedPage.packages || [])];
                                                                    newPkgs[idx] = { ...newPkgs[idx], description: e.target.value };
                                                                    setSelectedPage({ ...selectedPage, packages: newPkgs });
                                                                }}
                                                                className="w-full border border-slate-300 rounded-lg px-3 py-1.5 text-xs text-slate-600"
                                                            />
                                                        </div>
                                                    </div>

                                                    {/* Features checklist */}
                                                    <div>
                                                        <div className="flex items-center justify-between mb-2">
                                                            <span className="text-[10px] font-black uppercase text-slate-500 tracking-wider">Checklist Features</span>
                                                            <button
                                                                onClick={() => {
                                                                    const newPkgs = [...(selectedPage.packages || [])];
                                                                    newPkgs[idx].features = [...(newPkgs[idx].features || []), ''];
                                                                    setSelectedPage({ ...selectedPage, packages: newPkgs });
                                                                }}
                                                                className="text-[10px] font-bold text-indigo-600 inline-flex items-center gap-0.5"
                                                            >
                                                                <Plus className="w-3 h-3" /> Add Feature
                                                            </button>
                                                        </div>
                                                        <div className="space-y-2 max-h-[160px] overflow-y-auto pr-1">
                                                            {(pkg.features || []).map((feat, fIdx) => (
                                                                <div key={fIdx} className="flex gap-2">
                                                                    <input 
                                                                        value={feat}
                                                                        onChange={e => {
                                                                            const newPkgs = [...(selectedPage.packages || [])];
                                                                            newPkgs[idx].features[fIdx] = e.target.value;
                                                                            setSelectedPage({ ...selectedPage, packages: newPkgs });
                                                                        }}
                                                                        className="flex-1 border border-slate-300 rounded-md px-2.5 py-1 text-xs"
                                                                        placeholder="Feature detail"
                                                                    />
                                                                    <button
                                                                        onClick={() => {
                                                                            const newPkgs = [...(selectedPage.packages || [])];
                                                                            newPkgs[idx].features = newPkgs[idx].features.filter((_, fi) => fi !== fIdx);
                                                                            setSelectedPage({ ...selectedPage, packages: newPkgs });
                                                                        }}
                                                                        className="p-1 text-rose-600 hover:bg-rose-50 rounded"
                                                                    >
                                                                        <Trash2 className="w-3.5 h-3.5" />
                                                                    </button>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* TAB 3: TIMELINE & FLOW */}
                                {activeEditorTab === 'steps' && (
                                    <div className="space-y-6">
                                        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                                            <div>
                                                <h3 className="font-bold text-slate-800 text-sm">Visual Timeline Steps (Incorporation Flow)</h3>
                                                <p className="text-slate-500 text-[11px]">Configure sequential delivery checkpoints. Best kept to exactly 3 distinct highlights.</p>
                                            </div>
                                            <button
                                                onClick={() => {
                                                    const newSteps = [...(selectedPage.steps || [])];
                                                    newSteps.push({ number: `0${newSteps.length + 1}`, badge: 'Takes 1 Day', title: 'New step checkpoint', desc: 'Description of the step' });
                                                    setSelectedPage({ ...selectedPage, steps: newSteps });
                                                }}
                                                className="bg-indigo-50 border border-indigo-150 text-indigo-700 px-3.5 py-1.5 rounded-lg text-xs font-bold inline-flex items-center gap-1"
                                            >
                                                <Plus className="w-3.5 h-3.5" /> Add Step
                                            </button>
                                        </div>

                                        <div className="space-y-4">
                                            {(selectedPage.steps || []).map((step, idx) => (
                                                <div key={idx} className="bg-slate-50 border border-slate-200 rounded-2xl p-4 relative flex gap-4">
                                                    <button
                                                        onClick={() => {
                                                            const newSteps = (selectedPage.steps || []).filter((_, i) => i !== idx);
                                                            setSelectedPage({ ...selectedPage, steps: newSteps });
                                                        }}
                                                        className="absolute top-4 right-4 text-xs text-rose-600 font-bold hover:underline"
                                                    >
                                                        Delete
                                                    </button>
                                                    <div className="w-12 h-12 rounded-xl bg-indigo-600 text-white flex items-center justify-center font-black text-lg flex-shrink-0">
                                                        {step.number}
                                                    </div>
                                                    <div className="flex-1 grid md:grid-cols-2 gap-3 pr-8">
                                                        <div>
                                                            <label className="block text-[10px] font-black uppercase text-slate-500 tracking-wider mb-1">Step Badge</label>
                                                            <input 
                                                                value={step.badge}
                                                                onChange={e => {
                                                                    const newSteps = [...(selectedPage.steps || [])];
                                                                    newSteps[idx] = { ...newSteps[idx], badge: e.target.value };
                                                                    setSelectedPage({ ...selectedPage, steps: newSteps });
                                                                }}
                                                                className="w-full border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs font-semibold"
                                                                placeholder="e.g. Takes 15 Mins"
                                                            />
                                                        </div>
                                                        <div>
                                                            <label className="block text-[10px] font-black uppercase text-slate-500 tracking-wider mb-1">Step Title</label>
                                                            <input 
                                                                value={step.title}
                                                                onChange={e => {
                                                                    const newSteps = [...(selectedPage.steps || [])];
                                                                    newSteps[idx] = { ...newSteps[idx], title: e.target.value };
                                                                    setSelectedPage({ ...selectedPage, steps: newSteps });
                                                                }}
                                                                className="w-full border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs font-bold text-slate-800"
                                                            />
                                                        </div>
                                                        <div className="md:col-span-2">
                                                            <label className="block text-[10px] font-black uppercase text-slate-500 tracking-wider mb-1">Step Description</label>
                                                            <input 
                                                                value={step.desc}
                                                                onChange={e => {
                                                                    const newSteps = [...(selectedPage.steps || [])];
                                                                    newSteps[idx] = { ...newSteps[idx], desc: e.target.value };
                                                                    setSelectedPage({ ...selectedPage, steps: newSteps });
                                                                }}
                                                                className="w-full border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs text-slate-600"
                                                                placeholder="Detailed description of process step..."
                                                            />
                                                        </div>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* TAB 4: REVIEWS & SUCCESS STORIES */}
                                {activeEditorTab === 'reviews' && (
                                    <div className="space-y-6">
                                        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                                            <div>
                                                <h3 className="font-bold text-slate-800 text-sm">Customer Reviews & Success Stories</h3>
                                                <p className="text-slate-500 text-[11px]">Dynamic customer reviews list. Fully verifiable on SERPs.</p>
                                            </div>
                                            <button
                                                onClick={() => {
                                                    const newRevs = [...(selectedPage.reviews || [])];
                                                    newRevs.push({ rating: 5, date: 'Today', name: 'New Founder', company: 'My Startup Pvt Ltd', avatar: 'NF', text: 'Amazing review here...', verified: true });
                                                    setSelectedPage({ ...selectedPage, reviews: newRevs });
                                                }}
                                                className="bg-indigo-50 border border-indigo-150 text-indigo-700 px-3.5 py-1.5 rounded-lg text-xs font-bold inline-flex items-center gap-1"
                                            >
                                                <Plus className="w-3.5 h-3.5" /> Add Review
                                            </button>
                                        </div>

                                        <div className="space-y-4 max-h-[480px] overflow-y-auto pr-1">
                                            {(selectedPage.reviews || []).map((review, idx) => (
                                                <div key={idx} className="bg-slate-50 border border-slate-200 rounded-2xl p-4 relative">
                                                    <button
                                                        onClick={() => {
                                                            const newRevs = (selectedPage.reviews || []).filter((_, i) => i !== idx);
                                                            setSelectedPage({ ...selectedPage, reviews: newRevs });
                                                        }}
                                                        className="absolute top-4 right-4 text-xs text-rose-600 font-bold hover:underline"
                                                    >
                                                        Delete
                                                    </button>
                                                    <div className="grid md:grid-cols-4 gap-3 mb-3">
                                                        <div>
                                                            <label className="block text-[10px] font-black uppercase text-slate-500 tracking-wider mb-1">Author Name</label>
                                                            <input 
                                                                value={review.name}
                                                                onChange={e => {
                                                                    const newRevs = [...(selectedPage.reviews || [])];
                                                                    newRevs[idx] = { ...newRevs[idx], name: e.target.value, avatar: e.target.value.split(' ').map(w => w.charAt(0)).join('').toUpperCase().slice(0, 2) };
                                                                    setSelectedPage({ ...selectedPage, reviews: newRevs });
                                                                }}
                                                                className="w-full border border-slate-300 rounded-lg px-2 py-1 text-xs font-semibold"
                                                            />
                                                        </div>
                                                        <div>
                                                            <label className="block text-[10px] font-black uppercase text-slate-500 tracking-wider mb-1">Company</label>
                                                            <input 
                                                                value={review.company}
                                                                onChange={e => {
                                                                    const newRevs = [...(selectedPage.reviews || [])];
                                                                    newRevs[idx] = { ...newRevs[idx], company: e.target.value };
                                                                    setSelectedPage({ ...selectedPage, reviews: newRevs });
                                                                }}
                                                                className="w-full border border-slate-300 rounded-lg px-2 py-1 text-xs font-semibold"
                                                            />
                                                        </div>
                                                        <div>
                                                            <label className="block text-[10px] font-black uppercase text-slate-500 tracking-wider mb-1">Review Date</label>
                                                            <input 
                                                                value={review.date || 'Recently'}
                                                                onChange={e => {
                                                                    const newRevs = [...(selectedPage.reviews || [])];
                                                                    newRevs[idx] = { ...newRevs[idx], date: e.target.value };
                                                                    setSelectedPage({ ...selectedPage, reviews: newRevs });
                                                                }}
                                                                className="w-full border border-slate-300 rounded-lg px-2 py-1 text-xs"
                                                            />
                                                        </div>
                                                        <div>
                                                            <label className="block text-[10px] font-black uppercase text-slate-500 tracking-wider mb-1">Rating (Stars)</label>
                                                            <input 
                                                                type="number"
                                                                max="5"
                                                                min="1"
                                                                value={review.rating}
                                                                onChange={e => {
                                                                    const newRevs = [...(selectedPage.reviews || [])];
                                                                    newRevs[idx] = { ...newRevs[idx], rating: Number(e.target.value) };
                                                                    setSelectedPage({ ...selectedPage, reviews: newRevs });
                                                                }}
                                                                className="w-full border border-slate-300 rounded-lg px-2 py-1 text-xs font-bold"
                                                            />
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <label className="block text-[10px] font-black uppercase text-slate-500 tracking-wider mb-1">Review Text</label>
                                                        <textarea 
                                                            value={review.text}
                                                            onChange={e => {
                                                                const newRevs = [...(selectedPage.reviews || [])];
                                                                newRevs[idx] = { ...newRevs[idx], text: e.target.value };
                                                                setSelectedPage({ ...selectedPage, reviews: newRevs });
                                                            }}
                                                            className="w-full border border-slate-300 rounded-lg px-3 py-1.5 text-xs outline-none h-16 resize-none"
                                                        />
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* TAB 5: FAQs LIST */}
                                {activeEditorTab === 'faqs' && (
                                    <div className="space-y-6">
                                        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                                            <div>
                                                <h3 className="font-bold text-slate-800 text-sm">Frequently Asked Questions</h3>
                                                <p className="text-slate-500 text-[11px]">Structured Q&A database. Generates structured JSON-LD schemas automatically to power SGE and Perplexity features.</p>
                                            </div>
                                            <button
                                                onClick={() => {
                                                    const newFaqs = [...(selectedPage.faqs || [])];
                                                    newFaqs.push({ q: 'What is the question?', a: 'Here is the direct answer.' });
                                                    setSelectedPage({ ...selectedPage, faqs: newFaqs });
                                                }}
                                                className="bg-indigo-50 border border-indigo-150 text-indigo-700 px-3.5 py-1.5 rounded-lg text-xs font-bold inline-flex items-center gap-1"
                                            >
                                                <Plus className="w-3.5 h-3.5" /> Add FAQ
                                            </button>
                                        </div>

                                        <div className="space-y-4 max-h-[480px] overflow-y-auto pr-1">
                                            {(selectedPage.faqs || []).map((faq, idx) => (
                                                <div key={idx} className="bg-slate-50 border border-slate-200 rounded-2xl p-4 relative space-y-3">
                                                    <button
                                                        onClick={() => {
                                                            const newFaqs = (selectedPage.faqs || []).filter((_, i) => i !== idx);
                                                            setSelectedPage({ ...selectedPage, faqs: newFaqs });
                                                        }}
                                                        className="absolute top-4 right-4 text-xs text-rose-600 font-bold hover:underline"
                                                    >
                                                        Delete
                                                    </button>
                                                    <div>
                                                        <label className="block text-[10px] font-black uppercase text-slate-500 tracking-wider mb-1">Question (Q)</label>
                                                        <input 
                                                            value={faq.q}
                                                            onChange={e => {
                                                                const newFaqs = [...(selectedPage.faqs || [])];
                                                                newFaqs[idx] = { ...newFaqs[idx], q: e.target.value };
                                                                setSelectedPage({ ...selectedPage, faqs: newFaqs });
                                                            }}
                                                            className="w-full border border-slate-300 rounded-lg px-3 py-1.5 text-xs font-bold text-slate-800 bg-white"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-[10px] font-black uppercase text-slate-500 tracking-wider mb-1">Answer (A)</label>
                                                        <textarea 
                                                            value={faq.a}
                                                            onChange={e => {
                                                                const newFaqs = [...(selectedPage.faqs || [])];
                                                                newFaqs[idx] = { ...newFaqs[idx], a: e.target.value };
                                                                setSelectedPage({ ...selectedPage, faqs: newFaqs });
                                                            }}
                                                            className="w-full border border-slate-300 rounded-lg px-3 py-1.5 text-xs text-slate-600 outline-none h-16 resize-none bg-white"
                                                        />
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* TAB 6: SEO & AEO & TRACKING CONFIG */}
                                {activeEditorTab === 'seo' && (
                                    <div className="space-y-6 animate-in fade-in duration-300">
                                        <div className="border-b border-slate-100 pb-3 flex items-center justify-between">
                                            <div>
                                                <h3 className="font-bold text-slate-800 text-sm">On-Page SEO & Tracking Configuration</h3>
                                                <p className="text-slate-500 text-[11px]">Manage search visibility variables, tag setups (GA4 / Pixel), and direct Answer Citation structures.</p>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <Settings2 className="w-5 h-5 text-indigo-500" />
                                            </div>
                                        </div>

                                        <div className="space-y-4">
                                            {/* Focus Keywords */}
                                            <div>
                                                <label className="block text-xs font-black uppercase text-slate-500 tracking-wider mb-2 flex items-center gap-1">
                                                    Search Focus Keywords (Separated by commas)
                                                </label>
                                                <input 
                                                    value={(selectedPage.seoSettings?.focusKeywords || []).join(', ')}
                                                    onChange={e => {
                                                        const kws = e.target.value.split(',').map(k => k.trim()).filter(Boolean);
                                                        setSelectedPage({ 
                                                            ...selectedPage, 
                                                            seoSettings: { ...selectedPage.seoSettings, focusKeywords: kws } 
                                                        });
                                                    }}
                                                    className="w-full border border-slate-300 rounded-xl px-4 py-2.5 text-sm text-slate-850 font-bold"
                                                    placeholder="e.g. Private Limited Company, Company Registration"
                                                />
                                            </div>

                                            {/* Meta Tags */}
                                            <div className="grid md:grid-cols-2 gap-4">
                                                <div className="md:col-span-2">
                                                    <label className="block text-xs font-black uppercase text-slate-500 tracking-wider mb-2">Meta Title Tag (SERP Title)</label>
                                                    <input 
                                                        value={selectedPage.seoSettings?.titleTag || ''}
                                                        onChange={e => setSelectedPage({ 
                                                            ...selectedPage, 
                                                            seoSettings: { ...selectedPage.seoSettings, titleTag: e.target.value } 
                                                        })}
                                                        className="w-full border border-slate-300 rounded-xl px-4 py-2.5 text-sm font-semibold text-slate-900"
                                                        placeholder="Title Tag value..."
                                                    />
                                                </div>
                                                <div className="md:col-span-2">
                                                    <label className="block text-xs font-black uppercase text-slate-500 tracking-wider mb-2">Meta Description Tag</label>
                                                    <textarea 
                                                        value={selectedPage.seoSettings?.metaDescription || ''}
                                                        onChange={e => setSelectedPage({ 
                                                            ...selectedPage, 
                                                            seoSettings: { ...selectedPage.seoSettings, metaDescription: e.target.value } 
                                                        })}
                                                        className="w-full border border-slate-300 rounded-xl px-4 py-2.5 text-sm outline-none h-20 resize-none"
                                                        placeholder="Enter descriptive metadata snippet..."
                                                    />
                                                </div>
                                            </div>

                                            {/* Tracking Scripts Configurations */}
                                            <div className="p-5 bg-indigo-50/40 border border-indigo-100 rounded-2xl space-y-4">
                                                <h4 className="font-bold text-slate-800 text-xs uppercase tracking-wider flex items-center gap-1.5">
                                                    <Globe className="w-4 h-4 text-indigo-600 animate-spin-slow" />
                                                    Public Visitor Tracking Tag Integrations
                                                </h4>
                                                <div className="grid md:grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="block text-[10px] font-black uppercase text-slate-500 tracking-wider mb-1.5">Google Analytics (GA4) measurement ID</label>
                                                        <input 
                                                            value={selectedPage.trackingSettings?.googleAnalyticsId || ''}
                                                            onChange={e => setSelectedPage({
                                                                ...selectedPage,
                                                                trackingSettings: { ...selectedPage.trackingSettings, googleAnalyticsId: e.target.value }
                                                            })}
                                                            className="w-full border border-slate-300 rounded-lg px-3 py-2 text-xs font-semibold"
                                                            placeholder="G-XXXXXXXXXX"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-[10px] font-black uppercase text-slate-500 tracking-wider mb-1.5">Meta Pixel ID</label>
                                                        <input 
                                                            value={selectedPage.trackingSettings?.metaPixelId || ''}
                                                            onChange={e => setSelectedPage({
                                                                ...selectedPage,
                                                                trackingSettings: { ...selectedPage.trackingSettings, metaPixelId: e.target.value }
                                                            })}
                                                            className="w-full border border-slate-300 rounded-lg px-3 py-2 text-xs font-semibold"
                                                            placeholder="e.g. 157294657193740"
                                                        />
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Right: Real-time visual SEO/AEO analysis results grades preview */}
                    <div className="xl:col-span-4 space-y-6">
                        {/* 1. Real-Time Grader Rings */}
                        <div className="bg-slate-900 border border-slate-800 rounded-3xl p-5 text-white shadow-xl relative overflow-hidden">
                            <div className="absolute top-0 right-0 p-4 opacity-5">
                                <Sparkles className="w-24 h-24" />
                            </div>
                            <h3 className="font-bold text-xs uppercase tracking-widest text-cyan-300 mb-4 flex items-center gap-1.5">
                                <Zap className="w-4 h-4 text-cyan-400" />
                                Real-Time Scoring Audits
                            </h3>

                            <div className="grid grid-cols-2 gap-4">
                                {/* SEO Score Radial */}
                                <div className="bg-slate-950/40 p-4 rounded-2xl border border-slate-800 flex flex-col items-center justify-center text-center">
                                    <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest mb-2">SEO Score</span>
                                    <div className="relative w-14 h-14 flex items-center justify-center">
                                        <svg className="w-full h-full transform -rotate-90">
                                            <circle cx="28" cy="28" r="24" stroke="#1e293b" strokeWidth="3" fill="transparent" />
                                            <circle cx="28" cy="28" r="24" stroke={seoResult.score > 70 ? '#10b981' : seoResult.score > 40 ? '#f59e0b' : '#ef4444'} strokeWidth="3" fill="transparent" strokeDasharray={seoCircumference} strokeDashoffset={seoOffset} strokeLinecap="round" className="transition-all duration-700" />
                                        </svg>
                                        <span className="absolute font-black text-xs text-white">{seoResult.score}</span>
                                    </div>
                                    <span className="text-[9px] text-slate-500 font-bold uppercase mt-2">Traditional</span>
                                </div>

                                {/* AEO Score Radial */}
                                <div className="bg-slate-950/40 p-4 rounded-2xl border border-slate-800 flex flex-col items-center justify-center text-center">
                                    <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest mb-2">AEO Score</span>
                                    <div className="relative w-14 h-14 flex items-center justify-center">
                                        <svg className="w-full h-full transform -rotate-90">
                                            <circle cx="28" cy="28" r="24" stroke="#1e293b" strokeWidth="3" fill="transparent" />
                                            <circle cx="28" cy="28" r="24" stroke={aeoResult.score > 70 ? '#818cf8' : aeoResult.score > 40 ? '#f59e0b' : '#ef4444'} strokeWidth="3" fill="transparent" strokeDasharray={aeoCircumference} strokeDashoffset={aeoOffset} strokeLinecap="round" className="transition-all duration-700" />
                                        </svg>
                                        <span className="absolute font-black text-xs text-white">{aeoResult.score}</span>
                                    </div>
                                    <span className="text-[9px] text-slate-500 font-bold uppercase mt-2">AI Search (SGE)</span>
                                </div>
                            </div>

                            {/* Scoring checklist audit items */}
                            <div className="mt-4 border-t border-slate-800/80 pt-4 space-y-2">
                                <div className="text-[10px] font-black text-slate-400 uppercase tracking-wider mb-2">Optimization Warnings ({errors.length + warnings.length})</div>
                                <div className="space-y-1.5 max-h-[160px] overflow-y-auto pr-1 text-left">
                                    {[...errors, ...warnings].slice(0, 4).map((diag, idx) => (
                                        <div key={idx} className="flex gap-2 text-[10px] leading-relaxed text-slate-350 p-1.5 bg-slate-950/20 rounded border border-slate-850">
                                            {diag.type === 'error' ? <ShieldAlert className="w-3.5 h-3.5 text-rose-500 flex-shrink-0" /> : <AlertCircle className="w-3.5 h-3.5 text-amber-500 flex-shrink-0" />}
                                            <div>
                                                <span className="font-bold text-slate-200">{diag.label}: </span>
                                                <span>{diag.message}</span>
                                            </div>
                                        </div>
                                    ))}
                                    {errors.length + warnings.length === 0 && (
                                        <p className="text-[10px] text-emerald-400 font-bold italic text-center py-2">Fantastic! 100% optimized for traditional and AI search engines.</p>
                                    )}
                                </div>
                            </div>
                        </div>

                        {/* 2. Google Search Snippet Mockup Preview */}
                        <div className="bg-white border border-slate-200 rounded-3xl p-5 shadow-sm space-y-4 text-left">
                            <h3 className="font-bold text-xs uppercase tracking-wider text-slate-700 flex items-center gap-1.5">
                                <Eye className="w-4 h-4 text-indigo-500" />
                                Google SERP Snippet Preview
                            </h3>
                            <div className="border border-slate-100 p-4 rounded-2xl bg-slate-50/50 font-sans">
                                <div className="text-[10px] text-slate-500 flex items-center gap-1 font-medium">
                                    <span>https://vrhere.in</span>
                                    <ChevronRightIcon />
                                    <span>{selectedPageId}</span>
                                </div>
                                <div className="text-indigo-800 text-sm font-semibold mt-1 leading-snug truncate">
                                    {selectedPage.seoSettings?.titleTag || `${selectedPage.title || 'Service Details'} | VR Here`}
                                </div>
                                <div className="text-[11px] text-slate-650 leading-relaxed mt-1 font-medium">
                                    {selectedPage.seoSettings?.metaDescription || 'Add a Meta Description config to evaluate search snippets rendering profiles.'}
                                </div>
                            </div>
                        </div>

                        {/* 3. AI Citations Synthesis Preview */}
                        <div className="bg-slate-900 border border-slate-850 rounded-3xl p-5 text-white shadow-xl space-y-4 text-left">
                            <h3 className="font-bold text-xs uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                                <Award className="w-4 h-4 text-cyan-400 animate-pulse" />
                                AI Answer Synthesis citation (Mockup)
                            </h3>
                            <div className="space-y-3 font-sans">
                                <div className="flex items-center gap-2">
                                    <div className="bg-indigo-500/10 text-indigo-400 w-5 h-5 rounded flex items-center justify-center font-bold text-[9px] border border-indigo-500/10">AI</div>
                                    <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">Perplexity/Gemini Summary</span>
                                </div>
                                <p className="text-xs text-slate-300 leading-relaxed font-semibold">
                                    {selectedPage.seoSettings?.focusKeywords?.[0] ? (
                                        `Yes, VR Here provides detailed options for ${selectedPage.title || 'this service'}. Their focus packages cover dynamic customizable options. According to specifications, they provide expert advisory call checklists and full compliance setups.`
                                    ) : (
                                        'Set a focus keyword in your SEO settings tab to synthesize an AI answer engine citation mockup.'
                                    )}
                                </p>
                                <div className="flex items-center gap-2 pt-2 border-t border-slate-800/80">
                                    <span className="text-[8px] font-bold text-slate-500 uppercase tracking-widest">Cited sources:</span>
                                    <div className="inline-flex items-center gap-1 bg-indigo-500/10 text-indigo-400 text-[9px] font-bold px-2 py-0.5 rounded border border-indigo-500/20 cursor-default">
                                        <span>1. vrhere.in</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

const ChevronRightIcon = () => (
    <svg className="w-2 h-2 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
    </svg>
);

export default ServicePagesBuilder;
