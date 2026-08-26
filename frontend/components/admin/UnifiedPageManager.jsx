import React, { useEffect, useState } from 'react';
import axios from 'axios';
import {
    FileText, Plus, Trash2, Save, RefreshCw, CheckCircle2, AlertTriangle, Info, Globe, Eye, MapPin, Search, Layers, Loader2, Sparkles
} from 'lucide-react';
import { analyzeOnPageSeo } from '../../utils/onPageSeoAnalyzer';
import CityManager from './CityManager';

const UnifiedPageManager = ({ token }) => {
    const [viewMode, setViewMode] = useState('pages'); // 'pages' or 'cities'
    const [pages, setPages] = useState([]);
    const [selectedPageId, setSelectedPageId] = useState('private-limited');
    const [pageConfig, setPageConfig] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [isSaving, setIsSaving] = useState(false);
    const [message, setMessage] = useState({ text: '', type: '' });

    const authConfig = { headers: { Authorization: `Bearer ${token}` } };

    const fetchAllPages = async () => {
        try {
            const { data } = await axios.get('/api/service-pages');
            if (Array.isArray(data)) {
                setPages(data);
            }
        } catch (err) {
            console.error('Failed to load service pages list', err);
        }
    };

    const fetchPageDetail = async (pageId) => {
        setIsLoading(true);
        try {
            const { data } = await axios.get(`/api/service-pages/${pageId}`);
            setPageConfig({
                pageId: data.pageId || pageId,
                title: data.title || '',
                description: data.description || '',
                hero: {
                    title: data.hero?.title || '',
                    subtitle: data.hero?.subtitle || '',
                    badgeText: data.hero?.badgeText || "India's #1 Secure Registration Platform",
                    consultationPrice: data.hero?.consultationPrice || 499
                },
                packages: Array.isArray(data.packages) ? data.packages : [],
                faqs: Array.isArray(data.faqs) ? data.faqs : [],
                steps: Array.isArray(data.steps) ? data.steps : [],
                seoSettings: {
                    titleTag: data.seoSettings?.titleTag || '',
                    metaDescription: data.seoSettings?.metaDescription || '',
                    focusKeywords: Array.isArray(data.seoSettings?.focusKeywords) ? data.seoSettings.focusKeywords : ['']
                },
                enableCityPages: data.enableCityPages !== undefined ? data.enableCityPages : true,
                headerNavSync: {
                    enabled: data.headerNavSync?.enabled || false,
                    category: data.headerNavSync?.category || 'Business Registrations',
                    column: data.headerNavSync?.column || 'Company Formation'
                }
            });
        } catch (err) {
            console.error(`Failed to load page config for ${pageId}`, err);
            setMessage({ text: `Failed to load page data.`, type: 'error' });
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchAllPages();
    }, []);

    useEffect(() => {
        if (selectedPageId) {
            fetchPageDetail(selectedPageId);
        }
    }, [selectedPageId]);

    const handleSavePage = async () => {
        setIsSaving(true);
        setMessage({ text: '', type: '' });
        try {
            await axios.post(`/api/service-pages/${pageConfig.pageId}`, pageConfig, authConfig);
            setMessage({ text: `Page "${pageConfig.title}" saved successfully!`, type: 'success' });
            fetchAllPages();
        } catch (err) {
            console.error('Failed to save page', err);
            setMessage({ text: err.response?.data?.message || 'Error saving page config', type: 'error' });
        } finally {
            setIsSaving(false);
        }
    };

    // Calculate Yoast SEO Score dynamically
    const focusKeyword = pageConfig?.seoSettings?.focusKeywords?.[0] || '';
    const fullTextContent = `${pageConfig?.hero?.title || ''} ${pageConfig?.hero?.subtitle || ''} ${(pageConfig?.packages || []).map(p => p.description + ' ' + (p.features || []).join(' ')).join(' ')} ${(pageConfig?.faqs || []).map(f => f.q + ' ' + f.a).join(' ')}`;

    const seoAnalysis = analyzeOnPageSeo({
        focusKeyword,
        titleTag: pageConfig?.seoSettings?.titleTag || pageConfig?.title || '',
        metaDescription: pageConfig?.seoSettings?.metaDescription || pageConfig?.description || '',
        pageContent: fullTextContent,
        slug: pageConfig?.pageId || ''
    });

    return (
        <div className="space-y-6">
            {/* Top Bar Switcher */}
            <div className="flex flex-wrap items-center justify-between gap-4 bg-white p-4 rounded-2xl border border-slate-200 shadow-xs">
                <div className="flex items-center gap-2 bg-slate-100 p-1 rounded-xl">
                    <button
                        onClick={() => setViewMode('pages')}
                        className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition ${viewMode === 'pages' ? 'bg-white text-indigo-600 shadow-xs' : 'text-slate-600 hover:text-slate-900'}`}
                    >
                        <FileText className="w-4 h-4" />
                        Service Pages & SEO
                    </button>
                    <button
                        onClick={() => setViewMode('cities')}
                        className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition ${viewMode === 'cities' ? 'bg-white text-indigo-600 shadow-xs' : 'text-slate-600 hover:text-slate-900'}`}
                    >
                        <MapPin className="w-4 h-4" />
                        Master City Catalog
                    </button>
                </div>

                {viewMode === 'pages' && (
                    <div className="flex items-center gap-3">
                        <select
                            value={selectedPageId}
                            onChange={(e) => setSelectedPageId(e.target.value)}
                            className="px-3.5 py-2 rounded-xl border border-slate-200 bg-white text-sm font-semibold text-slate-800 focus:ring-2 focus:ring-indigo-500/20"
                        >
                            {pages.map(p => (
                                <option key={p.pageId} value={p.pageId}>{p.title || p.pageId}</option>
                            ))}
                            <option value="custom-new">+ Create New Custom Page</option>
                        </select>

                        <button
                            onClick={handleSavePage}
                            disabled={isSaving || isLoading}
                            className="flex items-center gap-2 px-5 py-2 bg-indigo-600 text-white rounded-xl text-sm font-semibold shadow-md shadow-indigo-200 hover:bg-indigo-700 transition disabled:opacity-50"
                        >
                            {isSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                            Save Changes
                        </button>
                    </div>
                )}
            </div>

            {message.text && (
                <div className={`p-4 rounded-xl text-sm font-medium ${message.type === 'success' ? 'bg-emerald-50 text-emerald-800 border border-emerald-200' : 'bg-red-50 text-red-800 border border-red-200'}`}>
                    {message.text}
                </div>
            )}

            {viewMode === 'cities' ? (
                <CityManager token={token} />
            ) : isLoading || !pageConfig ? (
                <div className="flex justify-center items-center py-20 bg-white rounded-2xl border border-slate-200">
                    <Loader2 className="w-8 h-8 text-indigo-600 animate-spin" />
                </div>
            ) : (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Left Column (2/3): Page Content Editor */}
                    <div className="lg:col-span-2 space-y-6">
                        {/* Page Basic Details */}
                        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-xs space-y-4">
                            <h3 className="font-bold text-slate-800 text-base flex items-center gap-2 border-b border-slate-100 pb-3">
                                <Layers className="w-4 h-4 text-indigo-600" /> Page General Info
                            </h3>
                            <div className="grid grid-cols-2 gap-4 text-sm">
                                <div>
                                    <label className="block font-semibold text-slate-700 mb-1">Page Title *</label>
                                    <input
                                        type="text"
                                        value={pageConfig.title}
                                        onChange={(e) => setPageConfig(prev => ({ ...prev, title: e.target.value }))}
                                        className="w-full px-3.5 py-2 rounded-xl border border-slate-200 focus:ring-2 focus:ring-indigo-500/20"
                                    />
                                </div>
                                <div>
                                    <label className="block font-semibold text-slate-700 mb-1">URL Slug (pageId) *</label>
                                    <input
                                        type="text"
                                        value={pageConfig.pageId}
                                        onChange={(e) => setPageConfig(prev => ({ ...prev, pageId: e.target.value.toLowerCase().replace(/[^a-z0-9]+/g, '-') }))}
                                        className="w-full px-3.5 py-2 rounded-xl border border-slate-200 font-mono text-xs focus:ring-2 focus:ring-indigo-500/20"
                                    />
                                </div>
                            </div>
                        </div>

                        {/* Hero Section Builder */}
                        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-xs space-y-4">
                            <h3 className="font-bold text-slate-800 text-base flex items-center gap-2 border-b border-slate-100 pb-3">
                                <Sparkles className="w-4 h-4 text-amber-500" /> Hero Section (Supports {"{city}"} placeholders)
                            </h3>
                            <div className="space-y-4 text-sm">
                                <div>
                                    <label className="block font-semibold text-slate-700 mb-1">Hero Title</label>
                                    <input
                                        type="text"
                                        placeholder="e.g. Register Your Private Limited Company in {city}"
                                        value={pageConfig.hero.title}
                                        onChange={(e) => setPageConfig(prev => ({ ...prev, hero: { ...prev.hero, title: e.target.value } }))}
                                        className="w-full px-3.5 py-2 rounded-xl border border-slate-200"
                                    />
                                </div>
                                <div>
                                    <label className="block font-semibold text-slate-700 mb-1">Hero Subtitle</label>
                                    <textarea
                                        rows="2"
                                        placeholder="e.g. Get incorporated online in {city}, {state} with expert legal support."
                                        value={pageConfig.hero.subtitle}
                                        onChange={(e) => setPageConfig(prev => ({ ...prev, hero: { ...prev.hero, subtitle: e.target.value } }))}
                                        className="w-full px-3.5 py-2 rounded-xl border border-slate-200"
                                    />
                                </div>
                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <label className="block font-semibold text-slate-700 mb-1">Badge Text</label>
                                        <input
                                            type="text"
                                            value={pageConfig.hero.badgeText}
                                            onChange={(e) => setPageConfig(prev => ({ ...prev, hero: { ...prev.hero, badgeText: e.target.value } }))}
                                            className="w-full px-3.5 py-2 rounded-xl border border-slate-200"
                                        />
                                    </div>
                                    <div>
                                        <label className="block font-semibold text-slate-700 mb-1">Consultation Price (₹)</label>
                                        <input
                                            type="number"
                                            value={pageConfig.hero.consultationPrice}
                                            onChange={(e) => setPageConfig(prev => ({ ...prev, hero: { ...prev.hero, consultationPrice: Number(e.target.value) } }))}
                                            className="w-full px-3.5 py-2 rounded-xl border border-slate-200"
                                        />
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* Packages Manager */}
                        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-xs space-y-4">
                            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                                <h3 className="font-bold text-slate-800 text-base">Packages & Commercial Plans</h3>
                                <button
                                    onClick={() => setPageConfig(prev => ({
                                        ...prev,
                                        packages: [...prev.packages, { id: `pkg-${Date.now()}`, name: 'New Package', price: 2999, description: '', features: ['Feature 1'] }]
                                    }))}
                                    className="text-xs flex items-center gap-1 font-semibold text-indigo-600 hover:text-indigo-700"
                                >
                                    <Plus className="w-3.5 h-3.5" /> Add Package
                                </button>
                            </div>
                            <div className="space-y-4">
                                {pageConfig.packages.map((pkg, idx) => (
                                    <div key={pkg.id || idx} className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 space-y-3">
                                        <div className="flex items-center justify-between">
                                            <input
                                                type="text"
                                                value={pkg.name}
                                                onChange={(e) => {
                                                    const val = e.target.value;
                                                    setPageConfig(prev => ({
                                                        ...prev,
                                                        packages: prev.packages.map((p, i) => i === idx ? { ...p, name: val } : p)
                                                    }));
                                                }}
                                                className="font-bold text-slate-800 bg-transparent border-b border-slate-300 focus:border-indigo-600 focus:outline-none"
                                            />
                                            <button
                                                onClick={() => setPageConfig(prev => ({ ...prev, packages: prev.packages.filter((_, i) => i !== idx) }))}
                                                className="text-slate-400 hover:text-red-600"
                                            >
                                                <Trash2 className="w-4 h-4" />
                                            </button>
                                        </div>
                                        <div className="grid grid-cols-2 gap-3 text-xs">
                                            <div>
                                                <label className="text-slate-500 font-semibold">Price (₹)</label>
                                                <input
                                                    type="number"
                                                    value={pkg.price}
                                                    onChange={(e) => {
                                                        const val = Number(e.target.value);
                                                        setPageConfig(prev => ({
                                                            ...prev,
                                                            packages: prev.packages.map((p, i) => i === idx ? { ...p, price: val } : p)
                                                        }));
                                                    }}
                                                    className="w-full px-2 py-1 rounded border border-slate-200 mt-1"
                                                />
                                            </div>
                                            <div>
                                                <label className="text-slate-500 font-semibold">Features (comma separated)</label>
                                                <input
                                                    type="text"
                                                    value={Array.isArray(pkg.features) ? pkg.features.join(', ') : ''}
                                                    onChange={(e) => {
                                                        const val = e.target.value.split(',').map(f => f.trim());
                                                        setPageConfig(prev => ({
                                                            ...prev,
                                                            packages: prev.packages.map((p, i) => i === idx ? { ...p, features: val } : p)
                                                        }));
                                                    }}
                                                    className="w-full px-2 py-1 rounded border border-slate-200 mt-1"
                                                />
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* FAQs Section */}
                        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-xs space-y-4">
                            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                                <h3 className="font-bold text-slate-800 text-base">Frequently Asked Questions</h3>
                                <button
                                    onClick={() => setPageConfig(prev => ({
                                        ...prev,
                                        faqs: [...prev.faqs, { q: 'Question text here?', a: 'Answer text here.' }]
                                    }))}
                                    className="text-xs flex items-center gap-1 font-semibold text-indigo-600 hover:text-indigo-700"
                                >
                                    <Plus className="w-3.5 h-3.5" /> Add FAQ
                                </button>
                            </div>
                            <div className="space-y-3">
                                {pageConfig.faqs.map((faq, idx) => (
                                    <div key={idx} className="p-3.5 rounded-xl border border-slate-200 bg-slate-50/50 space-y-2 text-xs">
                                        <div className="flex items-center justify-between">
                                            <input
                                                type="text"
                                                placeholder="Question (supports {city})"
                                                value={faq.q}
                                                onChange={(e) => {
                                                    const val = e.target.value;
                                                    setPageConfig(prev => ({
                                                        ...prev,
                                                        faqs: prev.faqs.map((f, i) => i === idx ? { ...f, q: val } : f)
                                                    }));
                                                }}
                                                className="w-full font-semibold text-slate-800 px-2 py-1 rounded border border-slate-200"
                                            />
                                            <button
                                                onClick={() => setPageConfig(prev => ({ ...prev, faqs: prev.faqs.filter((_, i) => i !== idx) }))}
                                                className="text-slate-400 hover:text-red-600 ml-2"
                                            >
                                                <Trash2 className="w-4 h-4" />
                                            </button>
                                        </div>
                                        <textarea
                                            rows="2"
                                            placeholder="Answer text..."
                                            value={faq.a}
                                            onChange={(e) => {
                                                const val = e.target.value;
                                                setPageConfig(prev => ({
                                                    ...prev,
                                                    faqs: prev.faqs.map((f, i) => i === idx ? { ...f, a: val } : f)
                                                }));
                                            }}
                                            className="w-full px-2 py-1 rounded border border-slate-200"
                                        />
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>

                    {/* Right Column (1/3): Yoast SEO Live Analyzer & City Enablement */}
                    <div className="space-y-6">
                        {/* Live Yoast SEO Scorecard */}
                        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-xs space-y-4">
                            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                                <h3 className="font-bold text-slate-800 text-base flex items-center gap-2">
                                    <Globe className="w-4 h-4 text-emerald-600" /> SEO Health
                                </h3>
                                <div className={`px-3 py-1 rounded-full text-xs font-bold ${seoAnalysis.score >= 80 ? 'bg-emerald-100 text-emerald-800' : seoAnalysis.score >= 50 ? 'bg-amber-100 text-amber-800' : 'bg-red-100 text-red-800'}`}>
                                    Score: {seoAnalysis.score}/100
                                </div>
                            </div>

                            <div className="space-y-3 text-sm">
                                <div>
                                    <label className="block font-semibold text-slate-700 mb-1">Focus Keyword *</label>
                                    <input
                                        type="text"
                                        placeholder="e.g. Private Limited Company"
                                        value={focusKeyword}
                                        onChange={(e) => {
                                            const val = e.target.value;
                                            setPageConfig(prev => ({
                                                ...prev,
                                                seoSettings: {
                                                    ...prev.seoSettings,
                                                    focusKeywords: [val]
                                                }
                                            }));
                                        }}
                                        className="w-full px-3 py-2 rounded-xl border border-slate-200 font-medium"
                                    />
                                </div>

                                <div>
                                    <label className="block font-semibold text-slate-700 mb-1">SEO Title Tag</label>
                                    <input
                                        type="text"
                                        value={pageConfig.seoSettings.titleTag}
                                        onChange={(e) => setPageConfig(prev => ({
                                            ...prev,
                                            seoSettings: { ...prev.seoSettings, titleTag: e.target.value }
                                        }))}
                                        className="w-full px-3 py-2 rounded-xl border border-slate-200 text-xs"
                                    />
                                </div>

                                <div>
                                    <label className="block font-semibold text-slate-700 mb-1">Meta Description</label>
                                    <textarea
                                        rows="3"
                                        value={pageConfig.seoSettings.metaDescription}
                                        onChange={(e) => setPageConfig(prev => ({
                                            ...prev,
                                            seoSettings: { ...prev.seoSettings, metaDescription: e.target.value }
                                        }))}
                                        className="w-full px-3 py-2 rounded-xl border border-slate-200 text-xs"
                                    />
                                </div>

                                {/* SEO Issues Checklist */}
                                <div className="pt-2 space-y-2 text-xs">
                                    <p className="font-semibold text-slate-700">Analysis Feedback:</p>
                                    {seoAnalysis.issues.map((iss, i) => (
                                        <div key={i} className="flex items-start gap-2">
                                            {iss.type === 'success' && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0 mt-0.5" />}
                                            {iss.type === 'warning' && <AlertTriangle className="w-3.5 h-3.5 text-amber-500 shrink-0 mt-0.5" />}
                                            {iss.type === 'error' && <AlertTriangle className="w-3.5 h-3.5 text-red-500 shrink-0 mt-0.5" />}
                                            {iss.type === 'info' && <Info className="w-3.5 h-3.5 text-blue-500 shrink-0 mt-0.5" />}
                                            <span className={iss.type === 'success' ? 'text-slate-600' : 'text-slate-800 font-medium'}>{iss.message}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>

                        {/* City Auto-Generation Control */}
                        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-xs space-y-4">
                            <h3 className="font-bold text-slate-800 text-base flex items-center gap-2 border-b border-slate-100 pb-3">
                                <MapPin className="w-4 h-4 text-indigo-600" /> City Auto-Generation
                            </h3>
                            <div className="flex items-center gap-2">
                                <input
                                    type="checkbox"
                                    id="enableCityPagesCheck"
                                    checked={pageConfig.enableCityPages}
                                    onChange={(e) => setPageConfig(prev => ({ ...prev, enableCityPages: e.target.checked }))}
                                    className="w-4 h-4 text-indigo-600 rounded"
                                />
                                <label htmlFor="enableCityPagesCheck" className="text-sm font-semibold text-slate-800 cursor-pointer">
                                    Auto-generate pages for all cities in Master Database
                                </label>
                            </div>
                            <p className="text-xs text-slate-500">
                                When enabled, visiting <code>vrhere.in/{pageConfig.pageId}-in-tirupati</code> will automatically render localized content with Tirupati address, state, and FAQs.
                            </p>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default UnifiedPageManager;
