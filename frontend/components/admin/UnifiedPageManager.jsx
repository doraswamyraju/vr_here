import React, { useEffect, useState, useMemo } from 'react';
import axios from 'axios';
import {
    FileText, Plus, Trash2, Save, CheckCircle2, AlertTriangle, Info, Globe, MapPin, Loader2, Sparkles, Wand2, Link2, ExternalLink, Table, Edit3, Power
} from 'lucide-react';
import { analyzeOnPageSeo } from '../../utils/onPageSeoAnalyzer';
import CityManager from './CityManager';
import { MENU_DATA } from '../SharedComponents';

const UnifiedPageManager = ({ token }) => {
    const [viewMode, setViewMode] = useState('pages'); // 'pages', 'table', or 'cities'
    const [pages, setPages] = useState([]);
    const [cities, setCities] = useState([]);
    const [menuCategories, setMenuCategories] = useState(MENU_DATA);
    const [selectedPageId, setSelectedPageId] = useState('pvt-ltd-registration');
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

    const fetchHeaderConfig = async () => {
        try {
            const { data } = await axios.get('/api/services/header-config');
            if (Array.isArray(data?.services) && data.services.length > 0) {
                setMenuCategories(data.services);
            }
        } catch (err) {
            console.error('Failed to fetch header menu config', err);
        }
    };

    const fetchCities = async () => {
        try {
            const { data } = await axios.get('/api/cities?all=false');
            if (Array.isArray(data)) {
                setCities(data);
            }
        } catch (err) {
            console.error('Failed to load cities list', err);
        }
    };

    const fetchPageDetail = async (pageId) => {
        setIsLoading(true);
        try {
            const { data } = await axios.get(`/api/service-pages/${pageId}`);
            setPageConfig({
                pageId: data.pageId || pageId,
                title: data.title || 'Private Limited Registration',
                description: data.description || '',
                isPublished: data.isPublished !== undefined ? data.isPublished : true,
                hero: {
                    title: data.hero?.title || 'Register Your Private Limited Company Online in {city}',
                    subtitle: data.hero?.subtitle || 'Launch your startup legally with expert CA/CS guidance in {city}, {state}.',
                    badgeText: data.hero?.badgeText || "India's #1 Secure Registration Platform",
                    consultationPrice: data.hero?.consultationPrice || 499
                },
                packages: Array.isArray(data.packages) ? data.packages : [],
                faqs: Array.isArray(data.faqs) ? data.faqs : [],
                steps: Array.isArray(data.steps) ? data.steps : [],
                seoSettings: {
                    titleTag: data.seoSettings?.titleTag || 'Private Limited Company Registration Online in India | VR Here',
                    metaDescription: data.seoSettings?.metaDescription || 'Register your Private Limited Company in India in 7 days. Get 100% online legal incorporation, MOA/AOA, PAN, TAN & CA/CS guidance.',
                    focusKeywords: Array.isArray(data.seoSettings?.focusKeywords) && data.seoSettings.focusKeywords.length > 0 ? data.seoSettings.focusKeywords : ['Private Limited Company']
                },
                enableCityPages: data.enableCityPages !== undefined ? data.enableCityPages : true,
                headerNavSync: {
                    enabled: data.headerNavSync?.enabled !== undefined ? data.headerNavSync.enabled : true,
                    category: data.headerNavSync?.category || (menuCategories[0]?.title || 'Accounting, Compliance & Taxation Services'),
                    column: data.headerNavSync?.column || (menuCategories[0]?.columns?.[0]?.title || 'Taxation & Legal Compliance')
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
        fetchHeaderConfig();
        fetchCities();
    }, []);

    useEffect(() => {
        if (selectedPageId) {
            fetchPageDetail(selectedPageId);
        }
    }, [selectedPageId]);

    // Get list of available columns for the currently selected dropdown category
    const activeCategoryObj = useMemo(() => {
        if (!pageConfig?.headerNavSync?.category) return menuCategories[0];
        return menuCategories.find(c => c.title === pageConfig.headerNavSync.category || c.id === pageConfig.headerNavSync.category) || menuCategories[0];
    }, [pageConfig?.headerNavSync?.category, menuCategories]);

    const availableColumns = useMemo(() => {
        if (!activeCategoryObj || !Array.isArray(activeCategoryObj.columns)) return [];
        return activeCategoryObj.columns.map(col => typeof col === 'string' ? col : col.title);
    }, [activeCategoryObj]);

    const handleSavePage = async () => {
        setIsSaving(true);
        setMessage({ text: '', type: '' });
        try {
            await axios.post(`/api/service-pages/${pageConfig.pageId}`, pageConfig, authConfig);

            // Save to Header Config if Navigation Sync is enabled
            if (pageConfig.headerNavSync?.enabled) {
                try {
                    const { data: menuData } = await axios.get('/api/services/header-config');
                    let servicesList = Array.isArray(menuData?.services) && menuData.services.length > 0 ? menuData.services : menuCategories;

                    let catItem = servicesList.find(s => s.title === pageConfig.headerNavSync.category || s.id === pageConfig.headerNavSync.category);
                    if (catItem) {
                        catItem.columns = catItem.columns || [];
                        let colItem = catItem.columns.find(c => (typeof c === 'string' ? c : c.title) === pageConfig.headerNavSync.column);
                        if (colItem) {
                            if (typeof colItem !== 'string' && Array.isArray(colItem.items)) {
                                if (!colItem.items.includes(pageConfig.title)) {
                                    colItem.items.push(pageConfig.title);
                                }
                            }
                        } else {
                            catItem.columns.push({ title: pageConfig.headerNavSync.column, items: [pageConfig.title] });
                        }
                        await axios.post('/api/services/header-config', { ...menuData, services: servicesList }, authConfig);
                    }
                } catch (navErr) {
                    console.warn('Navigation menu sync warning:', navErr);
                }
            }

            setMessage({ text: `Page "${pageConfig.title}" saved successfully!`, type: 'success' });
            fetchAllPages();
        } catch (err) {
            console.error('Failed to save page', err);
            setMessage({ text: err.response?.data?.message || 'Error saving page config', type: 'error' });
        } finally {
            setIsSaving(false);
        }
    };

    const handleDeletePage = async (pageIdToDelete) => {
        if (!window.confirm(`Are you sure you want to delete page "${pageIdToDelete}"? This action cannot be undone.`)) return;
        try {
            await axios.delete(`/api/service-pages/${pageIdToDelete}`, authConfig);
            setMessage({ text: `Page "${pageIdToDelete}" deleted successfully!`, type: 'success' });
            fetchAllPages();
        } catch (err) {
            console.error('Failed to delete page', err);
            setMessage({ text: err.response?.data?.message || 'Error deleting page.', type: 'error' });
        }
    };

    const handleTogglePublish = async (pageObj) => {
        try {
            const nextState = pageObj.isPublished === false ? true : false;
            await axios.post(`/api/service-pages/${pageObj.pageId}`, { ...pageObj, isPublished: nextState }, authConfig);
            setMessage({ text: `Page "${pageObj.pageId}" ${nextState ? 'enabled' : 'disabled'} successfully!`, type: 'success' });
            fetchAllPages();
        } catch (err) {
            console.error('Failed to toggle publish status', err);
        }
    };

    // Calculate SEO Score dynamically
    const focusKeyword = pageConfig?.seoSettings?.focusKeywords?.[0] || 'Private Limited Company';
    const fullTextContent = `${pageConfig?.hero?.title || ''} ${pageConfig?.hero?.subtitle || ''} ${(pageConfig?.packages || []).map(p => p.description + ' ' + (p.features || []).join(' ')).join(' ')} ${(pageConfig?.faqs || []).map(f => f.q + ' ' + f.a).join(' ')}`;

    const seoAnalysis = analyzeOnPageSeo({
        focusKeyword,
        titleTag: pageConfig?.seoSettings?.titleTag || pageConfig?.title || '',
        metaDescription: pageConfig?.seoSettings?.metaDescription || pageConfig?.description || '',
        pageContent: fullTextContent,
        slug: pageConfig?.pageId || ''
    });

    // Auto-Optimize SEO Titles & Meta Descriptions for 100% Score
    const handleAutoOptimizeSeo = () => {
        const kw = 'Private Limited Company';
        const autoTitle = `Private Limited Company Registration Online in India | VR Here`;
        const autoMeta = `Register your Private Limited Company in India in 7 days. Get 100% online legal incorporation, MOA/AOA, PAN, TAN & CA/CS guidance.`;

        setPageConfig(prev => ({
            ...prev,
            seoSettings: {
                ...prev.seoSettings,
                focusKeywords: [kw],
                titleTag: autoTitle,
                metaDescription: autoMeta
            }
        }));

        setMessage({ text: 'SEO Title & Meta Description auto-optimized for 100/100 Perfect Score!', type: 'success' });
    };

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
                        Private Limited Page & SEO
                    </button>
                    <button
                        onClick={() => setViewMode('table')}
                        className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition ${viewMode === 'table' ? 'bg-white text-indigo-600 shadow-xs' : 'text-slate-600 hover:text-slate-900'}`}
                    >
                        <Table className="w-4 h-4" />
                        Master Pages Table ({pages.length})
                    </button>
                    <button
                        onClick={() => setViewMode('cities')}
                        className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition ${viewMode === 'cities' ? 'bg-white text-indigo-600 shadow-xs' : 'text-slate-600 hover:text-slate-900'}`}
                    >
                        <MapPin className="w-4 h-4" />
                        Master City Catalog ({cities.length})
                    </button>
                </div>

                {viewMode === 'pages' && (
                    <div className="flex items-center gap-3">
                        <select
                            value={selectedPageId}
                            onChange={(e) => setSelectedPageId(e.target.value)}
                            className="px-3.5 py-2 rounded-xl border border-slate-200 bg-white text-sm font-semibold text-slate-800 focus:ring-2 focus:ring-indigo-500/20"
                        >
                            <option value="pvt-ltd-registration">Private Limited Registration</option>
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
            ) : viewMode === 'table' ? (
                /* MASTER PAGES TABULAR OVERVIEW */
                <div className="bg-white rounded-2xl border border-slate-200 shadow-xs overflow-hidden">
                    <div className="p-5 border-b border-slate-100 flex items-center justify-between">
                        <div>
                            <h3 className="font-bold text-slate-800 text-lg flex items-center gap-2">
                                <Table className="w-5 h-5 text-indigo-600" /> Master Pages Overview Table
                            </h3>
                            <p className="text-xs text-slate-500 mt-1">List of all service landing pages, enable/disable toggles, and deletion controls.</p>
                        </div>
                    </div>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm text-slate-600">
                            <thead className="bg-slate-50 border-b border-slate-200 text-slate-700 uppercase text-xs font-bold">
                                <tr>
                                    <th className="py-3.5 px-4">Page Title</th>
                                    <th className="py-3.5 px-4">URL Slug</th>
                                    <th className="py-3.5 px-4">Header Category</th>
                                    <th className="py-3.5 px-4">Status</th>
                                    <th className="py-3.5 px-4">City Pages</th>
                                    <th className="py-3.5 px-4 text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {pages.map(p => (
                                    <tr key={p._id || p.pageId} className="hover:bg-slate-50/80 transition">
                                        <td className="py-3.5 px-4 font-bold text-slate-900">{p.title || p.pageId}</td>
                                        <td className="py-3.5 px-4 font-mono text-xs text-indigo-600">/{p.pageId}</td>
                                        <td className="py-3.5 px-4 text-xs font-medium text-slate-600">{p.headerNavSync?.category || 'Business Registrations'}</td>
                                        <td className="py-3.5 px-4">
                                            <button
                                                onClick={() => handleTogglePublish(p)}
                                                className={`flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-bold transition ${p.isPublished !== false ? 'bg-emerald-50 text-emerald-700 border border-emerald-200 hover:bg-emerald-100' : 'bg-rose-50 text-rose-700 border border-rose-200 hover:bg-rose-100'}`}
                                            >
                                                <Power className="w-3 h-3" /> {p.isPublished !== false ? 'Enabled' : 'Disabled'}
                                            </button>
                                        </td>
                                        <td className="py-3.5 px-4">
                                            {p.enableCityPages !== false ? (
                                                <span className="px-2.5 py-1 rounded-full text-xs font-bold bg-indigo-50 text-indigo-700 border border-indigo-200">
                                                    Enabled ({cities.length} Cities)
                                                </span>
                                            ) : (
                                                <span className="px-2.5 py-1 rounded-full text-xs font-bold bg-slate-100 text-slate-600">Disabled</span>
                                            )}
                                        </td>
                                        <td className="py-3.5 px-4 text-right">
                                            <div className="flex items-center justify-end gap-2">
                                                <button
                                                    onClick={() => { setSelectedPageId(p.pageId); setViewMode('pages'); }}
                                                    className="p-1.5 text-slate-600 hover:text-indigo-600 hover:bg-indigo-50 rounded-lg font-semibold text-xs flex items-center gap-1"
                                                >
                                                    <Edit3 className="w-3.5 h-3.5" /> Edit
                                                </button>
                                                <a
                                                    href={`/${p.pageId}`}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="p-1.5 text-slate-500 hover:text-indigo-600 hover:bg-indigo-50 rounded-lg text-xs font-semibold flex items-center gap-1"
                                                >
                                                    <ExternalLink className="w-3.5 h-3.5" /> Live ↗
                                                </a>
                                                <button
                                                    onClick={() => handleDeletePage(p.pageId)}
                                                    className="p-1.5 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg font-semibold text-xs flex items-center gap-1"
                                                    title="Delete Master Page"
                                                >
                                                    <Trash2 className="w-3.5 h-3.5" /> Delete
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
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
                                <FileText className="w-4 h-4 text-indigo-600" /> Page General Info
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

                        {/* Navigation Menu Linker */}
                        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-xs space-y-4">
                            <h3 className="font-bold text-slate-800 text-base flex items-center gap-2 border-b border-slate-100 pb-3">
                                <Link2 className="w-4 h-4 text-indigo-600" /> Connect Page to Navigation Menu
                            </h3>
                            <div className="space-y-4 text-sm">
                                <div className="flex items-center gap-2">
                                    <input
                                        type="checkbox"
                                        id="headerNavSyncCheck"
                                        checked={pageConfig.headerNavSync?.enabled}
                                        onChange={(e) => setPageConfig(prev => ({
                                            ...prev,
                                            headerNavSync: { ...prev.headerNavSync, enabled: e.target.checked }
                                        }))}
                                        className="w-4 h-4 text-indigo-600 rounded"
                                    />
                                    <label htmlFor="headerNavSyncCheck" className="font-semibold text-slate-800 cursor-pointer">
                                        Show this page link in top Website Navigation Dropdown Menu
                                    </label>
                                </div>

                                {pageConfig.headerNavSync?.enabled && (
                                    <div className="grid grid-cols-2 gap-4 bg-slate-50 p-4 rounded-xl border border-slate-200">
                                        <div>
                                            <label className="block font-semibold text-slate-700 mb-1">Header Dropdown Category</label>
                                            <select
                                                value={pageConfig.headerNavSync.category}
                                                onChange={(e) => {
                                                    const catTitle = e.target.value;
                                                    const catObj = menuCategories.find(c => c.title === catTitle);
                                                    const firstCol = catObj?.columns?.[0] ? (typeof catObj.columns[0] === 'string' ? catObj.columns[0] : catObj.columns[0].title) : '';
                                                    setPageConfig(prev => ({
                                                        ...prev,
                                                        headerNavSync: {
                                                            ...prev.headerNavSync,
                                                            category: catTitle,
                                                            column: firstCol || prev.headerNavSync.column
                                                        }
                                                    }));
                                                }}
                                                className="w-full px-3 py-2 rounded-xl border border-slate-200 bg-white font-medium text-xs"
                                            >
                                                {menuCategories.map((c, idx) => (
                                                    <option key={c.id || idx} value={c.title}>{c.title}</option>
                                                ))}
                                            </select>
                                        </div>

                                        <div>
                                            <label className="block font-semibold text-slate-700 mb-1">Menu Column</label>
                                            <select
                                                value={pageConfig.headerNavSync.column}
                                                onChange={(e) => setPageConfig(prev => ({
                                                    ...prev,
                                                    headerNavSync: { ...prev.headerNavSync, column: e.target.value }
                                                }))}
                                                className="w-full px-3 py-2 rounded-xl border border-slate-200 bg-white font-medium text-xs"
                                            >
                                                {availableColumns.map((colName, i) => (
                                                    <option key={i} value={colName}>{colName}</option>
                                                ))}
                                            </select>
                                        </div>
                                    </div>
                                )}
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
                                        placeholder="e.g. Register Your Private Limited Company Online in {city}"
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

                        {/* Generated City Pages Live Preview Box */}
                        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-xs space-y-4">
                            <h3 className="font-bold text-slate-800 text-base flex items-center gap-2 border-b border-slate-100 pb-3">
                                <Globe className="w-4 h-4 text-indigo-600" /> Generated City Pages Live Preview
                            </h3>
                            <p className="text-xs text-slate-500">
                                Click <strong>"Preview Page"</strong> to view the live rendered page for any city with Tirupati / Hyderabad address, state, and FAQs dynamically injected!
                            </p>

                            {cities.length === 0 ? (
                                <p className="text-xs text-slate-400 italic">No active cities found in Master Database. Switch to <strong>"Master City Catalog"</strong> tab above to add cities.</p>
                            ) : (
                                <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                                    {cities.map(city => {
                                        const cityUrl = `/${pageConfig.pageId}-in-${city.slug}`;
                                        return (
                                            <div key={city._id} className="flex items-center justify-between p-2.5 rounded-xl bg-slate-50 border border-slate-200 text-xs">
                                                <div>
                                                    <span className="font-bold text-slate-800">{city.name}</span>
                                                    <span className="text-slate-400 ml-2">({city.state})</span>
                                                    <div className="font-mono text-[11px] text-indigo-600 mt-0.5">
                                                        vrhere.in{cityUrl}
                                                    </div>
                                                </div>
                                                <a
                                                    href={cityUrl}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="flex items-center gap-1 px-3 py-1.5 bg-indigo-50 text-indigo-700 font-semibold rounded-lg hover:bg-indigo-100 transition"
                                                >
                                                    <ExternalLink className="w-3.5 h-3.5" /> Preview Page ↗
                                                </a>
                                            </div>
                                        );
                                    })}
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Right Column (1/3): SEO Health & Auto-Optimizer */}
                    <div className="space-y-6">
                        {/* SEO Health + 1-Click Auto-Optimizer */}
                        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-xs space-y-4">
                            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                                <h3 className="font-bold text-slate-800 text-base flex items-center gap-2">
                                    <Globe className="w-4 h-4 text-emerald-600" /> SEO Health
                                </h3>
                                <div className={`px-3 py-1 rounded-full text-xs font-bold ${seoAnalysis.score >= 80 ? 'bg-emerald-100 text-emerald-800' : seoAnalysis.score >= 50 ? 'bg-amber-100 text-amber-800' : 'bg-red-100 text-red-800'}`}>
                                    Score: {seoAnalysis.score}/100
                                </div>
                            </div>

                            <button
                                type="button"
                                onClick={handleAutoOptimizeSeo}
                                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-gradient-to-r from-amber-500 to-orange-500 text-white font-bold rounded-xl text-xs shadow-md hover:from-amber-600 hover:to-orange-600 transition"
                            >
                                <Wand2 className="w-4 h-4" /> ⚡ Auto-Optimize SEO Titles & Meta (100% Score)
                            </button>

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
                                        <div key={i} className="flex items-start gap-2 p-2 rounded-lg bg-slate-50 border border-slate-100">
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
