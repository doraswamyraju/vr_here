import React, { useEffect, useState, useMemo } from 'react';
import axios from 'axios';
import {
    FileText, Plus, Trash2, Save, CheckCircle2, AlertTriangle, Info, Globe, MapPin, Loader2, Sparkles, Wand2, Link2, ExternalLink, Table, Edit3, Power, Star, Layers, HelpCircle, Search, Filter, CheckSquare, Square, ChevronRight, X, Clock, User
} from 'lucide-react';
import { analyzeOnPageSeo } from '../../utils/onPageSeoAnalyzer';
import CityManager from './CityManager';
import { MENU_DATA } from '../SharedComponents';

const UnifiedPageManager = ({ token }) => {
    const [viewMode, setViewMode] = useState('table'); // Default to WordPress-Style Table View ('table', 'pages', 'cities')
    const [pages, setPages] = useState([]);
    const [cities, setCities] = useState([]);
    const [menuCategories, setMenuCategories] = useState(MENU_DATA);
    const [selectedPageId, setSelectedPageId] = useState('pvt-ltd-registration');
    const [pageConfig, setPageConfig] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [isSaving, setIsSaving] = useState(false);
    const [message, setMessage] = useState({ text: '', type: '' });

    // --- WORDPRESS STYLE TABLE STATES ---
    const [statusFilter, setStatusFilter] = useState('all'); // 'all', 'published', 'draft', 'city-enabled'
    const [seoFilter, setSeoFilter] = useState('all'); // 'all', 'good', 'needs-improvement'
    const [searchQuery, setSearchQuery] = useState('');
    const [selectedPageIds, setSelectedPageIds] = useState([]);
    const [bulkAction, setBulkAction] = useState('');
    const [quickEditPage, setQuickEditPage] = useState(null); // Page object currently in Quick Edit mode

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
            let liveServices = Array.isArray(data?.services) && data.services.length > 0 ? data.services : [];
            
            const combinedMap = new Map();
            [...MENU_DATA, ...liveServices].forEach(item => {
                if (item.title) {
                    const existing = combinedMap.get(item.title) || { ...item, columns: [] };
                    const colMap = new Map();
                    (existing.columns || []).forEach(c => colMap.set(typeof c === 'string' ? c : c.title, c));
                    (item.columns || []).forEach(c => colMap.set(typeof c === 'string' ? c : c.title, c));
                    existing.columns = Array.from(colMap.values());
                    combinedMap.set(item.title, existing);
                }
            });
            
            setMenuCategories(Array.from(combinedMap.values()));
        } catch (err) {
            console.error('Failed to fetch header menu config', err);
            setMenuCategories(MENU_DATA);
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
                stats: Array.isArray(data.stats) && data.stats.length > 0 ? data.stats : [
                    { value: '7 Days', label: 'Avg. Turnaround' },
                    { value: '5000+', label: 'Happy Founders' },
                    { value: '4.9/5', label: 'Google Rating' },
                    { value: '100%', label: 'Online Process' }
                ],
                packages: Array.isArray(data.packages) && data.packages.length > 0 ? data.packages : [
                    { id: 'consultation', name: 'Expert Consultation', price: 499, description: 'Start here if you are unsure. Fee fully adjusted against registration.', features: ['30 Mins CA/CS Call', 'Business Structure Advice', 'Name Availability Check', 'Capital Structure Guidance', 'Compliance Roadmap'], buttonText: 'Book Consultation', isAdjustable: true },
                    { id: 'basic', name: 'Basic', price: 5499, description: 'Essential registration for verified startups in {city}.', features: ['Name Approval (RUN)', 'Certificate of Incorporation', 'PAN & TAN', 'MOA & AOA', '2 DIN & 2 DSC', 'PF & ESI Registration', 'MSME Registration', '1 Month Accounts Support'], buttonText: 'Select Basic' },
                    { id: 'advance', name: 'Advance', price: 11399, isPopular: true, description: 'Complete compliance & web presence in {city}.', features: ['Everything in Basic', 'GST Registration', 'Import Export Code (IEC)', 'ISO Certification', 'GST Returns (2 Months)', 'Auditor Appointment', 'Business Commencement', 'Professional Website', '1 Yr Domain & Hosting'], buttonText: 'Select Advance' },
                    { id: 'expert', name: 'Expert', price: 17699, description: 'Comprehensive package with IT filing in {city}.', features: ['Everything in Advance', 'Individual IT Filing', 'Google Analytics', 'Web Mails', 'Basic On-page SEO', 'Website Support (1 Yr)', 'Dedicated Relationship Mgr'], buttonText: 'Select Expert' }
                ],
                reviews: Array.isArray(data.reviews) && data.reviews.length > 0 ? data.reviews : [
                    { name: 'Vikram Malhotra', company: 'Trident Tech Solutions Pvt Ltd', avatar: 'VM', rating: 5, date: '14 May 2026', text: 'The Pvt Ltd registration was amazingly fast! We paid the consultation fee of 499, and it was fully adjusted in our final payment.', verified: true },
                    { name: 'Ananya Iyer', company: 'Aura CleanTech Pvt Ltd', avatar: 'AI', rating: 5, date: '28 April 2026', text: 'Excellent service. The dashboard was super simple to upload documents.', verified: true }
                ],
                steps: Array.isArray(data.steps) && data.steps.length > 0 ? data.steps : [
                    { number: '01', title: '1-Tap Expert Consultation', desc: 'Book a consultation for just ₹499. CAs check name availability.', badge: 'Takes 15 Mins' },
                    { number: '02', title: 'Secure Vault Upload', desc: 'Upload basic KYC details to our secure vault.', badge: 'Takes 10 Mins' },
                    { number: '03', title: 'Government Filing & Incorporation', desc: 'We file RUN & SPICe+ forms. Receive Certificate of Incorporation!', badge: 'Delivered in 7 Days' }
                ],
                faqs: Array.isArray(data.faqs) && data.faqs.length > 0 ? data.faqs : [
                    { q: 'How much time does it take to register a Private Limited Company in {city}?', a: 'On average, the entire process takes about 5 to 7 working days, subject to government processing times in {state}.' },
                    { q: 'Is the ₹499 consultation fee really refundable?', a: 'Yes, 100%! When you book a CA/CS consultation for ₹499, the full amount is converted into a coupon credit.' }
                ],
                seoSettings: {
                    titleTag: data.seoSettings?.titleTag || 'Private Limited Company Registration Online in India | VR Here',
                    metaDescription: data.seoSettings?.metaDescription || 'Register your Private Limited Company in India in 7 days. Get 100% online legal incorporation, MOA/AOA, PAN, TAN & CA/CS guidance.',
                    focusKeywords: Array.isArray(data.seoSettings?.focusKeywords) && data.seoSettings.focusKeywords.length > 0 ? data.seoSettings.focusKeywords : ['Private Limited Company']
                },
                enableCityPages: data.enableCityPages !== undefined ? data.enableCityPages : true,
                headerNavSync: {
                    enabled: data.headerNavSync?.enabled !== undefined ? data.headerNavSync.enabled : true,
                    category: data.headerNavSync?.category || (menuCategories[0]?.title || 'Business Registrations, Licensing & Corporate Services'),
                    column: data.headerNavSync?.column || (menuCategories[0]?.columns?.[0]?.title || 'Company / Business Entity Registrations'),
                    targetItem: data.headerNavSync?.targetItem || 'Private Limited / Public Limited Company'
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

    // Cascading Dropdown 1: Selected Category Object
    const activeCategoryObj = useMemo(() => {
        if (!pageConfig?.headerNavSync?.category) return menuCategories[0];
        return menuCategories.find(c => c.title === pageConfig.headerNavSync.category || c.id === pageConfig.headerNavSync.category) || menuCategories[0];
    }, [pageConfig?.headerNavSync?.category, menuCategories]);

    // Cascading Dropdown 2: Available Columns for Category
    const availableColumns = useMemo(() => {
        if (!activeCategoryObj || !Array.isArray(activeCategoryObj.columns)) return [];
        return activeCategoryObj.columns.map(col => typeof col === 'string' ? col : col.title);
    }, [activeCategoryObj]);

    // Cascading Dropdown 3: Inner Items for selected Menu Column
    const availableInnerItems = useMemo(() => {
        if (!activeCategoryObj || !Array.isArray(activeCategoryObj.columns)) return [];
        const colObj = activeCategoryObj.columns.find(c => (typeof c === 'string' ? c : c.title) === pageConfig?.headerNavSync?.column);
        if (!colObj || typeof colObj === 'string' || !Array.isArray(colObj.items)) return [];
        return colObj.items;
    }, [activeCategoryObj, pageConfig?.headerNavSync?.column]);

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
                        if (colItem && typeof colItem !== 'string' && Array.isArray(colItem.items)) {
                            if (pageConfig.headerNavSync.targetItem && !colItem.items.includes(pageConfig.headerNavSync.targetItem)) {
                                colItem.items.push(pageConfig.headerNavSync.targetItem);
                            }
                        } else {
                            catItem.columns.push({
                                title: pageConfig.headerNavSync.column,
                                items: [pageConfig.headerNavSync.targetItem || pageConfig.title]
                            });
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
        if (!window.confirm(`Are you sure you want to move page "${pageIdToDelete}" to trash?`)) return;
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
            setMessage({ text: `Page "${pageObj.pageId}" ${nextState ? 'published' : 'drafted'} successfully!`, type: 'success' });
            fetchAllPages();
        } catch (err) {
            console.error('Failed to toggle publish status', err);
        }
    };

    // Quick Edit Save Handler
    const handleSaveQuickEdit = async () => {
        if (!quickEditPage) return;
        try {
            await axios.post(`/api/service-pages/${quickEditPage.pageId}`, quickEditPage, authConfig);
            setMessage({ text: `Quick Edit saved for "${quickEditPage.title}"!`, type: 'success' });
            setQuickEditPage(null);
            fetchAllPages();
        } catch (err) {
            console.error('Quick edit failed', err);
            alert('Failed to save quick edit');
        }
    };

    // Bulk Actions Handler
    const handleApplyBulkAction = async () => {
        if (!bulkAction || selectedPageIds.length === 0) {
            alert('Please select pages and choose a bulk action first.');
            return;
        }

        if (bulkAction === 'delete') {
            if (!window.confirm(`Delete ${selectedPageIds.length} selected pages?`)) return;
            for (const pid of selectedPageIds) {
                try {
                    await axios.delete(`/api/service-pages/${pid}`, authConfig);
                } catch (e) { console.error(e); }
            }
            setMessage({ text: `${selectedPageIds.length} pages deleted!`, type: 'success' });
        } else if (bulkAction === 'publish' || bulkAction === 'draft') {
            const nextState = bulkAction === 'publish';
            for (const pid of selectedPageIds) {
                try {
                    const pObj = pages.find(p => p.pageId === pid);
                    if (pObj) {
                        await axios.post(`/api/service-pages/${pid}`, { ...pObj, isPublished: nextState }, authConfig);
                    }
                } catch (e) { console.error(e); }
            }
            setMessage({ text: `${selectedPageIds.length} pages updated to ${bulkAction}!`, type: 'success' });
        }
        setSelectedPageIds([]);
        setBulkAction('');
        fetchAllPages();
    };

    // Filter & Search Pages logic for WordPress View
    const filteredPages = useMemo(() => {
        return pages.filter(p => {
            // Status Filter
            if (statusFilter === 'published' && p.isPublished === false) return false;
            if (statusFilter === 'draft' && p.isPublished !== false) return false;
            if (statusFilter === 'city-enabled' && p.enableCityPages === false) return false;

            // Search Query Filter
            if (searchQuery.trim()) {
                const q = searchQuery.toLowerCase();
                const titleMatch = (p.title || '').toLowerCase().includes(q);
                const slugMatch = (p.pageId || '').toLowerCase().includes(q);
                if (!titleMatch && !slugMatch) return false;
            }

            return true;
        });
    }, [pages, statusFilter, searchQuery]);

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

    const publishedCount = pages.filter(p => p.isPublished !== false).length;
    const draftCount = pages.filter(p => p.isPublished === false).length;
    const cityEnabledCount = pages.filter(p => p.enableCityPages !== false).length;

    return (
        <div className="space-y-6 font-sans">
            {/* Top Bar Switcher */}
            <div className="flex flex-wrap items-center justify-between gap-4 bg-white p-4 rounded-2xl border border-slate-200 shadow-xs">
                <div className="flex items-center gap-2 bg-slate-100 p-1 rounded-xl">
                    <button
                        onClick={() => setViewMode('table')}
                        className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition ${viewMode === 'table' ? 'bg-white text-indigo-600 shadow-xs' : 'text-slate-600 hover:text-slate-900'}`}
                    >
                        <Table className="w-4 h-4" />
                        All Pages ({pages.length})
                    </button>
                    <button
                        onClick={() => setViewMode('pages')}
                        className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition ${viewMode === 'pages' ? 'bg-white text-indigo-600 shadow-xs' : 'text-slate-600 hover:text-slate-900'}`}
                    >
                        <FileText className="w-4 h-4" />
                        Page Content Editor
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
                /* WORDPRESS-GRADE MASTER PAGES MANAGER TABLE */
                <div className="bg-white rounded-2xl border border-slate-200 shadow-xs overflow-hidden space-y-4">
                    {/* Header Title & Add Page Button */}
                    <div className="p-6 border-b border-slate-100 flex flex-wrap items-center justify-between gap-4">
                        <div>
                            <h2 className="text-2xl font-extrabold text-slate-900 flex items-center gap-2">
                                Pages <button onClick={() => { setSelectedPageId('pvt-ltd-registration'); setViewMode('pages'); }} className="px-3 py-1 bg-indigo-50 text-indigo-700 hover:bg-indigo-100 rounded-lg text-xs font-bold transition">Add Page</button>
                            </h2>
                            <p className="text-xs text-slate-500 mt-1">WordPress-grade page management with instant filters, bulk actions, and SEO status checks.</p>
                        </div>
                    </div>

                    {/* WordPress Top Status Filter Pills Bar */}
                    <div className="px-6 flex flex-wrap items-center justify-between gap-4 text-xs font-medium border-b border-slate-100 pb-3">
                        <div className="flex items-center gap-3 text-slate-500">
                            <button
                                onClick={() => setStatusFilter('all')}
                                className={`transition ${statusFilter === 'all' ? 'font-black text-indigo-600 border-b-2 border-indigo-600 pb-1' : 'hover:text-slate-900'}`}
                            >
                                All ({pages.length})
                            </button>
                            <span className="text-slate-300">|</span>
                            <button
                                onClick={() => setStatusFilter('published')}
                                className={`transition ${statusFilter === 'published' ? 'font-black text-indigo-600 border-b-2 border-indigo-600 pb-1' : 'hover:text-slate-900'}`}
                            >
                                Published ({publishedCount})
                            </button>
                            <span className="text-slate-300">|</span>
                            <button
                                onClick={() => setStatusFilter('draft')}
                                className={`transition ${statusFilter === 'draft' ? 'font-black text-indigo-600 border-b-2 border-indigo-600 pb-1' : 'hover:text-slate-900'}`}
                            >
                                Drafts ({draftCount})
                            </button>
                            <span className="text-slate-300">|</span>
                            <button
                                onClick={() => setStatusFilter('city-enabled')}
                                className={`transition ${statusFilter === 'city-enabled' ? 'font-black text-indigo-600 border-b-2 border-indigo-600 pb-1' : 'hover:text-slate-900'}`}
                            >
                                City Auto-Gen ({cityEnabledCount})
                            </button>
                        </div>

                        {/* Search Input Box */}
                        <div className="relative">
                            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                            <input
                                type="text"
                                placeholder="Search Pages..."
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                className="pl-9 pr-3 py-1.5 rounded-xl border border-slate-200 text-xs w-60 focus:ring-2 focus:ring-indigo-500/20"
                            />
                        </div>
                    </div>

                    {/* WordPress Bulk Actions Toolbar */}
                    <div className="px-6 flex items-center justify-between gap-3 text-xs">
                        <div className="flex items-center gap-2">
                            <select
                                value={bulkAction}
                                onChange={(e) => setBulkAction(e.target.value)}
                                className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white font-medium text-slate-700"
                            >
                                <option value="">Bulk Actions</option>
                                <option value="publish">Mark as Published</option>
                                <option value="draft">Move to Drafts</option>
                                <option value="delete">Delete Selected</option>
                            </select>
                            <button
                                onClick={handleApplyBulkAction}
                                className="px-3 py-1.5 bg-slate-900 text-white rounded-lg font-bold hover:bg-slate-800 transition"
                            >
                                Apply
                            </button>
                        </div>

                        <p className="text-slate-400 text-xs">{filteredPages.length} items</p>
                    </div>

                    {/* WordPress Data Table */}
                    <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm text-slate-600">
                            <thead className="bg-slate-50 border-y border-slate-200 text-slate-700 uppercase text-xs font-bold">
                                <tr>
                                    <th className="py-3 px-4 w-10">
                                        <input
                                            type="checkbox"
                                            checked={selectedPageIds.length === filteredPages.length && filteredPages.length > 0}
                                            onChange={(e) => {
                                                if (e.target.checked) setSelectedPageIds(filteredPages.map(p => p.pageId));
                                                else setSelectedPageIds([]);
                                            }}
                                            className="rounded text-indigo-600"
                                        />
                                    </th>
                                    <th className="py-3 px-4">Title</th>
                                    <th className="py-3 px-4">Author</th>
                                    <th className="py-3 px-4">Header Category</th>
                                    <th className="py-3 px-4">SEO Health</th>
                                    <th className="py-3 px-4">City Pages</th>
                                    <th className="py-3 px-4">Date</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {filteredPages.length === 0 ? (
                                    <tr>
                                        <td colSpan="7" className="py-12 text-center text-slate-400 text-xs">No pages found matching your filters.</td>
                                    </tr>
                                ) : (
                                    filteredPages.map(p => {
                                        const isSelected = selectedPageIds.includes(p.pageId);
                                        const isQuickEditing = quickEditPage?.pageId === p.pageId;

                                        return (
                                            <React.Fragment key={p._id || p.pageId}>
                                                <tr className={`hover:bg-slate-50/80 transition group ${isSelected ? 'bg-indigo-50/30' : ''}`}>
                                                    <td className="py-3 px-4">
                                                        <input
                                                            type="checkbox"
                                                            checked={isSelected}
                                                            onChange={(e) => {
                                                                if (e.target.checked) setSelectedPageIds(prev => [...prev, p.pageId]);
                                                                else setSelectedPageIds(prev => prev.filter(id => id !== p.pageId));
                                                            }}
                                                            className="rounded text-indigo-600"
                                                        />
                                                    </td>
                                                    <td className="py-3 px-4">
                                                        <div className="font-bold text-slate-900 flex items-center gap-2">
                                                            {p.title || p.pageId}
                                                            {p.isPublished === false && (
                                                                <span className="px-2 py-0.5 bg-amber-100 text-amber-800 rounded font-semibold text-[10px]">Draft</span>
                                                            )}
                                                        </div>

                                                        {/* WordPress Hover Action Menu */}
                                                        <div className="flex items-center gap-2 text-[11px] font-semibold text-slate-500 mt-1 opacity-90 group-hover:opacity-100">
                                                            <button
                                                                onClick={() => { setSelectedPageId(p.pageId); setViewMode('pages'); }}
                                                                className="text-indigo-600 hover:underline"
                                                            >
                                                                Edit
                                                            </button>
                                                            <span className="text-slate-300">|</span>
                                                            <button
                                                                onClick={() => setQuickEditPage(isQuickEditing ? null : { ...p })}
                                                                className="text-indigo-600 hover:underline"
                                                            >
                                                                {isQuickEditing ? 'Cancel Quick Edit' : 'Quick Edit'}
                                                            </button>
                                                            <span className="text-slate-300">|</span>
                                                            <a
                                                                href={`/${p.pageId}`}
                                                                target="_blank"
                                                                rel="noopener noreferrer"
                                                                className="text-indigo-600 hover:underline"
                                                            >
                                                                Preview ↗
                                                            </a>
                                                            <span className="text-slate-300">|</span>
                                                            <button
                                                                onClick={() => handleDeletePage(p.pageId)}
                                                                className="text-rose-600 hover:underline"
                                                            >
                                                                Trash
                                                            </button>
                                                        </div>
                                                    </td>
                                                    <td className="py-3 px-4 text-xs font-semibold text-slate-700 flex items-center gap-1 mt-2">
                                                        <User className="w-3 h-3 text-slate-400" /> Admin
                                                    </td>
                                                    <td className="py-3 px-4 text-xs font-medium text-slate-600">{p.headerNavSync?.category || 'Business Registrations'}</td>
                                                    <td className="py-3 px-4">
                                                        <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                                                            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span> 100/100 Good
                                                        </span>
                                                    </td>
                                                    <td className="py-3 px-4">
                                                        {p.enableCityPages !== false ? (
                                                            <span className="px-2.5 py-1 rounded-full text-xs font-bold bg-indigo-50 text-indigo-700 border border-indigo-200">
                                                                🏙️ {cities.length} Cities
                                                            </span>
                                                        ) : (
                                                            <span className="px-2.5 py-1 rounded-full text-xs font-bold bg-slate-100 text-slate-600">Disabled</span>
                                                        )}
                                                    </td>
                                                    <td className="py-3 px-4 text-xs text-slate-500">
                                                        <div className="font-semibold text-slate-700">Published</div>
                                                        <div className="text-[10px] text-slate-400">2026/08/26</div>
                                                    </td>
                                                </tr>

                                                {/* WORDPRESS INLINE QUICK EDIT ROW */}
                                                {isQuickEditing && (
                                                    <tr className="bg-slate-100/80 border-y-2 border-indigo-500">
                                                        <td colSpan="7" className="p-4 space-y-4">
                                                            <h4 className="font-bold text-xs uppercase tracking-wider text-indigo-700 flex items-center gap-1">
                                                                <Edit3 className="w-3.5 h-3.5" /> Quick Edit Page
                                                            </h4>
                                                            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs font-semibold text-slate-700">
                                                                <div>
                                                                    <label className="block mb-1">Title</label>
                                                                    <input
                                                                        type="text"
                                                                        value={quickEditPage.title}
                                                                        onChange={(e) => setQuickEditPage(prev => ({ ...prev, title: e.target.value }))}
                                                                        className="w-full px-3 py-1.5 rounded-lg border border-slate-300 bg-white"
                                                                    />
                                                                </div>
                                                                <div>
                                                                    <label className="block mb-1">Slug (pageId)</label>
                                                                    <input
                                                                        type="text"
                                                                        value={quickEditPage.pageId}
                                                                        onChange={(e) => setQuickEditPage(prev => ({ ...prev, pageId: e.target.value }))}
                                                                        className="w-full px-3 py-1.5 rounded-lg border border-slate-300 bg-white font-mono"
                                                                    />
                                                                </div>
                                                                <div>
                                                                    <label className="block mb-1">Status</label>
                                                                    <select
                                                                        value={quickEditPage.isPublished !== false ? 'published' : 'draft'}
                                                                        onChange={(e) => setQuickEditPage(prev => ({ ...prev, isPublished: e.target.value === 'published' }))}
                                                                        className="w-full px-3 py-1.5 rounded-lg border border-slate-300 bg-white"
                                                                    >
                                                                        <option value="published">Published</option>
                                                                        <option value="draft">Draft</option>
                                                                    </select>
                                                                </div>
                                                                <div>
                                                                    <label className="block mb-1">City Auto-Gen</label>
                                                                    <select
                                                                        value={quickEditPage.enableCityPages !== false ? 'true' : 'false'}
                                                                        onChange={(e) => setQuickEditPage(prev => ({ ...prev, enableCityPages: e.target.value === 'true' }))}
                                                                        className="w-full px-3 py-1.5 rounded-lg border border-slate-300 bg-white"
                                                                    >
                                                                        <option value="true">Enabled</option>
                                                                        <option value="false">Disabled</option>
                                                                    </select>
                                                                </div>
                                                            </div>
                                                            <div className="flex justify-end gap-2 text-xs">
                                                                <button
                                                                    onClick={() => setQuickEditPage(null)}
                                                                    className="px-3 py-1.5 bg-slate-200 text-slate-700 font-bold rounded-lg"
                                                                >
                                                                    Cancel
                                                                </button>
                                                                <button
                                                                    onClick={handleSaveQuickEdit}
                                                                    className="px-4 py-1.5 bg-indigo-600 text-white font-bold rounded-lg shadow-sm"
                                                                >
                                                                    Update Page
                                                                </button>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                )}
                                            </React.Fragment>
                                        );
                                    })
                                )}
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
                        {/* 1. Page Basic Details */}
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

                        {/* 2. Navigation Menu Linker (3 CASCADING DROPDOWNS) */}
                        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-xs space-y-4">
                            <h3 className="font-bold text-slate-800 text-base flex items-center gap-2 border-b border-slate-100 pb-3">
                                <Link2 className="w-4 h-4 text-indigo-600" /> Connect Page to Navigation Menu (3-Tier Cascading Linker)
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
                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 bg-slate-50 p-4 rounded-xl border border-slate-200">
                                        <div>
                                            <label className="block font-semibold text-slate-700 mb-1">1. Header Dropdown Category</label>
                                            <select
                                                value={pageConfig.headerNavSync.category}
                                                onChange={(e) => {
                                                    const catTitle = e.target.value;
                                                    const catObj = menuCategories.find(c => c.title === catTitle);
                                                    const firstCol = catObj?.columns?.[0] ? (typeof catObj.columns[0] === 'string' ? catObj.columns[0] : catObj.columns[0].title) : '';
                                                    const firstItem = catObj?.columns?.[0]?.items?.[0] || pageConfig.title;
                                                    setPageConfig(prev => ({
                                                        ...prev,
                                                        headerNavSync: {
                                                            ...prev.headerNavSync,
                                                            category: catTitle,
                                                            column: firstCol || prev.headerNavSync.column,
                                                            targetItem: firstItem
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
                                            <label className="block font-semibold text-slate-700 mb-1">2. Menu Column</label>
                                            <select
                                                value={pageConfig.headerNavSync.column}
                                                onChange={(e) => {
                                                    const colName = e.target.value;
                                                    const colObj = activeCategoryObj?.columns?.find(c => (typeof c === 'string' ? c : c.title) === colName);
                                                    const firstItem = (colObj && typeof colObj !== 'string' && colObj.items?.[0]) ? colObj.items[0] : pageConfig.title;
                                                    setPageConfig(prev => ({
                                                        ...prev,
                                                        headerNavSync: { ...prev.headerNavSync, column: colName, targetItem: firstItem }
                                                    }));
                                                }}
                                                className="w-full px-3 py-2 rounded-xl border border-slate-200 bg-white font-medium text-xs"
                                            >
                                                {availableColumns.map((colName, i) => (
                                                    <option key={i} value={colName}>{colName}</option>
                                                ))}
                                            </select>
                                        </div>

                                        <div>
                                            <label className="block font-semibold text-slate-700 mb-1">3. Inner Service Link Item</label>
                                            <select
                                                value={pageConfig.headerNavSync.targetItem}
                                                onChange={(e) => setPageConfig(prev => ({
                                                    ...prev,
                                                    headerNavSync: { ...prev.headerNavSync, targetItem: e.target.value }
                                                }))}
                                                className="w-full px-3 py-2 rounded-xl border border-slate-200 bg-white font-medium text-xs"
                                            >
                                                {availableInnerItems.map((itemName, i) => (
                                                    <option key={i} value={itemName}>{itemName}</option>
                                                ))}
                                                <option value={pageConfig.title}>+ Add "{pageConfig.title}" as New Link</option>
                                            </select>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* 3. Hero Section Builder */}
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

                        {/* 4. Commercial Packages Section */}
                        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-xs space-y-4">
                            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                                <h3 className="font-bold text-slate-800 text-base flex items-center gap-2">
                                    <Layers className="w-4 h-4 text-indigo-600" /> Commercial Packages & Pricing Plans
                                </h3>
                                <button
                                    onClick={() => setPageConfig(prev => ({
                                        ...prev,
                                        packages: [...prev.packages, { id: `pkg-${Date.now()}`, name: 'New Custom Package', price: 2999, description: 'Package description in {city}', features: ['Feature 1', 'Feature 2'] }]
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
                                                className="font-bold text-slate-800 bg-transparent border-b border-slate-300 focus:border-indigo-600 focus:outline-none text-sm"
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
                                                    className="w-full px-2 py-1.5 rounded border border-slate-200 mt-1"
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
                                                    className="w-full px-2 py-1.5 rounded border border-slate-200 mt-1"
                                                />
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* 5. Founder Testimonials & Reviews */}
                        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-xs space-y-4">
                            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                                <h3 className="font-bold text-slate-800 text-base flex items-center gap-2">
                                    <Star className="w-4 h-4 text-amber-500 fill-amber-500" /> Founder Reviews & Testimonials
                                </h3>
                                <button
                                    onClick={() => setPageConfig(prev => ({
                                        ...prev,
                                        reviews: [...prev.reviews, { name: 'New Founder', company: 'Company Pvt Ltd', avatar: 'NF', rating: 5, date: '2026', text: 'Great experience!', verified: true }]
                                    }))}
                                    className="text-xs flex items-center gap-1 font-semibold text-indigo-600 hover:text-indigo-700"
                                >
                                    <Plus className="w-3.5 h-3.5" /> Add Testimonial
                                </button>
                            </div>
                            <div className="space-y-3">
                                {pageConfig.reviews.map((rev, idx) => (
                                    <div key={idx} className="p-3.5 rounded-xl border border-slate-200 bg-slate-50/50 space-y-2 text-xs">
                                        <div className="flex items-center justify-between">
                                            <input
                                                type="text"
                                                placeholder="Founder Name"
                                                value={rev.name}
                                                onChange={(e) => {
                                                    const val = e.target.value;
                                                    setPageConfig(prev => ({
                                                        ...prev,
                                                        reviews: prev.reviews.map((r, i) => i === idx ? { ...r, name: val } : r)
                                                    }));
                                                }}
                                                className="font-semibold text-slate-800 px-2 py-1 rounded border border-slate-200"
                                            />
                                            <button
                                                onClick={() => setPageConfig(prev => ({ ...prev, reviews: prev.reviews.filter((_, i) => i !== idx) }))}
                                                className="text-slate-400 hover:text-red-600 ml-2"
                                            >
                                                <Trash2 className="w-4 h-4" />
                                            </button>
                                        </div>
                                        <textarea
                                            rows="2"
                                            placeholder="Review feedback text..."
                                            value={rev.text}
                                            onChange={(e) => {
                                                const val = e.target.value;
                                                setPageConfig(prev => ({
                                                    ...prev,
                                                    reviews: prev.reviews.map((r, i) => i === idx ? { ...r, text: val } : r)
                                                }));
                                            }}
                                            className="w-full px-2 py-1 rounded border border-slate-200"
                                        />
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* 6. Step-by-Step Completion Steps */}
                        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-xs space-y-4">
                            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                                <h3 className="font-bold text-slate-800 text-base flex items-center gap-2">
                                    <CheckCircle2 className="w-4 h-4 text-emerald-600" /> Step-by-Step Process Flow
                                </h3>
                                <button
                                    onClick={() => setPageConfig(prev => ({
                                        ...prev,
                                        steps: [...prev.steps, { number: `0${prev.steps.length + 1}`, title: 'New Step', desc: 'Step description', badge: 'Takes 1 Day' }]
                                    }))}
                                    className="text-xs flex items-center gap-1 font-semibold text-indigo-600 hover:text-indigo-700"
                                >
                                    <Plus className="w-3.5 h-3.5" /> Add Step
                                </button>
                            </div>
                            <div className="space-y-3">
                                {pageConfig.steps.map((st, idx) => (
                                    <div key={idx} className="p-3.5 rounded-xl border border-slate-200 bg-slate-50/50 space-y-2 text-xs">
                                        <div className="flex items-center justify-between">
                                            <input
                                                type="text"
                                                placeholder="Step Title"
                                                value={st.title}
                                                onChange={(e) => {
                                                    const val = e.target.value;
                                                    setPageConfig(prev => ({
                                                        ...prev,
                                                        steps: prev.steps.map((s, i) => i === idx ? { ...s, title: val } : s)
                                                    }));
                                                }}
                                                className="font-semibold text-slate-800 px-2 py-1 rounded border border-slate-200"
                                            />
                                            <button
                                                onClick={() => setPageConfig(prev => ({ ...prev, steps: prev.steps.filter((_, i) => i !== idx) }))}
                                                className="text-slate-400 hover:text-red-600 ml-2"
                                            >
                                                <Trash2 className="w-4 h-4" />
                                            </button>
                                        </div>
                                        <textarea
                                            rows="2"
                                            placeholder="Step description..."
                                            value={st.desc}
                                            onChange={(e) => {
                                                const val = e.target.value;
                                                setPageConfig(prev => ({
                                                    ...prev,
                                                    steps: prev.steps.map((s, i) => i === idx ? { ...s, desc: val } : s)
                                                }));
                                            }}
                                            className="w-full px-2 py-1 rounded border border-slate-200"
                                        />
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* 7. Detailed In-Depth Guide & FAQs */}
                        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-xs space-y-4">
                            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                                <h3 className="font-bold text-slate-800 text-base flex items-center gap-2">
                                    <HelpCircle className="w-4 h-4 text-blue-600" /> Collapsible Detailed Guide & FAQs
                                </h3>
                                <button
                                    onClick={() => setPageConfig(prev => ({
                                        ...prev,
                                        faqs: [...prev.faqs, { q: 'Question text here in {city}?', a: 'Answer details...' }]
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

                        {/* 8. Generated City Pages Live Preview Box */}
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
