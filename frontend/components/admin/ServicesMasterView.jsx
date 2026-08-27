import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Plus, Trash2, Save, Upload, Loader2 } from 'lucide-react';
import { MENU_DATA } from '../SharedComponents';
import ServicePagesBuilder from './ServicePagesBuilder';
import UnifiedPageManager from './UnifiedPageManager';

const toEditableSeed = () =>
    MENU_DATA.map((service) => ({
        id: service.id,
        title: service.title,
        iconKey: service.iconKey || 'Briefcase',
        columns: Array.isArray(service.columns) ? service.columns : [],
        offers: [],
    }));

const normalizeServices = (services = []) =>
    services.map((service) => ({
        ...service,
        columns: Array.isArray(service.columns)
            ? service.columns
            : Array.isArray(service.items)
                ? [{ title: 'Services', items: service.items }]
                : [],
        offers: Array.isArray(service.offers) ? service.offers : [],
    }));

const ServicesMasterView = ({ token }) => {
    const [activeSubTab, setActiveSubTab] = useState('header'); // 'header' or 'pages'
    const [services, setServices] = useState(toEditableSeed());
    const [tickerMessages, setTickerMessages] = useState([
        'New: Income Tax return filing support now available.',
        'Startup consultation fee is adjustable against package purchase.',
        'Get faster support for registrations and certifications.',
    ]);
    const [capsules, setCapsules] = useState([]);
    const [isSaving, setIsSaving] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const [message, setMessage] = useState('');

    const authConfig = { headers: { Authorization: `Bearer ${token}` } };

    const updateService = (serviceIndex, updater) => {
        setServices((prev) =>
            prev.map((service, idx) => (idx === serviceIndex ? updater(service) : service))
        );
    };

    const fetchConfig = async () => {
        setIsLoading(true);
        try {
            const { data } = await axios.get('/api/services/header-config');
            if (Array.isArray(data?.services) && data.services.length > 0) {
                setServices(normalizeServices(data.services));
            }
            if (Array.isArray(data?.tickerMessages)) {
                setTickerMessages(data.tickerMessages);
            }
            if (Array.isArray(data?.capsules)) {
                setCapsules(data.capsules);
            }
        } catch (error) {
            console.error('Failed to load services header config', error);
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchConfig();
    }, []);

    const saveAll = async () => {
        setIsSaving(true);
        setMessage('');
        try {
            const payload = {
                tickerMessages: (tickerMessages || []).map((m) => m.trim()).filter(Boolean),
                services: services.map((service) => ({
                    id: (service.id || '').trim(),
                    title: (service.title || '').trim(),
                    iconKey: (service.iconKey || 'Briefcase').trim(),
                    columns: (service.columns || [])
                        .map((column) => ({
                            title: (column.title || '').trim(),
                            items: (column.items || []).map((item) => item.trim()).filter(Boolean),
                        }))
                        .filter((column) => column.title && column.items.length > 0),
                    offers: (service.offers || [])
                        .map((offer) => ({
                            ...offer,
                            title: (offer.title || '').trim(),
                            imageUrl: (offer.imageUrl || '').trim(),
                            ctaLink: (offer.ctaLink || '/contact').trim(),
                        }))
                        .filter((offer) => offer.title && offer.imageUrl),
                })).filter((service) => service.id && service.title),
                capsules: capsules.map((cap) => ({
                    text: (cap.text || '').trim(),
                    link: (cap.link || '').trim(),
                })).filter((cap) => cap.text && cap.link),
            };

            await axios.put('/api/services/header-config', payload, authConfig);
            setMessage('Services config updated successfully.');
            await fetchConfig();
        } catch (error) {
            console.error('Failed to save services config', error);
            setMessage(error?.response?.data?.message || 'Failed to save services config.');
        } finally {
            setIsSaving(false);
        }
    };

    const uploadOfferImage = async (serviceId, offerId, file) => {
        if (!file) return;
        const formData = new FormData();
        formData.append('image', file);
        try {
            const { data } = await axios.post(
                `/api/services/header-config/${serviceId}/offers/${offerId}/image`,
                formData,
                {
                    headers: {
                        ...authConfig.headers,
                        'Content-Type': 'multipart/form-data',
                    },
                }
            );
            setServices((prev) =>
                prev.map((service) =>
                    service.id !== serviceId
                        ? service
                        : {
                            ...service,
                            offers: (service.offers || []).map((offer) =>
                                offer._id !== offerId ? offer : { ...offer, imageUrl: data.imageUrl }
                            ),
                        }
                )
            );
            setMessage('Offer image uploaded.');
        } catch (error) {
            console.error('Image upload failed', error);
            setMessage(error?.response?.data?.message || 'Image upload failed.');
        }
    };

    if (isLoading) {
        return (
            <div className="h-64 flex items-center justify-center text-slate-500">
                <Loader2 className="w-5 h-5 animate-spin mr-2" /> Loading services config...
            </div>
        );
    }

    return (
        <div className="animate-in fade-in duration-300">
            {/* Unified Sub-tab Segmented Controller */}
            <div className="flex border border-slate-200 rounded-2xl mb-6 bg-slate-50/50 p-1 max-w-md shadow-sm">
                <button
                    onClick={() => setActiveSubTab('header')}
                    className={`flex-1 text-center py-2 rounded-xl font-bold text-xs uppercase tracking-wider transition ${activeSubTab === 'header' ? 'bg-white text-slate-900 shadow border border-slate-200/50' : 'text-slate-500 hover:text-slate-800'}`}
                >
                    Global Header Settings
                </button>
                <button
                    onClick={() => setActiveSubTab('pages')}
                    className={`flex-1 text-center py-2 rounded-xl font-bold text-xs uppercase tracking-wider transition ${activeSubTab === 'pages' ? 'bg-white text-slate-900 shadow border border-slate-200/50' : 'text-slate-500 hover:text-slate-800'}`}
                >
                    Landing Pages & SEO/AEO
                </button>
            </div>

            {activeSubTab === 'pages' ? (
                <UnifiedPageManager token={token} />
            ) : (
                <>
                    <div className="mb-6 flex items-center justify-between">
                        <div className="text-left">
                            <h2 className="text-2xl font-bold text-slate-800">Services Master</h2>
                            <p className="text-slate-500">Manage header tabs, dropdown columns, dynamic hero tags, and latest offers.</p>
                        </div>
                        <button
                            onClick={saveAll}
                            disabled={isSaving}
                            className="inline-flex items-center gap-2 bg-indigo-600 text-white px-5 py-2.5 rounded-xl font-bold text-sm hover:bg-indigo-700 disabled:opacity-60"
                        >
                            {isSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                            Save Changes
                        </button>
                    </div>

                    {message && (
                        <div className="mb-4 px-4 py-3 bg-white border border-slate-200 rounded-xl text-sm text-slate-700">
                            {message}
                        </div>
                    )}

                    <div className="mb-5 bg-white border border-slate-200 rounded-2xl p-5 shadow-sm">
                        <div className="flex items-center justify-between mb-3">
                            <h3 className="font-bold text-slate-800">Top Bar Ticker (Latest Updates)</h3>
                            <button
                                onClick={() => setTickerMessages((prev) => [...prev, ''])}
                                className="text-xs font-bold text-indigo-600 inline-flex items-center gap-1"
                            >
                                <Plus className="w-3 h-3" /> Add Message
                            </button>
                        </div>
                        <div className="space-y-2">
                            {tickerMessages.map((msg, idx) => (
                                <div key={`ticker-${idx}`} className="flex gap-2">
                                    <input
                                        value={msg}
                                        onChange={(e) =>
                                            setTickerMessages((prev) => prev.map((x, i) => (i === idx ? e.target.value : x)))
                                        }
                                        className="flex-1 border border-slate-300 rounded-lg px-3 py-2 text-sm"
                                        placeholder="Ticker message"
                                    />
                                    <button
                                        onClick={() => setTickerMessages((prev) => prev.filter((_, i) => i !== idx))}
                                        className="p-2 rounded-lg border border-rose-200 text-rose-600 hover:bg-rose-50"
                                    >
                                        <Trash2 className="w-4 h-4" />
                                    </button>
                                </div>
                            ))}
                        </div>
                    </div>

                    <div className="mb-5 bg-white border border-slate-200 rounded-2xl p-5 shadow-sm">
                        <div className="flex items-center justify-between mb-4">
                            <div>
                                <h3 className="font-bold text-slate-800">Hero Section Interactive Capsules</h3>
                                <p className="text-xs text-slate-500 mt-0.5">Manage up to 10 service tags that fall, drift, and can be thrown inside the Hero section background. Clicking a capsule opens that service page.</p>
                            </div>
                            <div className="flex items-center gap-3">
                                <span className={`text-xs font-bold px-2.5 py-1 rounded-lg ${capsules.length >= 10 ? 'bg-rose-100 text-rose-700 border border-rose-200' : 'bg-indigo-50 text-indigo-700 border border-indigo-150'}`}>
                                    {capsules.length} / 10 Tags
                                </span>
                                <button
                                    onClick={() => setCapsules((prev) => [...prev, { text: '', link: '' }])}
                                    disabled={capsules.length >= 10}
                                    className="text-xs font-bold text-indigo-600 inline-flex items-center gap-1 disabled:opacity-50 disabled:cursor-not-allowed"
                                >
                                    <Plus className="w-3 h-3" /> Add Tag
                                </button>
                            </div>
                        </div>

                        {capsules.length === 0 ? (
                            <p className="text-xs text-slate-400 italic py-6 text-center border border-dashed border-slate-200 rounded-xl bg-slate-50">No capsules defined. Add at least one to show on the hero section.</p>
                        ) : (
                            <div className="grid md:grid-cols-2 gap-4 max-h-[360px] overflow-y-auto pr-1">
                                {capsules.map((cap, idx) => (
                                    <div key={idx} className="flex gap-3 items-center p-3 rounded-2xl border border-slate-200 bg-slate-50/50 hover:bg-slate-50 transition relative group">
                                        <div className="flex-1 space-y-2">
                                            <input
                                                value={cap.text}
                                                onChange={(e) =>
                                                    setCapsules((prev) => prev.map((x, i) => (i === idx ? { ...x, text: e.target.value } : x)))
                                                }
                                                className="w-full border border-slate-350 rounded-lg px-3 py-1.5 text-xs font-bold text-slate-700 bg-white"
                                                placeholder="Capsule Label (e.g. GST Registration)"
                                            />
                                            <div className="flex gap-2">
                                                <select
                                                    value={cap.link}
                                                    onChange={(e) =>
                                                        setCapsules((prev) => prev.map((x, i) => (i === idx ? { ...x, link: e.target.value } : x)))
                                                    }
                                                    className="flex-1 border border-slate-300 rounded-lg px-2 py-1 text-xs bg-white text-slate-600 outline-none"
                                                >
                                                    <option value="">-- Service Page --</option>
                                                    <option value="/pvt-ltd-registration">Private Limited Registration</option>
                                                    <option value="/public-limited-company">Public Limited Company</option>
                                                    <option value="/llp-registration">LLP Registration</option>
                                                    <option value="/partnership-firm-registration">Partnership Firm Registration</option>
                                                    <option value="/proprietorship-setup">Proprietorship Setup</option>
                                                    <option value="/section-8-company">Section 8 Company (NGO)</option>
                                                    <option value="/one-person-company">One Person Company (OPC)</option>
                                                    <option value="/society-trust-registration">Society & Trust Registration</option>
                                                    <option value="/gst-registration">GST Registration</option>
                                                    <option value="/income-tax-return">Income Tax Return Filing</option>
                                                    <option value="/accounting-services">Accounting Services</option>
                                                    <option value="/compliance-scheme-2026">Companies Compliance Scheme 2026</option>
                                                    <option value="/all-services">All Services Page</option>
                                                    <option value="/contact">Contact Us / Inquiry</option>
                                                </select>
                                                <input
                                                    value={cap.link}
                                                    onChange={(e) =>
                                                        setCapsules((prev) => prev.map((x, i) => (i === idx ? { ...x, link: e.target.value } : x)))
                                                    }
                                                    className="flex-1 border border-slate-300 rounded-lg px-3 py-1 text-[11px] bg-white"
                                                    placeholder="Or custom link"
                                                />
                                            </div>
                                        </div>
                                        <button
                                            onClick={() => setCapsules((prev) => prev.filter((_, i) => i !== idx))}
                                            className="p-2.5 rounded-xl border border-rose-200 text-rose-600 hover:bg-rose-50 hover:text-rose-700 transition"
                                        >
                                            <Trash2 className="w-4 h-4" />
                                        </button>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    <div className="space-y-5">
                        {services.map((service, serviceIndex) => (
                            <div key={service.id || serviceIndex} className="bg-white border border-slate-200 rounded-2xl p-5 shadow-sm">
                                <div className="grid md:grid-cols-3 gap-4 mb-4">
                                    <input
                                        value={service.title}
                                        onChange={(e) => updateService(serviceIndex, (s) => ({ ...s, title: e.target.value }))}
                                        className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm font-semibold"
                                        placeholder="Main tab title"
                                    />
                                    <input
                                        value={service.id}
                                        onChange={(e) => updateService(serviceIndex, (s) => ({ ...s, id: e.target.value }))}
                                        className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                                        placeholder="tab id"
                                    />
                                    <input
                                        value={service.iconKey || ''}
                                        onChange={(e) => updateService(serviceIndex, (s) => ({ ...s, iconKey: e.target.value }))}
                                        className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                                        placeholder="Icon key"
                                    />
                                </div>

                                <div className="grid lg:grid-cols-2 gap-6">
                                    <div>
                                        <div className="flex items-center justify-between mb-2">
                                            <h3 className="font-bold text-slate-800">Dropdown Columns</h3>
                                            <button
                                                onClick={() =>
                                                    updateService(serviceIndex, (s) => ({
                                                        ...s,
                                                        columns: [...(s.columns || []), { title: '', items: [''] }],
                                                    }))
                                                }
                                                className="text-xs font-bold text-indigo-600 inline-flex items-center gap-1"
                                            >
                                                <Plus className="w-3 h-3" /> Add Column
                                            </button>
                                        </div>

                                        <div className="space-y-3">
                                            {(service.columns || []).map((column, colIndex) => (
                                                <div key={`${service.id}-col-${colIndex}`} className="border border-slate-200 rounded-xl p-3 bg-slate-50">
                                                    <div className="flex gap-2 mb-2">
                                                        <input
                                                            value={column.title || ''}
                                                            onChange={(e) =>
                                                                updateService(serviceIndex, (s) => ({
                                                                    ...s,
                                                                    columns: (s.columns || []).map((c, idx) => (idx === colIndex ? { ...c, title: e.target.value } : c)),
                                                                }))
                                                            }
                                                            className="flex-1 border border-slate-300 rounded-lg px-3 py-2 text-sm font-semibold"
                                                            placeholder="Column title"
                                                        />
                                                        <button
                                                            onClick={() =>
                                                                updateService(serviceIndex, (s) => ({
                                                                    ...s,
                                                                    columns: (s.columns || []).filter((_, idx) => idx !== colIndex),
                                                                }))
                                                            }
                                                            className="p-2 rounded-lg border border-rose-200 text-rose-600 hover:bg-rose-50"
                                                        >
                                                            <Trash2 className="w-4 h-4" />
                                                        </button>
                                                    </div>

                                                    <div className="space-y-2">
                                                        {(column.items || []).map((item, itemIndex) => (
                                                            <div key={`${service.id}-col-${colIndex}-item-${itemIndex}`} className="flex gap-2">
                                                                <input
                                                                    value={item}
                                                                    onChange={(e) =>
                                                                        updateService(serviceIndex, (s) => ({
                                                                            ...s,
                                                                            columns: (s.columns || []).map((c, idx) =>
                                                                                idx !== colIndex
                                                                                    ? c
                                                                                    : {
                                                                                        ...c,
                                                                                        items: (c.items || []).map((x, innerIdx) => (innerIdx === itemIndex ? e.target.value : x)),
                                                                                    }
                                                                            ),
                                                                        }))
                                                                    }
                                                                    className="flex-1 border border-slate-300 rounded-lg px-3 py-2 text-sm"
                                                                    placeholder="Service name"
                                                                />
                                                                <button
                                                                    onClick={() =>
                                                                        updateService(serviceIndex, (s) => ({
                                                                            ...s,
                                                                            columns: (s.columns || []).map((c, idx) =>
                                                                                idx !== colIndex
                                                                                    ? c
                                                                                    : { ...c, items: (c.items || []).filter((_, innerIdx) => innerIdx !== itemIndex) }
                                                                            ),
                                                                        }))
                                                                    }
                                                                    className="p-2 rounded-lg border border-rose-200 text-rose-600 hover:bg-rose-50"
                                                                >
                                                                    <Trash2 className="w-4 h-4" />
                                                                </button>
                                                            </div>
                                                        ))}
                                                        <button
                                                            onClick={() =>
                                                                updateService(serviceIndex, (s) => ({
                                                                    ...s,
                                                                    columns: (s.columns || []).map((c, idx) =>
                                                                        idx !== colIndex ? c : { ...c, items: [...(c.items || []), ''] }
                                                                    ),
                                                                }))
                                                            }
                                                            className="text-xs font-bold text-indigo-600 inline-flex items-center gap-1"
                                                        >
                                                            <Plus className="w-3 h-3" /> Add Service
                                                        </button>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>

                                    <div>
                                        <div className="flex items-center justify-between mb-2">
                                            <h3 className="font-bold text-slate-800">Latest Offers</h3>
                                            <button
                                                onClick={() =>
                                                    updateService(serviceIndex, (s) => ({
                                                        ...s,
                                                        offers: [...(s.offers || []), { title: '', imageUrl: '', ctaLink: '/contact' }],
                                                    }))
                                                }
                                                className="text-xs font-bold text-indigo-600 inline-flex items-center gap-1"
                                            >
                                                <Plus className="w-3 h-3" /> Add Offer
                                            </button>
                                        </div>
                                        <div className="space-y-3">
                                            {(service.offers || []).map((offer, offerIndex) => (
                                                <div key={offer._id || `${service.id}-offer-${offerIndex}`} className="border border-slate-200 rounded-xl p-3 bg-slate-50">
                                                    <div className="space-y-2">
                                                        <input
                                                            value={offer.title || ''}
                                                            onChange={(e) =>
                                                                updateService(serviceIndex, (s) => ({
                                                                    ...s,
                                                                    offers: (s.offers || []).map((x, idx) => (idx === offerIndex ? { ...x, title: e.target.value } : x)),
                                                                }))
                                                            }
                                                            className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                                                            placeholder="Offer title"
                                                        />
                                                        <input
                                                            value={offer.imageUrl || ''}
                                                            onChange={(e) =>
                                                                updateService(serviceIndex, (s) => ({
                                                                    ...s,
                                                                    offers: (s.offers || []).map((x, idx) => (idx === offerIndex ? { ...x, imageUrl: e.target.value } : x)),
                                                                }))
                                                            }
                                                            className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                                                            placeholder="Offer image URL"
                                                        />
                                                        <input
                                                            value={offer.ctaLink || ''}
                                                            onChange={(e) =>
                                                                updateService(serviceIndex, (s) => ({
                                                                    ...s,
                                                                    offers: (s.offers || []).map((x, idx) => (idx === offerIndex ? { ...x, ctaLink: e.target.value } : x)),
                                                                }))
                                                            }
                                                            className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                                                            placeholder="Offer link"
                                                        />
                                                    </div>
                                                    <div className="mt-2 flex items-center justify-between">
                                                        <label className="inline-flex items-center gap-2 text-xs font-bold text-indigo-600 cursor-pointer">
                                                            <Upload className="w-3 h-3" />
                                                            Upload image
                                                            <input
                                                                type="file"
                                                                accept="image/*"
                                                                className="hidden"
                                                                onChange={(e) => uploadOfferImage(service.id, offer._id, e.target.files?.[0])}
                                                                disabled={!offer._id}
                                                            />
                                                        </label>
                                                        <button
                                                            onClick={() =>
                                                                updateService(serviceIndex, (s) => ({
                                                                    ...s,
                                                                    offers: (s.offers || []).filter((_, idx) => idx !== offerIndex),
                                                                }))
                                                            }
                                                            className="text-rose-600 text-xs font-bold"
                                                        >
                                                            Remove
                                                        </button>
                                                    </div>
                                                    {!offer._id && (
                                                        <p className="text-[11px] text-slate-500 mt-1">Save once to enable direct image uploads for this offer.</p>
                                                    )}
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </>
            )}
        </div>
    );
};

export default ServicesMasterView;
