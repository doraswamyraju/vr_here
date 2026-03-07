import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Plus, Trash2, Save, Upload, Loader2 } from 'lucide-react';
import { MENU_DATA } from '../SharedComponents';

const toEditableSeed = () =>
    MENU_DATA.map((service) => ({
        id: service.id,
        title: service.title,
        iconKey: service.iconKey || 'Briefcase',
        items: service.items || [],
        offers: [],
    }));

const ServicesMasterView = ({ token }) => {
    const [services, setServices] = useState(toEditableSeed());
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
                setServices(data.services);
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
                services: services.map((service) => ({
                    ...service,
                    items: (service.items || []).map((item) => item.trim()).filter(Boolean),
                    offers: (service.offers || []).map((offer) => ({
                        ...offer,
                        title: (offer.title || '').trim(),
                        imageUrl: (offer.imageUrl || '').trim(),
                        ctaLink: (offer.ctaLink || '/contact').trim(),
                    })).filter((offer) => offer.title && offer.imageUrl),
                })),
            };
            await axios.put('/api/services/header-config', payload, authConfig);
            setMessage('Services menu updated successfully.');
            await fetchConfig();
        } catch (error) {
            console.error('Failed to save services menu', error);
            setMessage(error?.response?.data?.message || 'Failed to save services menu.');
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
        <div className="animate-in fade-in zoom-in duration-300">
            <div className="mb-6 flex items-center justify-between">
                <div className="text-left">
                    <h2 className="text-2xl font-bold text-slate-800">Services Master</h2>
                    <p className="text-slate-500">Header main services, sub-services, and latest offer images.</p>
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

            <div className="space-y-5">
                {services.map((service, serviceIndex) => (
                    <div key={service.id} className="bg-white border border-slate-200 rounded-2xl p-5 shadow-sm">
                        <div className="grid md:grid-cols-3 gap-4 mb-4">
                            <input
                                value={service.title}
                                onChange={(e) => updateService(serviceIndex, (s) => ({ ...s, title: e.target.value }))}
                                className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm font-semibold"
                                placeholder="Main service title"
                            />
                            <input
                                value={service.id}
                                onChange={(e) => updateService(serviceIndex, (s) => ({ ...s, id: e.target.value }))}
                                className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                                placeholder="service id"
                            />
                            <input
                                value={service.iconKey || ''}
                                onChange={(e) => updateService(serviceIndex, (s) => ({ ...s, iconKey: e.target.value }))}
                                className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                                placeholder="Icon key (Factory, Briefcase...)"
                            />
                        </div>

                        <div className="grid lg:grid-cols-2 gap-6">
                            <div>
                                <div className="flex items-center justify-between mb-2">
                                    <h3 className="font-bold text-slate-800">Sub-services</h3>
                                    <button
                                        onClick={() => updateService(serviceIndex, (s) => ({ ...s, items: [...(s.items || []), ''] }))}
                                        className="text-xs font-bold text-indigo-600 inline-flex items-center gap-1"
                                    >
                                        <Plus className="w-3 h-3" /> Add
                                    </button>
                                </div>
                                <div className="space-y-2">
                                    {(service.items || []).map((item, itemIndex) => (
                                        <div key={`${service.id}-item-${itemIndex}`} className="flex gap-2">
                                            <input
                                                value={item}
                                                onChange={(e) =>
                                                    updateService(serviceIndex, (s) => ({
                                                        ...s,
                                                        items: (s.items || []).map((x, idx) => (idx === itemIndex ? e.target.value : x)),
                                                    }))
                                                }
                                                className="flex-1 border border-slate-300 rounded-lg px-3 py-2 text-sm"
                                                placeholder="Sub-service name"
                                            />
                                            <button
                                                onClick={() =>
                                                    updateService(serviceIndex, (s) => ({
                                                        ...s,
                                                        items: (s.items || []).filter((_, idx) => idx !== itemIndex),
                                                    }))
                                                }
                                                className="p-2 rounded-lg border border-rose-200 text-rose-600 hover:bg-rose-50"
                                            >
                                                <Trash2 className="w-4 h-4" />
                                            </button>
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
        </div>
    );
};

export default ServicesMasterView;
