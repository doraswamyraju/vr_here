import React, { useEffect, useMemo, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { ArrowRight, Layers } from 'lucide-react';
import { MENU_DATA, SharedFooter, SharedHeader, getServiceLink } from './components/SharedComponents';

const normalizeServices = (services = []) =>
    services.map((service) => ({
        ...service,
        columns: Array.isArray(service.columns)
            ? service.columns
            : Array.isArray(service.items)
                ? [{ title: 'Services', items: service.items }]
                : [],
    }));

const AllServicesPage = () => {
    const [isScrolled, setIsScrolled] = useState(false);
    const [services, setServices] = useState(normalizeServices(MENU_DATA));
    const location = useLocation();

    const selectedCategory = useMemo(() => {
        const params = new URLSearchParams(location.search);
        return params.get('category');
    }, [location.search]);

    useEffect(() => {
        const onScroll = () => setIsScrolled(window.scrollY > 20);
        window.addEventListener('scroll', onScroll);
        return () => window.removeEventListener('scroll', onScroll);
    }, []);

    useEffect(() => {
        const fetchMenu = async () => {
            try {
                const res = await fetch('/api/services/header-config');
                if (!res.ok) return;
                const data = await res.json();
                if (!Array.isArray(data?.services) || data.services.length === 0) return;
                setServices(normalizeServices(data.services));
            } catch (err) {
                console.error('Failed to load services config', err);
            }
        };
        fetchMenu();
    }, []);

    useEffect(() => {
        if (!selectedCategory) return;
        const target = document.getElementById(`service-${selectedCategory}`);
        if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, [selectedCategory, services]);

    return (
        <div className="min-h-screen bg-slate-50 text-slate-800">
            <SharedHeader isScrolled={isScrolled} />

            <section className="relative overflow-hidden bg-slate-900 text-white pt-20 pb-16">
                <div className="absolute inset-0">
                    <div className="absolute -top-12 left-1/3 h-56 w-56 rounded-full bg-red-600/30 blur-3xl" />
                    <div className="absolute -bottom-12 right-1/4 h-56 w-56 rounded-full bg-orange-500/20 blur-3xl" />
                </div>
                <div className="relative z-10 max-w-7xl mx-auto px-4 text-center">
                    <div className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-white/10 px-4 py-1 text-xs font-bold uppercase tracking-wider">
                        <Layers className="w-3.5 h-3.5" />
                        Complete Service Catalog
                    </div>
                    <h1 className="mt-4 text-4xl md:text-5xl font-black">All Services</h1>
                    <p className="mt-3 text-slate-300 max-w-3xl mx-auto">
                        Explore all categories and sub-services from business setup to compliance, funding, licensing, and industrial support.
                    </p>
                </div>
            </section>

            <section className="max-w-7xl mx-auto px-4 py-12 space-y-8">
                {services.map((service) => (
                    <div
                        key={service.id}
                        id={`service-${service.id}`}
                        className={`rounded-2xl border bg-white p-6 shadow-sm ${selectedCategory === service.id ? 'border-red-300 shadow-red-100/50' : 'border-slate-200'}`}
                    >
                        <h2 className="text-2xl font-black text-slate-900">{service.title}</h2>

                        <div className={`mt-5 grid gap-4 ${service.columns.length >= 3 ? 'lg:grid-cols-3' : service.columns.length === 2 ? 'lg:grid-cols-2' : 'lg:grid-cols-1'}`}>
                            {service.columns.map((column, colIdx) => (
                                <div key={`${service.id}-column-${colIdx}`} className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                                    <h3 className="text-sm font-extrabold text-slate-800 uppercase tracking-wide">{column.title}</h3>
                                    <div className="mt-3 space-y-2">
                                        {(column.items || []).map((item, i) => (
                                            <a key={`${service.id}-${colIdx}-${i}`} href={getServiceLink(item)} className="block text-sm font-medium text-slate-700 hover:text-red-600 transition-colors">
                                                {item}
                                            </a>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </div>

                        <div className="mt-5">
                            <a href={`/contact?service=${encodeURIComponent(service.title)}`} className="inline-flex items-center gap-2 text-sm font-bold text-red-600 hover:text-red-700">
                                Request this category <ArrowRight className="w-4 h-4" />
                            </a>
                        </div>
                    </div>
                ))}
            </section>

            <SharedFooter />
        </div>
    );
};

export default AllServicesPage;
