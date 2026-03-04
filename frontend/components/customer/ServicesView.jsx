import React from 'react';
import {
    Briefcase, Factory, Stamp, Calculator, Globe,
    IndianRupee, Lightbulb, ArrowRight, Search
} from 'lucide-react';

const SERVICES = [
    {
        id: 'registration',
        title: 'Start Business',
        icon: Briefcase,
        color: 'bg-rose-50 text-rose-600',
        description: 'Pvt Ltd, LLP, Section 8, FSSAI, Trade License',
        price: 'From ₹1,999'
    },
    {
        id: 'machinery',
        title: 'Machinery & Industrial',
        icon: Factory,
        color: 'bg-blue-50 text-blue-600',
        description: 'Sourcing, Vendor Verification, Turnkey Setup',
        price: 'Quote Based'
    },
    {
        id: 'iso',
        title: 'Certifications',
        icon: Stamp,
        color: 'bg-amber-50 text-amber-600',
        description: 'ISO 9001, FDA, CE, BIS, HACCP, Halal',
        price: 'From ₹2,499'
    },
    {
        id: 'accounting',
        title: 'Accounting & Tax',
        icon: Calculator,
        color: 'bg-emerald-50 text-emerald-600',
        description: 'GST Returns, Income Tax, Audits, RoC Filings',
        price: 'From ₹499/mo'
    },
    {
        id: 'govt',
        title: 'Govt Portals',
        icon: Globe,
        color: 'bg-indigo-50 text-indigo-600',
        description: 'GeM, TReDS, RERA, Import Export Code',
        price: 'From ₹999'
    },
    {
        id: 'msme',
        title: 'Industrial Consultancy',
        icon: IndianRupee,
        color: 'bg-orange-50 text-orange-600',
        description: 'Project Reports (DPR), Loans, Subsidies',
        price: 'Quote Based'
    }
];

const ServicesView = () => {
    return (
        <div className="space-y-6 pb-20 md:pb-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div className="flex justify-between items-end mb-2 px-1">
                <div>
                    <h1 className="text-2xl lg:text-3xl font-black text-slate-800 tracking-tight">Services Catalog</h1>
                    <p className="text-slate-500 text-sm">Select a specialized service to initiate your business journey.</p>
                </div>
            </div>

            {/* Search Bar */}
            <div className="relative group">
                <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                    <Search size={18} className="text-slate-400 group-focus-within:text-indigo-500 transition-colors" />
                </div>
                <input
                    type="text"
                    placeholder="Search for legal, tax or industrial services..."
                    className="w-full pl-11 pr-4 py-4 bg-white border border-slate-100 rounded-2xl shadow-sm outline-none focus:ring-2 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all text-sm font-medium"
                />
            </div>

            {/* Services Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mt-6">
                {SERVICES.map((service) => (
                    <button
                        key={service.id}
                        className="bg-white p-6 rounded-[32px] border border-slate-100 shadow-sm hover:shadow-xl hover:border-indigo-100 transition-all flex flex-col md:flex-row lg:flex-col items-center md:items-start lg:items-center text-center md:text-left lg:text-center gap-4 group"
                    >
                        <div className={`w-16 h-16 ${service.color} rounded-2xl flex items-center justify-center shrink-0 group-hover:scale-110 transition-transform`}>
                            <service.icon size={28} />
                        </div>
                        <div className="flex-1 min-w-0">
                            <h3 className="font-black text-slate-800 text-sm lg:text-base mb-1 group-hover:text-indigo-600 transition-colors">{service.title}</h3>
                            <p className="text-[11px] lg:text-xs text-slate-400 font-bold uppercase tracking-wider mb-2">{service.description}</p>
                            <div className="flex items-center justify-center md:justify-start lg:justify-center gap-2">
                                <span className="px-3 py-1 bg-slate-50 text-[10px] font-black text-slate-500 rounded-lg uppercase tracking-widest">{service.price}</span>
                                <div className="w-8 h-8 rounded-full bg-indigo-50 flex items-center justify-center text-indigo-600 transition-all group-hover:translate-x-1 lg:hidden">
                                    <ArrowRight size={14} />
                                </div>
                            </div>
                        </div>
                    </button>
                ))}
            </div>

            {/* Custom Request Card */}
            <div className="bg-slate-900 rounded-[40px] p-8 text-white overflow-hidden relative group mt-12">
                <div className="absolute top-0 right-0 w-64 h-64 bg-indigo-500/10 rounded-full -mr-32 -mt-32 blur-3xl"></div>
                <div className="relative z-10 flex flex-col lg:flex-row items-center justify-between gap-8">
                    <div className="flex flex-col lg:flex-row items-center lg:items-start gap-6">
                        <div className="w-16 h-16 bg-white/10 rounded-[24px] flex items-center justify-center shadow-xl">
                            <Lightbulb className="text-amber-400" size={32} />
                        </div>
                        <div className="text-center lg:text-left">
                            <h4 className="font-black text-2xl mb-2 tracking-tight">Need a custom business solution?</h4>
                            <p className="text-slate-400 text-sm leading-relaxed max-w-xl">Our multidisciplinary experts can create tailored end-to-end setups, feasiblity reports, and turnkey projects specifically for your industry.</p>
                        </div>
                    </div>
                    <button className="whitespace-nowrap bg-indigo-600 hover:bg-indigo-500 text-white px-10 py-4 rounded-2xl text-sm font-black transition-all shadow-2xl shadow-indigo-900/40 hover:-translate-y-1 active:translate-y-0">
                        Consult Expert
                    </button>
                </div>
            </div>
        </div>
    );
};

export default ServicesView;
