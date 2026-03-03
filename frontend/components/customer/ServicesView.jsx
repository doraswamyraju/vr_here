import React from 'react';
import {
    Briefcase, Factory, Stamp, Calculator, Globe,
    IndianRupee, Lightbulb, MoreHorizontal, ArrowRight, Search
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
                    <h1 className="text-2xl font-black text-slate-800 tracking-tight">Our Services</h1>
                    <p className="text-slate-500 text-sm">Select a service to get started.</p>
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
                    className="w-full pl-11 pr-4 py-3.5 bg-white border border-slate-100 rounded-2xl shadow-sm outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all text-sm font-medium"
                />
            </div>

            {/* Services Grid */}
            <div className="grid grid-cols-1 gap-4 mt-6">
                {SERVICES.map((service) => (
                    <button
                        key={service.id}
                        className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm hover:shadow-md hover:border-indigo-100 transition-all flex items-center gap-4 text-left group"
                    >
                        <div className={`w-14 h-14 ${service.color} rounded-2xl flex items-center justify-center shrink-0 group-hover:scale-110 transition-transform`}>
                            <service.icon size={24} />
                        </div>
                        <div className="flex-1 min-w-0">
                            <h3 className="font-bold text-slate-800 text-sm mb-0.5 group-hover:text-indigo-600 transition-colors">{service.title}</h3>
                            <p className="text-[11px] text-slate-400 font-medium line-clamp-1 mb-1">{service.description}</p>
                            <span className="text-[10px] font-black text-slate-500 uppercase tracking-wider">{service.price}</span>
                        </div>
                        <div className="w-8 h-8 rounded-full bg-slate-50 flex items-center justify-center text-slate-300 group-hover:bg-indigo-50 group-hover:text-indigo-500 transition-colors">
                            <ArrowRight size={16} />
                        </div>
                    </button>
                ))}
            </div>

            {/* Custom Request Card */}
            <div className="bg-slate-900 rounded-3xl p-6 text-white overflow-hidden relative group">
                <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/10 rounded-full -mr-16 -mt-16 blur-2xl"></div>
                <div className="relative z-10 flex flex-col gap-4">
                    <div className="w-12 h-12 bg-white/10 rounded-2xl flex items-center justify-center">
                        <Lightbulb className="text-amber-400" size={24} />
                    </div>
                    <div>
                        <h4 className="font-black text-lg mb-1 tracking-tight">Need something else?</h4>
                        <p className="text-slate-400 text-xs leading-relaxed mb-4">Tell us your specific requirement and our experts will create a custom solution for you.</p>
                        <button className="w-full bg-indigo-600 hover:bg-indigo-500 text-white py-3 rounded-xl text-sm font-black transition-all shadow-lg shadow-indigo-900/20">
                            Contact Expert
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ServicesView;
