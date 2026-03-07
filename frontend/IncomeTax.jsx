import React, { useEffect, useState } from 'react';
import { CheckCircle2, ArrowRight, FileCheck, ShieldCheck } from 'lucide-react';
import { SharedFooter, SharedHeader } from './components/SharedComponents';

const IncomeTaxPage = () => {
    const [isScrolled, setIsScrolled] = useState(false);

    useEffect(() => {
        const onScroll = () => setIsScrolled(window.scrollY > 20);
        window.addEventListener('scroll', onScroll);
        return () => window.removeEventListener('scroll', onScroll);
    }, []);

    return (
        <div className="min-h-screen bg-white text-slate-800">
            <SharedHeader isScrolled={isScrolled} />

            <section className="relative overflow-hidden bg-slate-900 text-white pt-20 pb-16">
                <div className="absolute inset-0">
                    <div className="absolute -top-10 right-10 h-56 w-56 rounded-full bg-red-600/30 blur-3xl" />
                    <div className="absolute -bottom-12 left-10 h-56 w-56 rounded-full bg-orange-500/25 blur-3xl" />
                </div>
                <div className="relative z-10 max-w-6xl mx-auto px-4">
                    <h1 className="text-4xl md:text-5xl font-black">Income Tax Return Filing</h1>
                    <p className="mt-4 max-w-2xl text-slate-300">
                        End-to-end ITR filing support for salaried, professionals, businesses, and NGOs with compliance-first review.
                    </p>
                    <a href="/contact?service=Income Tax Return Filing" className="inline-flex items-center gap-2 mt-6 bg-red-600 hover:bg-red-700 px-5 py-3 rounded-lg font-bold text-sm">
                        Get Started <ArrowRight className="w-4 h-4" />
                    </a>
                </div>
            </section>

            <section className="max-w-6xl mx-auto px-4 py-14">
                <div className="grid md:grid-cols-3 gap-6">
                    {[
                        'ITR 1 to ITR 7 filing support',
                        'Tax computation and deduction review',
                        'Advance tax and self-assessment guidance',
                        'Capital gains and property income treatment',
                        'Notice response and compliance support',
                        'Secure document handling and audit-ready files',
                    ].map((item) => (
                        <div key={item} className="rounded-xl border border-slate-200 p-5 bg-slate-50">
                            <div className="flex items-start gap-2 text-slate-700">
                                <CheckCircle2 className="w-5 h-5 text-green-600 mt-0.5" />
                                <span className="font-medium text-sm">{item}</span>
                            </div>
                        </div>
                    ))}
                </div>

                <div className="mt-10 rounded-2xl border border-slate-200 p-6 bg-white shadow-sm">
                    <h2 className="text-2xl font-black text-slate-900">Why choose VR HERE for ITR?</h2>
                    <div className="mt-4 grid md:grid-cols-2 gap-4 text-sm">
                        <div className="flex items-center gap-2"><FileCheck className="w-4 h-4 text-red-600" /> Expert review before final submission</div>
                        <div className="flex items-center gap-2"><ShieldCheck className="w-4 h-4 text-red-600" /> Data confidentiality and secure process</div>
                    </div>
                </div>
            </section>

            <SharedFooter />
        </div>
    );
};

export default IncomeTaxPage;
