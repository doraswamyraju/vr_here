import React, { useEffect, useState } from 'react';
import { SharedHeader, SharedFooter } from './components/SharedComponents';

const sections = [
    {
        title: '1. Scope of Engagement',
        content:
            'These Terms and Conditions govern the professional engagement between VR HERE Business Management Solutions and the Client for accounting, bookkeeping, payroll, GST, TDS, and allied compliance services. Services are limited strictly to the scope agreed in writing.',
    },
    {
        title: '2. Client Responsibilities',
        content:
            'The Client is solely responsible for providing complete, accurate, and timely information/documents. VR HERE is not responsible for consequences arising from delayed, inaccurate, incomplete, or misleading information supplied by the Client.',
    },
    {
        title: '3. Timelines and Delays',
        content:
            'All timelines are indicative and depend on client cooperation and portal/system availability. Delays caused by client non-cooperation, non-payment, or government portal issues automatically extend timelines.',
    },
    {
        title: '4. Fees and Payments',
        content:
            'Professional fees are payable as per agreed quotation/package without set-off or deduction. Government/statutory fees, penalties, and levies are extra unless expressly included. Fees once paid are non-refundable. Services may be suspended for non-payment.',
    },
    {
        title: '5. Confidentiality',
        content:
            'VR HERE will maintain confidentiality of client information, except where disclosure is required by law, regulation, court order, or due to client acts/omissions.',
    },
    {
        title: '6. Communications and Authorizations',
        content:
            'Email/messages and electronic communications from the Client are treated as valid instructions and approvals.',
    },
    {
        title: '7. Limitation of Liability',
        content:
            'VR HERE does not guarantee approvals or outcomes. Liability, if any, is limited to the professional fee received for the specific service. VR HERE is not liable for indirect/consequential losses, penalties due to client defaults, or portal/system/legal changes.',
    },
    {
        title: '8. Indemnity',
        content:
            'The Client agrees to indemnify and hold harmless VR HERE and its team from losses/claims/costs arising due to misrepresentation, non-disclosure, statutory non-compliance, or breach of these terms by the Client.',
    },
    {
        title: '9. Termination',
        content:
            'Either party may terminate in writing. All outstanding dues become immediately payable. VR HERE may withhold further services until full settlement.',
    },
    {
        title: '10. Force Majeure',
        content:
            'VR HERE is not liable for delay/failure due to events beyond reasonable control including government action, portal failure, system outage, and regulatory restrictions.',
    },
    {
        title: '11. Governing Law and Jurisdiction',
        content:
            'These terms are governed by the laws of India. Disputes are subject to the exclusive jurisdiction of competent courts in the State of Telangana.',
    },
    {
        title: '12. Acceptance',
        content:
            'By availing our services, the Client confirms they have read, understood, and agreed to these Terms and Conditions.',
    },
];

const TermsConditionsPage = () => {
    const [isScrolled, setIsScrolled] = useState(false);

    useEffect(() => {
        const onScroll = () => setIsScrolled(window.scrollY > 20);
        window.addEventListener('scroll', onScroll);
        return () => window.removeEventListener('scroll', onScroll);
    }, []);

    return (
        <div className="min-h-screen bg-slate-50 text-slate-800">
            <SharedHeader isScrolled={isScrolled} />
            <section className="pt-24 pb-14 bg-slate-900 text-white">
                <div className="max-w-5xl mx-auto px-4">
                    <h1 className="text-4xl md:text-5xl font-black">Terms & Conditions</h1>
                    <p className="mt-4 text-slate-300 max-w-3xl">
                        Terms governing accounting and compliance services provided by VR HERE Business Management Solutions.
                    </p>
                </div>
            </section>

            <section className="max-w-5xl mx-auto px-4 py-10 space-y-5">
                {sections.map((section) => (
                    <article key={section.title} className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
                        <h2 className="text-lg font-black text-slate-900">{section.title}</h2>
                        <p className="text-slate-600 mt-3 leading-relaxed">{section.content}</p>
                    </article>
                ))}
            </section>
            <SharedFooter />
        </div>
    );
};

export default TermsConditionsPage;
