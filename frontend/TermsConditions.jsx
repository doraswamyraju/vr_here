import React, { useEffect, useState } from 'react';
import { SharedHeader, SharedFooter } from './components/SharedComponents';

const paragraphs = [
    "These Terms and Conditions govern the professional engagement between the Service Provider and the Client and shall be binding upon execution or commencement of services. The Service Provider shall render accounting, bookkeeping, payroll processing, GST, TDS, and other allied professional services strictly in accordance with the scope expressly agreed in writing. Any services not specifically agreed upon shall be deemed excluded and shall be undertaken only upon prior written approval and at such additional consideration as may be determined solely by the Service Provider. The Client acknowledges that the Service Provider does not provide any assurance, guarantee, or warranty of outcomes, approvals, or statutory acceptance.",
    "The Client shall be solely responsible for furnishing all information, documents, records, explanations, and confirmations required for the performance of services, and such information shall be complete, accurate, true, and timely. The Service Provider shall not be obligated to verify, audit, or independently validate the information so provided. Any error, omission, delay, default, non-compliance, penalty, interest, demand, notice, or adverse consequence arising directly or indirectly from inaccurate, incomplete, misleading, or delayed information supplied by the Client shall be the sole responsibility of the Client, and the Service Provider shall bear no liability whatsoever in this regard.",
    "All timelines communicated by the Service Provider are indicative and conditional upon the Client’s timely cooperation and submission of requisite information. Any delay or failure attributable to the Client or arising from issues on any government portal shall automatically extend the applicable timelines, and the Service Provider shall not be held responsible for any statutory non-compliance, penalty, or consequences arising therefrom. The Client expressly agrees that services may be suspended at the discretion of the Service Provider in the event of non-cooperation or non-payment.",
    "Professional fees shall be payable strictly as per the agreed quotation or service package and within the stipulated timelines, without any deduction, adjustment, withholding, or set-off. Government fees, statutory dues, penalties, interest, or levies are expressly excluded unless specifically agreed in writing. Fees once paid shall be non-refundable under any circumstances, including termination, discontinuance, or partial utilization of services. Non-payment or delayed payment shall entitle the Service Provider to suspend services without any liability.",
    "The Service Provider shall maintain confidentiality of Client information received in the course of service delivery; however, the Service Provider shall not be liable for disclosures required under law, regulation, judicial order, or disclosures necessitated due to acts, omissions, or defaults attributable to the Client. The Client acknowledges that electronic communication, including email and messaging platforms, shall constitute valid, binding, and legally enforceable instructions and approvals.",
    "All reports, returns, filings, and submissions prepared by the Service Provider are based solely on information provided by the Client. The Client retains full responsibility for representations made before statutory authorities. While reasonable professional care shall be exercised, the Service Provider shall not be responsible for changes in law, retrospective amendments, technical interpretations, system errors of government portals, or differing views adopted by authorities.",
    "The Client hereby agrees to fully indemnify and hold harmless the Service Provider, its proprietors, partners, employees, and representatives from and against any and all losses, claims, demands, penalties, damages, proceedings, costs, and expenses arising out of or in connection with inaccurate information, non-disclosure, misrepresentation, statutory non-compliance, or breach of these terms by the Client.",
    "Notwithstanding anything contained herein, the aggregate liability of the Service Provider, if any, shall be strictly limited to the professional fees actually received for the specific service giving rise to the claim. Under no circumstances shall the Service Provider be liable for any indirect, incidental, consequential, special, or punitive damages, including loss of profits, business interruption, or reputational harm.",
    "Either party may terminate this engagement by written notice; however, upon termination, all outstanding dues shall become immediately payable. The Service Provider shall not be obligated to continue services until full and final settlement is received. The Service Provider shall not be liable for any failure or delay caused by events beyond reasonable control, including acts of God, governmental actions, system failures, or regulatory restrictions.",
    "These Terms and Conditions shall be governed by and construed in accordance with the laws of India, and all disputes arising out of or in connection herewith shall be subject to the exclusive jurisdiction of the competent courts situated in the State of Telangana."
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
                        Accounting & Compliance Services terms governing the professional engagement with VR HERE.
                    </p>
                </div>
            </section>

            <section className="max-w-5xl mx-auto px-4 py-10 space-y-6">
                <div className="bg-white border border-slate-200 rounded-3xl p-8 shadow-sm space-y-6">
                    <h2 className="text-xl font-bold text-slate-950 border-b border-slate-100 pb-4">
                        Terms & Conditions
                    </h2>
                    
                    <div className="space-y-5 text-slate-600 leading-relaxed text-sm md:text-base">
                        {paragraphs.map((para, idx) => (
                            <p key={idx}>{para}</p>
                        ))}
                    </div>

                    <div className="mt-8 pt-6 border-t border-slate-100 bg-slate-50 -mx-8 -mb-8 p-8 rounded-b-3xl">
                        <h3 className="font-bold text-slate-900 mb-2">Acceptance: -</h3>
                        <p className="text-slate-600 font-medium text-sm">
                            By availing our services, the Client confirms that they have read, understood, and agreed to the above Terms & Conditions.
                        </p>
                    </div>
                </div>
            </section>
            <SharedFooter />
        </div>
    );
};

export default TermsConditionsPage;
