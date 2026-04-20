import React from 'react';
import { 
  Calculator, 
  ShieldCheck, 
  Briefcase, 
  FileText, 
  Award,
  User as UsersIcon,
  PieChart,
  HardHat,
  Scale
} from 'lucide-react';

const ProfessionalCard = ({ title, description, icon: Icon, color }) => (
  <div className="group bg-slate-900/50 backdrop-blur-sm rounded-3xl border border-white/10 p-8 hover:border-red-500/50 transition-all duration-300 hover:-translate-y-1">
    <div className={`w-14 h-14 rounded-2xl ${color} flex items-center justify-center mb-6 group-hover:scale-110 transition-transform duration-300 shadow-lg`}>
      <Icon className="w-7 h-7 text-white" />
    </div>
    <h3 className="text-xl font-black text-white mb-3 tracking-tight">{title}</h3>
    <p className="text-slate-400 text-sm leading-relaxed">{description}</p>
  </div>
);

const ProfessionalsModule = ({ sectionId = 'managed-by-professionals' }) => {
  const professionals = [
    {
      title: 'Chartered Accountants (CAs)',
      description: 'Expertise in Statutory Audit, Taxation, Financial Planning, and Business Consulting to ensure your finances are robust and compliant.',
      icon: Calculator,
      color: 'bg-blue-600'
    },
    {
      title: 'Company Secretaries (CSs)',
      description: 'Handling Corporate Governance, ROC Filings, Legal Secretarial Services, and ensuring your business stays compliant with all statutory laws.',
      icon: ShieldCheck,
      color: 'bg-emerald-600'
    },
    {
      title: 'Cost Accountants (CMAs)',
      description: 'Strategic Cost Management, Audit, and Optimization services to improve operational efficiency and bottom-line performance.',
      icon: PieChart,
      color: 'bg-orange-600'
    },
    {
      title: 'Tax Consultants',
      description: 'Specialists in Indirect Taxes (GST) and Direct Taxes (IT), providing advisory, filing, and representation services across all tax verticals.',
      icon: FileText,
      color: 'bg-red-600'
    },
    {
      title: 'Quality Consultants',
      description: 'Experts in ISO Certifications (9001, 14001, etc.), Quality Management Systems, and ensuring global standards in your operations.',
      icon: Award,
      color: 'bg-purple-600'
    },
    {
      title: 'Industrial Consultants',
      description: 'Technical expertise in Machinery Sourcing, Factory Setup, Pollution Control, and comprehensive industrial licensing solutions.',
      icon: HardHat,
      color: 'bg-amber-600'
    },
    {
      title: 'Legal Advisors',
      description: 'Qualified legal professionals specializing in Business Laws, Contracts, Intellectual Property, and Dispute Resolution support.',
      icon: Scale,
      color: 'bg-indigo-600'
    },
    {
      title: 'Business Analysts',
      description: 'Strategic experts providing market analysis, feasibility reports, and data-driven insights to scale your business ventures.',
      icon: Briefcase,
      color: 'bg-cyan-600'
    }
  ];

  return (
    <section id={sectionId} className="py-24 bg-gradient-to-b from-slate-950 via-slate-900 to-slate-950 text-white relative overflow-hidden">
      {/* Decorative Elements */}
      <div className="absolute top-0 left-0 w-full h-full pointer-events-none">
        <div className="absolute -top-28 -left-20 w-96 h-96 rounded-full bg-red-500/5 blur-3xl" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] rounded-full bg-blue-500/5 blur-[120px]" />
        <div className="absolute -bottom-28 -right-20 w-96 h-96 rounded-full bg-orange-500/5 blur-3xl" />
      </div>

      <div className="max-w-7xl mx-auto px-4 relative z-10">
        <div className="text-center mb-16">
          <div className="inline-flex items-center px-4 py-2 rounded-full bg-white/5 text-red-400 text-xs font-bold uppercase tracking-widest mb-4 border border-white/10">
            <UsersIcon className="w-4 h-4 mr-2" /> Professional Network
          </div>
          <h2 className="text-3xl md:text-6xl font-black text-white tracking-tight leading-[1.1]">
            Managed by <span className="bg-gradient-to-r from-red-500 to-orange-500 bg-clip-text text-transparent">Professionals</span>
          </h2>
          <p className="text-slate-400 mt-6 max-w-2xl mx-auto text-lg leading-relaxed">
            Our platform is powered by a diverse network of highly qualified professionals, 
            ensuring expert-level execution and strategic guidance for every business need.
          </p>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
          {professionals.map((prof, index) => (
            <ProfessionalCard key={index} {...prof} />
          ))}
        </div>

        <div className="mt-20 p-10 rounded-[40px] bg-gradient-to-r from-red-600 to-orange-600 text-white text-center shadow-2xl shadow-red-600/20">
          <h3 className="text-2xl md:text-3xl font-black mb-4">Need Dedicated Expert Advice?</h3>
          <p className="text-white/90 mb-8 max-w-xl mx-auto font-medium">
            Connect with our certified professionals today for a personalized consultation tailored to your business goals.
          </p>
          <a
            href="/contact"
            className="inline-flex items-center bg-white text-red-600 px-8 py-4 rounded-2xl font-black text-sm uppercase tracking-wider hover:bg-slate-100 transition-all hover:scale-105"
          >
            Talk to an Expert
          </a>
        </div>
      </div>
    </section>
  );
};

export default ProfessionalsModule;
