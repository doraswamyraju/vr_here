import React from 'react';
import { Users, ShieldCheck } from 'lucide-react';
import { ADVISORS, LEADERSHIP_TEAM } from './ourTeamData';

const ProfileCard = ({ profile }) => (
  <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm hover:shadow-lg transition-all duration-300 hover:-translate-y-1">
    <h3 className="text-lg font-black text-slate-900">{profile.name}</h3>
    <p className="text-xs font-bold uppercase tracking-wide text-red-600 mt-1">{profile.title}</p>
    <p className="text-sm text-slate-600 leading-relaxed mt-3">{profile.summary}</p>
  </div>
);

const OurTeamModule = ({ compact = false, sectionId = 'our-team' }) => {
  const teamItems = compact ? LEADERSHIP_TEAM.slice(0, 4) : LEADERSHIP_TEAM;
  const advisorItems = compact ? ADVISORS.slice(0, 2) : ADVISORS;

  return (
    <section id={sectionId} className="py-20 bg-gradient-to-b from-white to-slate-50 border-t border-slate-100">
      <div className="max-w-7xl mx-auto px-4">
        <div className="text-center mb-12">
          <div className="inline-flex items-center px-4 py-2 rounded-full bg-red-50 text-red-600 text-xs font-bold uppercase tracking-wider mb-4">
            <Users className="w-4 h-4 mr-2" /> Our Team
          </div>
          <h2 className="text-3xl md:text-4xl font-black text-slate-900">People Behind VR HERE</h2>
          <p className="text-slate-500 mt-4 max-w-2xl mx-auto">
            Cross-functional professionals in finance, compliance, training, investments, and operations.
          </p>
        </div>

        <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-6">
          {teamItems.map((profile) => (
            <ProfileCard key={profile.name} profile={profile} />
          ))}
        </div>

        <div className="mt-14 text-center">
          <div className="inline-flex items-center px-4 py-2 rounded-full bg-slate-900 text-white text-xs font-bold uppercase tracking-wider mb-4">
            <ShieldCheck className="w-4 h-4 mr-2" /> Our Advisors
          </div>
          <h3 className="text-2xl font-black text-slate-900">Strategic Advisory Panel</h3>
        </div>
        <div className="grid md:grid-cols-2 gap-6 mt-8">
          {advisorItems.map((profile) => (
            <ProfileCard key={profile.name} profile={profile} />
          ))}
        </div>

        {compact && (
          <div className="text-center mt-10">
            <a
              href="/our-team"
              className="inline-flex items-center bg-red-600 text-white px-6 py-3 rounded-lg font-bold text-sm hover:bg-red-700 transition"
            >
              View Full Team Profile
            </a>
          </div>
        )}
      </div>
    </section>
  );
};

export default OurTeamModule;
