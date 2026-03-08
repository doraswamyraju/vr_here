import React from 'react';
import { Users, ShieldCheck, Sparkles, ArrowRight } from 'lucide-react';
import { ADVISORS, LEADERSHIP_TEAM } from './ourTeamData';

const ProfileCard = ({ profile }) => (
  <div className="group bg-white rounded-3xl border border-slate-200 overflow-hidden shadow-sm hover:shadow-2xl hover:shadow-indigo-100/70 transition-all duration-300 hover:-translate-y-1">
    <div className="relative h-52 overflow-hidden">
      <img
        src={profile.imageUrl}
        alt={profile.name}
        className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
      />
      <div className="absolute inset-0 bg-gradient-to-t from-black/70 via-black/20 to-transparent" />
      <div className="absolute bottom-4 left-4 right-4">
        <p className="text-white text-xs font-bold uppercase tracking-wide">{profile.title}</p>
        <h3 className="text-white text-xl font-black mt-1">{profile.name}</h3>
      </div>
    </div>
    <div className="p-5">
      <p className="text-sm text-slate-600 leading-relaxed">{profile.summary}</p>
    </div>
  </div>
);

const OurTeamModule = ({ compact = false, sectionId = 'our-team' }) => {
  const teamItems = compact ? LEADERSHIP_TEAM.slice(0, 4) : LEADERSHIP_TEAM;
  const advisorItems = compact ? ADVISORS.slice(0, 2) : ADVISORS;

  return (
    <section id={sectionId} className="py-24 bg-gradient-to-b from-slate-950 via-slate-900 to-slate-950 text-white relative overflow-hidden">
      <div className="absolute -top-28 -left-20 w-96 h-96 rounded-full bg-red-500/20 blur-3xl" />
      <div className="absolute -bottom-28 -right-20 w-96 h-96 rounded-full bg-blue-500/20 blur-3xl" />
      <div className="max-w-7xl mx-auto px-4">
        <div className="text-center mb-14 relative z-10">
          <div className="inline-flex items-center px-4 py-2 rounded-full bg-white/10 text-red-300 text-xs font-bold uppercase tracking-wider mb-4 border border-white/15">
            <Users className="w-4 h-4 mr-2" /> Our Team
          </div>
          <h2 className="text-3xl md:text-5xl font-black text-white">People Behind VR HERE</h2>
          <p className="text-slate-300 mt-4 max-w-3xl mx-auto">
            Cross-functional professionals in finance, compliance, training, investments, and operations.
          </p>
          <div className="flex justify-center mt-6">
            <div className="inline-flex items-center text-xs font-bold text-amber-300 bg-amber-400/10 px-3 py-1.5 rounded-full border border-amber-300/20">
              <Sparkles className="w-3.5 h-3.5 mr-2" /> High-trust advisory + execution team
            </div>
          </div>
        </div>

        <div className="grid md:grid-cols-2 xl:grid-cols-4 gap-6 relative z-10">
          {teamItems.map((profile) => (
            <ProfileCard key={profile.name} profile={profile} />
          ))}
        </div>

        <div className="mt-16 text-center relative z-10">
          <div className="inline-flex items-center px-4 py-2 rounded-full bg-white/10 text-white text-xs font-bold uppercase tracking-wider mb-4 border border-white/15">
            <ShieldCheck className="w-4 h-4 mr-2" /> Our Advisors
          </div>
          <h3 className="text-2xl font-black text-white">Strategic Advisory Panel</h3>
        </div>
        <div className="grid md:grid-cols-2 gap-6 mt-8 relative z-10">
          {advisorItems.map((profile) => (
            <ProfileCard key={profile.name} profile={profile} />
          ))}
        </div>

        {compact && (
          <div className="text-center mt-10">
            <a
              href="/our-team"
              className="inline-flex items-center bg-red-600 text-white px-6 py-3 rounded-lg font-bold text-sm hover:bg-red-700 transition shadow-lg shadow-red-700/30"
            >
              View Full Team Profile <ArrowRight className="w-4 h-4 ml-2" />
            </a>
          </div>
        )}
      </div>
    </section>
  );
};

export default OurTeamModule;
