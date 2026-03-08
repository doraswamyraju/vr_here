import React from 'react';
import { SharedHeader, SharedFooter } from './components/SharedComponents';
import OurTeamModule from './components/OurTeamModule';

const OurTeamPage = () => (
  <div className="min-h-screen bg-white">
    <SharedHeader />
    <OurTeamModule compact={false} sectionId="our-team-page" />
    <SharedFooter />
  </div>
);

export default OurTeamPage;
