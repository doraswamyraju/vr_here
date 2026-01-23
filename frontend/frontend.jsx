import React from 'react';
import HomePage from './HomePage';
import PrivateLimitedPage from './PrivateLimited';

const App = () => {
  // Simple "Router" based on URL path
  // We use includes() to be safe against subfolder deployment (e.g. /vr_here/pvt-ltd-registration)
  const path = window.location.pathname;

  if (path.includes('pvt-ltd-registration')) {
    return <PrivateLimitedPage />;
  }

  // Default route
  return <HomePage />;
};

export default App;