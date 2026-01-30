import React from 'react';
import HomePage from './HomePage';
import PrivateLimitedPage from './PrivateLimited';
import AdminPage from './admin';
import CustomerPage from './customer';
import EmployeePage from './employee';
import ContactUsPage from './ContactUs';
import PartnershipFirmPage from './PartnershipFirm';
import GSTRegistrationPage from './GSTRegistration';

const App = () => {
  // Simple "Router" based on URL path
  const path = window.location.pathname;

  if (path.includes('pvt-ltd-registration')) {
    return <PrivateLimitedPage />;
  }
  if (path.includes('partnership-firm')) {
    return <PartnershipFirmPage />;
  }
  if (path.includes('gst-registration')) {
    return <GSTRegistrationPage />;
  }
  if (path.includes('admin')) {
    return <AdminPage />;
  }
  if (path.includes('customer')) {
    return <CustomerPage />;
  }
  if (path.includes('employee')) {
    return <EmployeePage />;
  }
  if (path.includes('contact')) {
    return <ContactUsPage />;
  }

  // Default route
  return <HomePage />;
};

export default App;