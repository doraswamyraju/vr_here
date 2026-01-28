import React from 'react';
import HomePage from './HomePage';
import PrivateLimitedPage from './PrivateLimited';
import AdminPage from './admin';
import CustomerPage from './customer';
import EmployeePage from './employee';

const App = () => {
  // Simple "Router" based on URL path
  const path = window.location.pathname;

  if (path.includes('pvt-ltd-registration')) {
    return <PrivateLimitedPage />;
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

  // Default route
  return <HomePage />;
};

export default App;