import React, { useContext } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthContext } from './context/AuthContext';

// Pages
import HomePage from './HomePage';
import LoginPage from './Auth/Login';
import RegisterPage from './Auth/Register';
import ForgotPassword from './Auth/ForgotPassword';
import ResetPassword from './Auth/ResetPassword';
import PrivateLimitedPage from './PrivateLimited';
import PartnershipFirmPage from './PartnershipFirm';
import GSTRegistrationPage from './GSTRegistration';
import IncomeTaxPage from './IncomeTax';
import IncomeTaxAssessment from './IncomeTaxAssessment';
import AdminPage from './admin';
import CustomerPage from './customer';
import EmployeePage from './employee';
import ContactUsPage from './ContactUs';
import HeaderDesignOptions from './HeaderDesignOptions';
import ServiceCardDesignOptions from './ServiceCardDesignOptions';
import AllServicesPage from './AllServices';
import TermsConditionsPage from './TermsConditions';
import CompaniesComplianceScheme from './CompaniesComplianceScheme';
import AccountingServices from './AccountingServices';
import PartnerSignupPage from './PartnerSignup';
import PartnerDashboardPage from './partner';
import FreelancerSignupPage from './FreelancerSignup';
import FreelancerDashboardPage from './freelancer';

const ProtectedRoute = ({ children, allowedRoles }) => {
  const { user, loading } = useContext(AuthContext);

  if (loading) return <div className="min-h-screen flex items-center justify-center">Loading...</div>;

  if (!user) return <Navigate to="/login" />;

  if (allowedRoles && !allowedRoles.includes(user.role)) {
    return <Navigate to="/" />;
  }

  return children;
};

const App = () => {
  const { logout } = useContext(AuthContext);

  return (
    <Routes>
      {/* Public Routes */}
      <Route path="/" element={<HomePage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password/:resetToken" element={<ResetPassword />} />
      <Route path="/pvt-ltd-registration" element={<PrivateLimitedPage />} />
      <Route path="/partnership-firm" element={<PartnershipFirmPage />} />
      <Route path="/gst-registration" element={<GSTRegistrationPage />} />
      <Route path="/income-tax-return" element={<IncomeTaxPage />} />
      <Route path="/income-tax-assessment" element={<IncomeTaxAssessment />} />
      <Route path="/all-services" element={<AllServicesPage />} />
      <Route path="/terms-and-conditions" element={<TermsConditionsPage />} />
      <Route path="/compliance-scheme-2026" element={<CompaniesComplianceScheme />} />
      <Route path="/accounting-services" element={<AccountingServices />} />
      <Route path="/partner/signup" element={<PartnerSignupPage />} />
      <Route path="/freelancer/signup" element={<FreelancerSignupPage />} />

      <Route path="/contact" element={<ContactUsPage />} />

      {/* Protected Routes */}
      <Route
        path="/admin"
        element={
          <ProtectedRoute allowedRoles={['admin']}>
            <AdminPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/employee"
        element={
          <ProtectedRoute allowedRoles={['employee']}>
            <EmployeePage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/dashboard"
        element={
          <ProtectedRoute allowedRoles={['client', 'admin']}>
            <CustomerPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/customer-dashboard"
        element={
          <ProtectedRoute allowedRoles={['client', 'admin']}>
            <CustomerPage />
          </ProtectedRoute>
        }
      />

      <Route
        path="/partner-dashboard"
        element={
          <ProtectedRoute allowedRoles={['partner', 'admin']}>
            <PartnerDashboardPage />
          </ProtectedRoute>
        }
      />

      <Route
        path="/freelancer-dashboard"
        element={
          <ProtectedRoute allowedRoles={['freelancer', 'admin']}>
            <AuthContext.Consumer>
              {({ user }) => (
                <FreelancerDashboardPage userInfo={user} onLogout={logout} />
              )}
            </AuthContext.Consumer>
          </ProtectedRoute>
        }
      />

      {/* TEMP: Design Previews */}
      <Route path="/header-designs" element={<HeaderDesignOptions />} />
      <Route path="/service-designs" element={<ServiceCardDesignOptions />} />
    </Routes>
  );
};

export default App;
