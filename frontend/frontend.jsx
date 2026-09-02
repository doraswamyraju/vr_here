import React, { useContext } from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { AuthContext } from './context/AuthContext';

// Existing Pages
import HomePage from './HomePage';
import LoginPage from './Auth/Login';
import RegisterPage from './Auth/Register';
import GoogleCallback from './Auth/GoogleCallback';
import ForgotPassword from './Auth/ForgotPassword';
import ResetPassword from './Auth/ResetPassword';
import PrivateLimitedPage from './PrivateLimited';
import PublicLimitedPage from './PublicLimited';
import LLPRegistrationPage from './LLPRegistration';
import PartnershipFirmPage from './PartnershipFirm';
import ProprietorshipSetupPage from './ProprietorshipSetup';
import Section8CompanyPage from './Section8Company';
import OnePersonCompanyPage from './OnePersonCompany';
import SocietyTrustRegistrationPage from './SocietyTrustRegistration';
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
import PrivacyPolicyPage from './PrivacyPolicy';

// Dedicated New Service Pages
import CloudAccountingPage from './CloudAccounting';
import GSTReturnFilingPage from './GSTReturnFiling';
import PayrollManagementPage from './PayrollManagement';
import ProfessionalTaxPage from './ProfessionalTax';
import EpfEsiReturnsPage from './EpfEsiReturns';
import TdsTcsFilingPage from './TdsTcsFiling';
import MisReportingPage from './MisReporting';
import AuditServicesPage from './AuditServices';
import TaxExemptionCertificatesPage from './TaxExemptionCertificates';

import ISO9001CertificationPage from './ISO9001Certification';
import ISO14001CertificationPage from './ISO14001Certification';
import ISO45001CertificationPage from './ISO45001Certification';
import ISO22000CertificationPage from './ISO22000Certification';
import ISO27001CertificationPage from './ISO27001Certification';
import GmpHaccpCertificationPage from './GmpHaccpCertification';
import CeMarkingCertificationPage from './CeMarkingCertification';
import IsiBisCertificationPage from './IsiBisCertification';
import HalalKosherCertificationPage from './HalalKosherCertification';

import UdyamRegistrationPage from './UdyamRegistration';
import ShopsEstablishmentLicensePage from './ShopsEstablishmentLicense';
import ImportExportCodePage from './ImportExportCode';
import StartupIndiaRegistrationPage from './StartupIndiaRegistration';
import FssaiLicensePage from './FssaiLicense';
import TradeLicensePage from './TradeLicense';
import LabourLicensePage from './LabourLicense';
import PollutionNOCPage from './PollutionNOC';
import RocAnnualFilingsPage from './RocAnnualFilings';
import DirectorKYCPage from './DirectorKYC';
import DscRegistrationPage from './DscRegistration';

import GemRegistrationPage from './GemRegistration';
import TredsRegistrationPage from './TredsRegistration';
import ReraRegistrationPage from './ReraRegistration';
import DprCmaPreparationPage from './DprCmaPreparation';
import MsmeSubsidiesLoansPage from './MsmeSubsidiesLoans';
import TrademarkRegistrationPage from './TrademarkRegistration';
import MachinerySourcingPage from './MachinerySourcing';

const ProtectedRoute = ({ children, allowedRoles }) => {
  const { user: contextUser, loading } = useContext(AuthContext);

  const user = contextUser || (() => {
    try {
      const saved = localStorage.getItem('userInfo');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  })();

  if (loading && !user) return <div className="min-h-screen flex items-center justify-center">Loading...</div>;

  if (!user) return <Navigate to="/login" replace />;

  if (allowedRoles && !allowedRoles.includes(user.role)) {
    return <Navigate to="/" replace />;
  }

  return children;
};

const App = () => {
  const { logout } = useContext(AuthContext);
  const location = useLocation();

  React.useEffect(() => {
    const isDashboardPath = /^\/(admin|employee|freelancer-dashboard|partner-dashboard|customer-dashboard|dashboard|partner\/dashboard)/.test(location.pathname);
    
    const syncVisibility = () => {
      if (typeof window.__setLetsTrackLauncherVisibility === 'function') {
        window.__setLetsTrackLauncherVisibility(!isDashboardPath);
      }
    };

    syncVisibility();
    const interval = setInterval(syncVisibility, 300);
    const timeout = setTimeout(() => clearInterval(interval), 4000);
    return () => {
      clearInterval(interval);
      clearTimeout(timeout);
    };
  }, [location.pathname]);

  return (
    <Routes>
      {/* Public Core Routes */}
      <Route path="/" element={<HomePage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/auth/google/callback" element={<GoogleCallback />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password/:resetToken" element={<ResetPassword />} />
      <Route path="/contact" element={<ContactUsPage />} />
      <Route path="/all-services" element={<AllServicesPage />} />
      <Route path="/terms-and-conditions" element={<TermsConditionsPage />} />
      <Route path="/privacy-policy" element={<PrivacyPolicyPage />} />
      <Route path="/partner/signup" element={<PartnerSignupPage />} />
      <Route path="/freelancer/signup" element={<FreelancerSignupPage />} />
      <Route path="/header-design-options" element={<HeaderDesignOptions />} />
      <Route path="/service-card-design-options" element={<ServiceCardDesignOptions />} />

      {/* Corporate Entity Routes */}
      <Route path="/pvt-ltd-registration" element={<PrivateLimitedPage />} />
      <Route path="/private-limited-registration" element={<PrivateLimitedPage />} />
      <Route path="/public-limited-company" element={<PublicLimitedPage />} />
      <Route path="/llp-registration" element={<LLPRegistrationPage />} />
      <Route path="/partnership-firm" element={<PartnershipFirmPage />} />
      <Route path="/partnership-firm-registration" element={<PartnershipFirmPage />} />
      <Route path="/proprietorship-setup" element={<ProprietorshipSetupPage />} />
      <Route path="/sole-proprietorship" element={<ProprietorshipSetupPage />} />
      <Route path="/section-8-company" element={<Section8CompanyPage />} />
      <Route path="/section-8-company-registration" element={<Section8CompanyPage />} />
      <Route path="/one-person-company" element={<OnePersonCompanyPage />} />
      <Route path="/opc-registration" element={<OnePersonCompanyPage />} />
      <Route path="/society-trust-registration" element={<SocietyTrustRegistrationPage />} />
      <Route path="/trust-registration" element={<SocietyTrustRegistrationPage />} />
      <Route path="/society-registration" element={<SocietyTrustRegistrationPage />} />
      <Route path="/gst-registration" element={<GSTRegistrationPage />} />
      <Route path="/income-tax-return" element={<IncomeTaxPage />} />
      <Route path="/income-tax-assessment" element={<IncomeTaxAssessment />} />
      <Route path="/compliance-scheme-2026" element={<CompaniesComplianceScheme />} />
      <Route path="/accounting-services" element={<AccountingServices />} />

      {/* Category 1: Accounting, Compliance & Taxation */}
      <Route path="/cloud-accounting" element={<CloudAccountingPage />} />
      <Route path="/gst-return-filing" element={<GSTReturnFilingPage />} />
      <Route path="/payroll-management" element={<PayrollManagementPage />} />
      <Route path="/professional-tax" element={<ProfessionalTaxPage />} />
      <Route path="/epf-esi-returns" element={<EpfEsiReturnsPage />} />
      <Route path="/tds-tcs-filing" element={<TdsTcsFilingPage />} />
      <Route path="/mis-reporting" element={<MisReportingPage />} />
      <Route path="/audit-services" element={<AuditServicesPage />} />
      <Route path="/12aa-80g-certificates" element={<TaxExemptionCertificatesPage />} />

      {/* Category 2: Certification & Quality Management (ISO & Standards) */}
      <Route path="/iso-9001-certification" element={<ISO9001CertificationPage />} />
      <Route path="/iso-14001-certification" element={<ISO14001CertificationPage />} />
      <Route path="/iso-45001-certification" element={<ISO45001CertificationPage />} />
      <Route path="/iso-22000-certification" element={<ISO22000CertificationPage />} />
      <Route path="/iso-27001-certification" element={<ISO27001CertificationPage />} />
      <Route path="/gmp-haccp-certification" element={<GmpHaccpCertificationPage />} />
      <Route path="/ce-marking-certification" element={<CeMarkingCertificationPage />} />
      <Route path="/isi-bis-certification" element={<IsiBisCertificationPage />} />
      <Route path="/halal-kosher-certification" element={<HalalKosherCertificationPage />} />

      {/* Category 3: Mandatory Licenses, Registrations & ROC */}
      <Route path="/udyam-registration" element={<UdyamRegistrationPage />} />
      <Route path="/shops-establishment-license" element={<ShopsEstablishmentLicensePage />} />
      <Route path="/import-export-code" element={<ImportExportCodePage />} />
      <Route path="/startup-india-registration" element={<StartupIndiaRegistrationPage />} />
      <Route path="/fssai-license" element={<FssaiLicensePage />} />
      <Route path="/trade-license" element={<TradeLicensePage />} />
      <Route path="/labour-license" element={<LabourLicensePage />} />
      <Route path="/pollution-noc" element={<PollutionNOCPage />} />
      <Route path="/roc-annual-filings" element={<RocAnnualFilingsPage />} />
      <Route path="/director-kyc" element={<DirectorKYCPage />} />
      <Route path="/dsc-registration" element={<DscRegistrationPage />} />

      {/* Category 4 & 5: Govt, MSME, Branding & Industry Setup */}
      <Route path="/gem-registration" element={<GemRegistrationPage />} />
      <Route path="/treds-registration" element={<TredsRegistrationPage />} />
      <Route path="/rera-registration" element={<ReraRegistrationPage />} />
      <Route path="/dpr-cma-preparation" element={<DprCmaPreparationPage />} />
      <Route path="/msme-subsidies-loans" element={<MsmeSubsidiesLoansPage />} />
      <Route path="/trademark-registration" element={<TrademarkRegistrationPage />} />
      <Route path="/machinery-sourcing" element={<MachinerySourcingPage />} />

      {/* Programmatic City Landing Page Catch-All Route */}
      <Route path="/:slug" element={<PrivateLimitedPage />} />

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
          <ProtectedRoute allowedRoles={['employee', 'admin']}>
            <EmployeePage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/customer-dashboard"
        element={
          <ProtectedRoute allowedRoles={['customer', 'client']}>
            <CustomerPage />
          </ProtectedRoute>
        }
      />
      <Route path="/dashboard" element={<Navigate to="/customer-dashboard" replace />} />
      <Route
        path="/partner-dashboard"
        element={
          <ProtectedRoute allowedRoles={['partner']}>
            <PartnerDashboardPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/freelancer-dashboard"
        element={
          <ProtectedRoute allowedRoles={['freelancer']}>
            <FreelancerDashboardPage />
          </ProtectedRoute>
        }
      />

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
};

export default App;
