package com.sbr.vrherebms.ui.screens.customer

import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.ui.theme.*
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel

data class ServiceItemModel(
    val id: String,
    val title: String,
    val categoryId: String,
    val categoryName: String,
    val icon: ImageVector,
    val colorTheme: Color,
    val turnaround: String,
    val startingPrice: String,
    val trustBadge: String,
    val targetUrl: String
)

data class ServiceCategoryItem(
    val id: String,
    val name: String,
    val icon: ImageVector
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomerServicesTab(
    viewModel: CustomerDashboardViewModel,
    onSelectTab: (String) -> Unit,
    onOpenLiveService: (String, String) -> Unit
) {
    var searchQuery by remember { mutableStateOf("") }
    var selectedCategory by remember { mutableStateOf("ALL") }

    val categoriesList = remember {
        listOf(
            ServiceCategoryItem("ALL", "All Services", Icons.Default.GridView),
            ServiceCategoryItem("CORP", "Corporate Entity", Icons.Default.Apartment),
            ServiceCategoryItem("TAX", "Tax & Accounting", Icons.Default.Calculate),
            ServiceCategoryItem("ISO", "ISO & Quality", Icons.Default.Verified),
            ServiceCategoryItem("LICENSE", "Licensing & Govt", Icons.Default.Description),
            ServiceCategoryItem("MSME", "MSME & Schemes", Icons.Default.Public),
            ServiceCategoryItem("STARTUP", "Industrial & Setup", Icons.Default.Lightbulb)
        )
    }

    val allServicesList = remember {
        listOf(
            // 1. Corporate Entity Registrations (8)
            ServiceItemModel("pvt-ltd-registration", "Private Limited Company", "CORP", "Corporate Entity", Icons.Default.Apartment, Indigo500, "⚡ 7 Days", "From ₹5,499", "MCA Verified", "https://vrhere.in/pvt-ltd-registration"),
            ServiceItemModel("public-limited-company", "Public Limited Company", "CORP", "Corporate Entity", Icons.Default.AccountBalance, Indigo600, "⚡ 10-14 Days", "From ₹14,999", "MCA Verified", "https://vrhere.in/public-limited-company"),
            ServiceItemModel("llp-registration", "Limited Liability Partnership (LLP)", "CORP", "Corporate Entity", Icons.Default.People, Emerald500, "⚡ 5-7 Days", "From ₹4,899", "MCA Verified", "https://vrhere.in/llp-registration"),
            ServiceItemModel("one-person-company", "One Person Company (OPC)", "CORP", "Corporate Entity", Icons.Default.Person, Amber500, "⚡ 5-7 Days", "From ₹4,999", "Solo Founder", "https://vrhere.in/one-person-company"),
            ServiceItemModel("partnership-firm", "Partnership Firm Registration", "CORP", "Corporate Entity", Icons.Default.Groups, Color(0xFFEC4899), "⚡ 3-5 Days", "From ₹3,499", "State ROF", "https://vrhere.in/partnership-firm"),
            ServiceItemModel("section-8-company", "Section 8 Company (NGO)", "CORP", "Corporate Entity", Icons.Default.Favorite, PrimaryRed, "⚡ 10-12 Days", "From ₹8,499", "80G / 12A Ready", "https://vrhere.in/section-8-company"),
            ServiceItemModel("society-trust-registration", "Society / Trust Registration", "CORP", "Corporate Entity", Icons.Default.Shield, Color(0xFF0EA5E9), "⚡ 7-10 Days", "From ₹6,999", "Trust Deed", "https://vrhere.in/society-trust-registration"),
            ServiceItemModel("proprietorship-setup", "Proprietorship Setup", "CORP", "Corporate Entity", Icons.Default.Work, Slate500, "⚡ 2-3 Days", "From ₹1,999", "Fast Setup", "https://vrhere.in/proprietorship-setup"),

            // 2. Tax & Accounting Services (22)
            ServiceItemModel("cloud-accounting", "Cloud Accounting (Tally, Zoho Books)", "TAX", "Tax & Accounting", Icons.Default.PieChart, Color(0xFF0EA5E9), "⚡ Monthly Retainer", "From ₹2,999/mo", "Monthly MIS", "https://vrhere.in/cloud-accounting"),
            ServiceItemModel("gst-return-filing", "GST Return Filing (GSTR 1, 3B, 9)", "TAX", "Tax & Accounting", Icons.Default.ReceiptLong, Emerald500, "⚡ Monthly / Qtr", "From ₹499/mo", "Zero Penalty", "https://vrhere.in/gst-return-filing"),
            ServiceItemModel("payroll-management", "Payroll Management & Payslips", "TAX", "Tax & Accounting", Icons.Default.Badge, Amber500, "⚡ Monthly Cycle", "From ₹2,499/mo", "PF/ESI Compliant", "https://vrhere.in/payroll-management"),
            ServiceItemModel("professional-tax", "Professional Tax (PTEC / PTRC)", "TAX", "Tax & Accounting", Icons.Default.Receipt, Color(0xFF3B82F6), "⚡ 2-3 Days", "From ₹1,999", "Commercial Taxes", "https://vrhere.in/professional-tax"),
            ServiceItemModel("epf-esi-returns", "EPF & ESI Monthly Returns & ECR", "TAX", "Tax & Accounting", Icons.Default.PeopleAlt, Color(0xFFA855F7), "⚡ Monthly Cycle", "From ₹1,999/mo", "EPFO & ESIC", "https://vrhere.in/epf-esi-returns"),
            ServiceItemModel("gratuity-management", "Gratuity Trust & Valuation", "TAX", "Tax & Accounting", Icons.Default.CardGiftcard, Color(0xFFEC4899), "⚡ 3-5 Days", "From ₹3,499", "Statutory Gratuity", "https://vrhere.in/gratuity-management"),
            ServiceItemModel("tds-tcs-filing", "TDS / TCS Filing (24Q, 26Q, 27EQ)", "TAX", "Tax & Accounting", Icons.Default.Assignment, PrimaryRed, "⚡ Quarterly Filing", "From ₹1,999", "TRACES Verified", "https://vrhere.in/tds-tcs-filing"),
            ServiceItemModel("inventory-stock-management", "Inventory & Stock Audit Ledgers", "TAX", "Tax & Accounting", Icons.Default.Inventory2, Slate500, "⚡ Monthly / Qtr", "From ₹2,999", "Stock Verification", "https://vrhere.in/inventory-stock-management"),
            ServiceItemModel("invoice-generation-support", "E-Invoicing & E-Way Bill Setup", "TAX", "Tax & Accounting", Icons.Default.PostAdd, Color(0xFF0EA5E9), "⚡ 24 Hours", "From ₹1,499", "GST E-Invoice", "https://vrhere.in/invoice-generation-support"),
            ServiceItemModel("expense-tracking-consultancy", "Expense Tracking & Cost Control", "TAX", "Tax & Accounting", Icons.Default.CreditCard, Emerald500, "⚡ Monthly Retainer", "From ₹1,999/mo", "Cost Reduction", "https://vrhere.in/expense-tracking-consultancy"),
            ServiceItemModel("mis-reporting", "Monthly MIS & Financial Dashboards", "TAX", "Tax & Accounting", Icons.Default.BarChart, Indigo500, "⚡ Monthly Reports", "From ₹3,999/mo", "CFO Advisory", "https://vrhere.in/mis-reporting"),
            ServiceItemModel("compliance-scheme-2026", "Companies Compliance Scheme 2026 (CCFS)", "TAX", "Tax & Accounting", Icons.Default.EventNote, Amber500, "⚡ Fast Track", "From ₹4,999", "Immunity Scheme", "https://vrhere.in/compliance-scheme-2026"),
            ServiceItemModel("gst-registration", "GST Registration Online", "TAX", "Tax & Accounting", Icons.Default.AppRegistration, Emerald500, "⚡ 3-5 Days", "From ₹2,569", "GSTIN Issued", "https://vrhere.in/gst-registration"),
            ServiceItemModel("income-tax-return", "Income Tax Return Filing (ITR 1-7)", "TAX", "Tax & Accounting", Icons.Default.CurrencyRupee, Color(0xFF3B82F6), "⚡ 24-48 Hours", "From ₹1,499", "CA Certified", "https://vrhere.in/income-tax-return"),
            ServiceItemModel("12aa-80g-certificates", "12A & 80G Tax Exemption Certificates", "TAX", "Tax & Accounting", Icons.Default.CardGiftcard, Color(0xFFEC4899), "⚡ Form 10A/10AB", "From ₹6,999", "100% Tax Relief", "https://vrhere.in/12aa-80g-certificates"),
            ServiceItemModel("tax-planning-support", "Corporate & Individual Tax Planning", "TAX", "Tax & Accounting", Icons.Default.Lightbulb, Amber500, "⚡ Expert Call", "From ₹2,999", "Max Savings", "https://vrhere.in/tax-planning-support"),
            ServiceItemModel("15ca-certification", "Form 15CA & 15CB Foreign Remittance", "TAX", "Tax & Accounting", Icons.Default.Public, Color(0xFF0EA5E9), "⚡ 24 Hours", "From ₹2,499", "CA Certificate", "https://vrhere.in/15ca-certification"),
            ServiceItemModel("internal-audit", "Internal Financial Controls (IFC) Audit", "TAX", "Tax & Accounting", Icons.Default.FindInPage, Indigo500, "⚡ Comprehensive", "From ₹9,999", "Risk Mitigation", "https://vrhere.in/internal-audit"),
            ServiceItemModel("gst-audit", "GST & GSTR-9C Reconciliation Audit", "TAX", "Tax & Accounting", Icons.Default.Verified, Emerald500, "⚡ CA Certified", "From ₹9,999", "ITC Verified", "https://vrhere.in/gst-audit"),
            ServiceItemModel("sox-audit", "SOX 404 Internal Controls Compliance", "TAX", "Tax & Accounting", Icons.Default.Lock, Indigo600, "⚡ Enterprise", "From ₹19,999", "Global Standards", "https://vrhere.in/sox-audit"),
            ServiceItemModel("stock-compliance-audit", "Physical Stock & Fixed Assets Audit", "TAX", "Tax & Accounting", Icons.Default.Archive, Color(0xFFEA580C), "⚡ On-Site / Remote", "From ₹7,999", "Bank Ready", "https://vrhere.in/stock-compliance-audit"),
            ServiceItemModel("audit-services", "Statutory & Tax Audit (Sec 44AB)", "TAX", "Tax & Accounting", Icons.Default.HistoryEdu, PrimaryRed, "⚡ ICAI Standards", "From ₹9,999", "CA Practice", "https://vrhere.in/audit-services"),

            // 3. ISO & Quality Certifications (16)
            ServiceItemModel("iso-9001-certification", "ISO 9001:2015 Quality Management", "ISO", "ISO & Quality", Icons.Default.VerifiedUser, Indigo500, "⚡ 5-7 Days", "From ₹3,499", "IAF Accredited", "https://vrhere.in/iso-9001-certification"),
            ServiceItemModel("iso-14001-certification", "ISO 14001:2015 Environmental (EMS)", "ISO", "ISO & Quality", Icons.Default.Eco, Emerald500, "⚡ 5-7 Days", "From ₹5,499", "Green & ESG", "https://vrhere.in/iso-14001-certification"),
            ServiceItemModel("iso-45001-certification", "ISO 45001:2018 Health & Safety (OH&S)", "ISO", "ISO & Quality", Icons.Default.HealthAndSafety, PrimaryRed, "⚡ 5-7 Days", "From ₹5,999", "Workplace Safety", "https://vrhere.in/iso-45001-certification"),
            ServiceItemModel("iso-22000-certification", "ISO 22000:2018 Food Safety (FSMS)", "ISO", "ISO & Quality", Icons.Default.Restaurant, Amber500, "⚡ 5-7 Days", "From ₹6,999", "Food Safety", "https://vrhere.in/iso-22000-certification"),
            ServiceItemModel("iso-27001-certification", "ISO 27001:2022 InfoSec & Cybersecurity", "ISO", "ISO & Quality", Icons.Default.Security, Indigo600, "⚡ 7-10 Days", "From ₹8,999", "Cyber Verified", "https://vrhere.in/iso-27001-certification"),
            ServiceItemModel("iso-50001-certification", "ISO 50001:2018 Energy Management", "ISO", "ISO & Quality", Icons.Default.Bolt, Color(0xFFEA580C), "⚡ 5-7 Days", "From ₹7,999", "Energy Efficiency", "https://vrhere.in/iso-50001-certification"),
            ServiceItemModel("iso-13485-certification", "ISO 13485:2016 Medical Devices", "ISO", "ISO & Quality", Icons.Default.MedicalServices, Color(0xFFEC4899), "⚡ 7-10 Days", "From ₹9,999", "Medical Device", "https://vrhere.in/iso-13485-certification"),
            ServiceItemModel("iso-20000-certification", "ISO 20000-1:2018 IT Service Management", "ISO", "ISO & Quality", Icons.Default.Dns, Color(0xFF0EA5E9), "⚡ 5-7 Days", "From ₹8,999", "ITSM Standard", "https://vrhere.in/iso-20000-certification"),
            ServiceItemModel("iso-22301-certification", "ISO 22301:2019 Business Continuity", "ISO", "ISO & Quality", Icons.Default.Autorenew, Emerald500, "⚡ 5-7 Days", "From ₹8,999", "Resilience", "https://vrhere.in/iso-22301-certification"),
            ServiceItemModel("gmp-haccp-certification", "GMP & HACCP Certification", "ISO", "ISO & Quality", Icons.Default.Medication, Color(0xFF0EA5E9), "⚡ 5-7 Days", "From ₹6,499", "WHO-GMP", "https://vrhere.in/gmp-haccp-certification"),
            ServiceItemModel("ce-marking-certification", "CE Marking for European Exports", "ISO", "ISO & Quality", Icons.Default.Public, Color(0xFFEA580C), "⚡ 7-10 Days", "From ₹12,499", "EU Conformity", "https://vrhere.in/ce-marking-certification"),
            ServiceItemModel("isi-bis-certification", "ISI Mark & BIS CRS Registration", "ISO", "ISO & Quality", Icons.Default.Stars, Color(0xFFA855F7), "⚡ 10-15 Days", "From ₹14,999", "Bureau Standards", "https://vrhere.in/isi-bis-certification"),
            ServiceItemModel("fda-compliance-support", "US FDA Registration & Compliance", "ISO", "ISO & Quality", Icons.Default.LocalHospital, Color(0xFF3B82F6), "⚡ 5-7 Days", "From ₹14,999", "US FDA Ready", "https://vrhere.in/fda-compliance-support"),
            ServiceItemModel("brcgs-certification", "BRCGS Global Food Standard", "ISO", "ISO & Quality", Icons.Default.Shield, Slate500, "⚡ 10-12 Days", "From ₹14,999", "Global Retail", "https://vrhere.in/brcgs-certification"),
            ServiceItemModel("kosher-certification", "Kosher Global Food Certification", "ISO", "ISO & Quality", Icons.Default.AutoAwesome, Amber500, "⚡ 5-7 Days", "From ₹11,999", "Kosher Standard", "https://vrhere.in/kosher-certification"),
            ServiceItemModel("halal-kosher-certification", "Halal & Kosher Export Certification", "ISO", "ISO & Quality", Icons.Default.CheckCircle, Emerald500, "⚡ 5-7 Days", "From ₹7,999", "Global Export", "https://vrhere.in/halal-kosher-certification"),

            // 4. Mandatory Licensing & Governance (28)
            ServiceItemModel("udyam-registration", "Udyam MSME Registration Certificate", "LICENSE", "Licensing & Govt", Icons.Default.FlashOn, Color(0xFF3B82F6), "⚡ 24 Hours", "From ₹999", "Ministry of MSME", "https://vrhere.in/udyam-registration"),
            ServiceItemModel("shops-establishment-license", "Shops & Establishment Act License", "LICENSE", "Licensing & Govt", Icons.Default.Storefront, Emerald500, "⚡ 2-4 Days", "From ₹1,499", "State Labour Dept", "https://vrhere.in/shops-establishment-license"),
            ServiceItemModel("epfo-pf-registration", "EPFO (PF) Code Registration", "LICENSE", "Licensing & Govt", Icons.Default.VpnKey, Indigo500, "⚡ 2-3 Days", "From ₹2,999", "EPFO Code", "https://vrhere.in/epfo-pf-registration"),
            ServiceItemModel("esic-registration", "ESIC Employer Sub-Code Setup", "LICENSE", "Licensing & Govt", Icons.Default.LocalHospital, PrimaryRed, "⚡ 2-3 Days", "From ₹2,999", "ESIC Code", "https://vrhere.in/esic-registration"),
            ServiceItemModel("professional-tax-registration", "Professional Tax Registration (PT)", "LICENSE", "Licensing & Govt", Icons.Default.BusinessCenter, Amber500, "⚡ 2-3 Days", "From ₹1,999", "State Taxes", "https://vrhere.in/professional-tax-registration"),
            ServiceItemModel("startup-india-registration", "Startup India DPIIT Recognition", "LICENSE", "Licensing & Govt", Icons.Default.Whatshot, PrimaryRed, "⚡ 3-5 Days", "From ₹3,499", "3 Yr Tax Holiday", "https://vrhere.in/startup-india-registration"),
            ServiceItemModel("import-export-code", "Import Export Code (IEC)", "LICENSE", "Licensing & Govt", Icons.Default.FlightTakeoff, Color(0xFFA855F7), "⚡ 24 Hours", "From ₹2,199", "DGFT Verified", "https://vrhere.in/import-export-code"),
            ServiceItemModel("fssai-license", "FSSAI Food License / Registration", "LICENSE", "Licensing & Govt", Icons.Default.Restaurant, Amber500, "⚡ 3-5 Days", "From ₹1,999", "FoSCoS Govt", "https://vrhere.in/fssai-license"),
            ServiceItemModel("lei-certificate", "Legal Entity Identifier (LEI Code)", "LICENSE", "Licensing & Govt", Icons.Default.Fingerprint, Color(0xFF0EA5E9), "⚡ 24-48 Hours", "From ₹4,999", "RBI / Global LEI", "https://vrhere.in/lei-certificate"),
            ServiceItemModel("trade-license", "Municipal Trade License", "LICENSE", "Licensing & Govt", Icons.Default.LocationCity, Color(0xFF0EA5E9), "⚡ 3-5 Days", "From ₹2,499", "Municipal Corp", "https://vrhere.in/trade-license"),
            ServiceItemModel("labour-license", "Contract Labour License (CLRA)", "LICENSE", "Licensing & Govt", Icons.Default.GroupWork, Slate500, "⚡ 5-7 Days", "From ₹5,499", "CLRA Act", "https://vrhere.in/labour-license"),
            ServiceItemModel("pollution-noc", "Pollution Control Board NOC (CTE/CTO)", "LICENSE", "Licensing & Govt", Icons.Default.Air, PrimaryRed, "⚡ 7-10 Days", "From ₹9,999", "SPCB Approved", "https://vrhere.in/pollution-noc"),
            ServiceItemModel("factory-license", "Factory License & Plan Approval", "LICENSE", "Licensing & Govt", Icons.Default.PrecisionManufacturing, Color(0xFFEA580C), "⚡ 10-15 Days", "From ₹11,999", "Factories Act", "https://vrhere.in/factory-license"),
            ServiceItemModel("fcra-registration", "FCRA Foreign Contribution Registration", "LICENSE", "Licensing & Govt", Icons.Default.Language, Indigo600, "⚡ MHA Verified", "From ₹14,999", "Foreign Funding", "https://vrhere.in/fcra-registration"),
            ServiceItemModel("ngo-darpan-registration", "NITI Aayog NGO DARPAN Portal", "LICENSE", "Licensing & Govt", Icons.Default.GridOn, Emerald500, "⚡ 24-48 Hours", "From ₹2,499", "Govt Grants", "https://vrhere.in/ngo-darpan-registration"),
            ServiceItemModel("roc-annual-filings", "ROC Annual Filings (AOC-4, MGT-7)", "LICENSE", "Licensing & Govt", Icons.Default.FolderZip, Indigo500, "⚡ Annual Filing", "From ₹4,999", "MCA21 V3", "https://vrhere.in/roc-annual-filings"),
            ServiceItemModel("director-kyc", "Director KYC (DIR-3 KYC Online)", "LICENSE", "Licensing & Govt", Icons.Default.PersonSearch, Amber500, "⚡ 10 Mins", "From ₹499", "Active DIN", "https://vrhere.in/director-kyc"),
            ServiceItemModel("roc-search-certificate", "ROC Search Report & Title Search", "LICENSE", "Licensing & Govt", Icons.Default.Search, Color(0xFF0EA5E9), "⚡ 24 Hours", "From ₹2,999", "Bank Ready", "https://vrhere.in/roc-search-certificate"),
            ServiceItemModel("roc-charge-creation", "Charge Creation & Modification (CHG-1)", "LICENSE", "Licensing & Govt", Icons.Default.Link, Color(0xFFA855F7), "⚡ 2-3 Days", "From ₹3,999", "MCA Charge", "https://vrhere.in/roc-charge-creation"),
            ServiceItemModel("change-in-shareholding", "Change in Shareholding & Transfer", "LICENSE", "Licensing & Govt", Icons.Default.SwapHoriz, Color(0xFFEC4899), "⚡ 3-5 Days", "From ₹3,499", "SH-4 Stamped", "https://vrhere.in/change-in-shareholding"),
            ServiceItemModel("change-in-directorship", "Change in Directorship (DIR-11/DIR-12)", "LICENSE", "Licensing & Govt", Icons.Default.ManageAccounts, Emerald500, "⚡ 2-3 Days", "From ₹2,499", "MCA V3", "https://vrhere.in/change-in-directorship"),
            ServiceItemModel("merger-demerger-winding-up", "Mergers, Demergers & Winding Up (STK-2)", "LICENSE", "Licensing & Govt", Icons.Default.CallMerge, PrimaryRed, "⚡ NCLT / Fast Track", "From ₹24,999", "Legal Counsel", "https://vrhere.in/merger-demerger-winding-up"),
            ServiceItemModel("bonus-loans-buyback", "Bonus Issue, Loan & Buyback Compliance", "LICENSE", "Licensing & Govt", Icons.Default.Payments, Color(0xFF0EA5E9), "⚡ 3-5 Days", "From ₹4,999", "MCA Filings", "https://vrhere.in/bonus-loans-buyback"),
            ServiceItemModel("share-allotment-transfer", "Share Allotment (PAS-3) & Transfers", "LICENSE", "Licensing & Govt", Icons.Default.FileCopy, Indigo500, "⚡ 2-4 Days", "From ₹3,499", "Form PAS-3", "https://vrhere.in/share-allotment-transfer"),
            ServiceItemModel("increase-share-capital", "Increase in Authorized Share Capital", "LICENSE", "Licensing & Govt", Icons.Default.TrendingUp, Emerald500, "⚡ 3-5 Days", "From ₹3,999", "SH-7 Approval", "https://vrhere.in/increase-share-capital"),
            ServiceItemModel("company-name-address-change", "Change in Name, Address, Objects (INC-24)", "LICENSE", "Licensing & Govt", Icons.Default.EditLocation, Amber500, "⚡ 5-7 Days", "From ₹3,499", "ROC Approval", "https://vrhere.in/company-name-address-change"),
            ServiceItemModel("dsc-registration", "Class 3 Digital Signature (DSC + Token)", "LICENSE", "Licensing & Govt", Icons.Default.Key, Indigo500, "⚡ 15 Mins", "From ₹1,499", "CCA India", "https://vrhere.in/dsc-registration"),
            ServiceItemModel("rera-registration", "RERA Real Estate Agent / Project", "LICENSE", "Licensing & Govt", Icons.Default.HomeWork, Color(0xFFEA580C), "⚡ 5-7 Days", "From ₹3,999", "State RERA", "https://vrhere.in/rera-registration"),

            // 5. MSME Schemes, Subsidies & Govt Portals (22)
            ServiceItemModel("gem-registration", "GeM Govt Marketplace Primary Seller", "MSME", "MSME & Schemes", Icons.Default.ShoppingCart, Color(0xFFEA580C), "⚡ 3-5 Days", "From ₹2,999", "Govt Tenders", "https://vrhere.in/gem-registration"),
            ServiceItemModel("gem-oem-panel", "GeM OEM Panel & Brand Assessment", "MSME", "MSME & Schemes", Icons.Default.Shield, Indigo500, "⚡ 5-7 Days", "From ₹7,999", "OEM Verified", "https://vrhere.in/gem-oem-panel"),
            ServiceItemModel("gem-brand-approval", "GeM Brand Approval & Catalog Creation", "MSME", "MSME & Schemes", Icons.Default.CheckCircle, Emerald500, "⚡ 2-3 Days", "From ₹3,999", "Brand Approved", "https://vrhere.in/gem-brand-approval"),
            ServiceItemModel("gem-product-listing", "GeM Product & Service Listing", "MSME", "MSME & Schemes", Icons.Default.FormatListBulleted, Amber500, "⚡ 24 Hours", "From ₹2,499", "Active Listing", "https://vrhere.in/gem-product-listing"),
            ServiceItemModel("gem-tender-bidding", "GeM Bid Participation & Tender Mgmt", "MSME", "MSME & Schemes", Icons.Default.Gavel, PrimaryRed, "⚡ Real-time Bid", "From ₹9,999", "Tender Win Support", "https://vrhere.in/gem-tender-bidding"),
            ServiceItemModel("treds-registration", "TReDS Invoice Factoring (RXIL, M1xchange)", "MSME", "MSME & Schemes", Icons.Default.CreditCard, Emerald500, "⚡ 48 Hours", "From ₹3,499", "RBI Regulated", "https://vrhere.in/treds-registration"),
            ServiceItemModel("single-window-registration", "State Single Window Clearances (AP/TS)", "MSME", "MSME & Schemes", Icons.Default.Window, Color(0xFF0EA5E9), "⚡ 5-7 Days", "From ₹4,999", "State DIC", "https://vrhere.in/single-window-registration"),
            ServiceItemModel("npci-registration", "NPCI & BBPS Portal Onboarding", "MSME", "MSME & Schemes", Icons.Default.Hub, Indigo600, "⚡ Fintech Sync", "From ₹9,999", "NPCI Approved", "https://vrhere.in/npci-registration"),
            ServiceItemModel("ecommerce-seller-registration", "Amazon / Flipkart Seller Launch Kit", "MSME", "MSME & Schemes", Icons.Default.ShoppingBag, Color(0xFFEA580C), "⚡ 2-3 Days", "From ₹2,499", "E-Commerce Ready", "https://vrhere.in/ecommerce-seller-registration"),
            ServiceItemModel("dpr-cma-preparation", "Detailed Project Report (DPR Preparation)", "MSME", "MSME & Schemes", Icons.Default.Assessment, Indigo500, "⚡ 3-5 Days", "From ₹4,999", "Bank Credit Ready", "https://vrhere.in/dpr-cma-preparation"),
            ServiceItemModel("cma-data-preparation", "CMA Data Preparation for Bank Loans", "MSME", "MSME & Schemes", Icons.Default.Timeline, Emerald500, "⚡ 48-72 Hours", "From ₹4,999", "CA Certified", "https://vrhere.in/cma-data-preparation"),
            ServiceItemModel("bank-loans-support", "Term Loan & Working Capital Syndication", "MSME", "MSME & Schemes", Icons.Default.AccountBalance, Color(0xFF3B82F6), "⚡ Loan Sanction", "From ₹7,999", "Lowest Interest", "https://vrhere.in/bank-loans-support"),
            ServiceItemModel("cgtmse-loan-support", "CGTMSE Collateral-Free Loans (Up to ₹5 Cr)", "MSME", "MSME & Schemes", Icons.Default.Security, Color(0xFFA855F7), "⚡ Bank Guarantee", "From ₹6,999", "Zero Collateral", "https://vrhere.in/cgtmse-loan-support"),
            ServiceItemModel("pmegp-loan-support", "PMEGP Subsidy Loan (15% to 35% Subsidy)", "MSME", "MSME & Schemes", Icons.Default.Savings, Color(0xFFEC4899), "⚡ KVIC / DIC Sync", "From ₹6,999", "35% Margin Money", "https://vrhere.in/pmegp-loan-support"),
            ServiceItemModel("mudra-loans-support", "Mudra Loan Support (Shishu, Kishore, Tarun)", "MSME", "MSME & Schemes", Icons.Default.MonetizationOn, Amber500, "⚡ Up to ₹10 Lakhs", "From ₹3,499", "Govt Scheme", "https://vrhere.in/mudra-loans-support"),
            ServiceItemModel("standup-india-loans", "Stand-Up India Loan Support (SC/ST/Women)", "MSME", "MSME & Schemes", Icons.Default.AccessibilityNew, Color(0xFF0EA5E9), "⚡ ₹10L - ₹1 Cr", "From ₹6,999", "Greenfield Unit", "https://vrhere.in/standup-india-loans"),
            ServiceItemModel("zed-scheme-support", "MSME ZED Certification & CLCSS Subsidy", "MSME", "MSME & Schemes", Icons.Default.MilitaryTech, Emerald500, "⚡ Bronze/Silver/Gold", "From ₹7,999", "Govt Subsidy", "https://vrhere.in/zed-scheme-support"),
            ServiceItemModel("pmfme-subsidy-scheme", "PMFME Food Processing 35% Subsidy", "MSME", "MSME & Schemes", Icons.Default.LocalCafe, Color(0xFFEA580C), "⚡ MoFPI Scheme", "From ₹9,999", "₹10L Max Subsidy", "https://vrhere.in/pmfme-subsidy-scheme"),
            ServiceItemModel("nsic-schemes-registration", "NSIC Single Point Registration (SPRS)", "MSME", "MSME & Schemes", Icons.Default.Store, Slate500, "⚡ 5-7 Days", "From ₹4,999", "Zero EMD Tenders", "https://vrhere.in/nsic-schemes-registration"),
            ServiceItemModel("nabard-subsidy-schemes", "NABARD Agri-Infrastructure Subsidy", "MSME", "MSME & Schemes", Icons.Default.Agriculture, Emerald500, "⚡ Project Cycle", "From ₹11,999", "Agri Subsidy", "https://vrhere.in/nabard-subsidy-schemes"),
            ServiceItemModel("cold-chain-subsidy", "Cold Chain & Value Addition Subsidies", "MSME", "MSME & Schemes", Icons.Default.AcUnit, Color(0xFF0EA5E9), "⚡ MoFPI Grant", "From ₹14,999", "Capital Grant", "https://vrhere.in/cold-chain-subsidy"),
            ServiceItemModel("msme-subsidies-loans", "State Industrial Investment Subsidies", "MSME", "MSME & Schemes", Icons.Default.Paid, Amber500, "⚡ State Incentives", "From ₹14,999", "Power & Stamp Duty", "https://vrhere.in/msme-subsidies-loans"),

            // 6. Branding & Industrial Setup (17)
            ServiceItemModel("business-plan-preparation", "Investor-Grade Business Plan Drafting", "STARTUP", "Industrial & Setup", Icons.Default.Description, Indigo500, "⚡ 5-7 Days", "From ₹7,999", "Investor Ready", "https://vrhere.in/business-plan-preparation"),
            ServiceItemModel("pitch-deck-preparation", "VC & Angel Pitch Deck Design", "STARTUP", "Industrial & Setup", Icons.Default.Slideshow, PrimaryRed, "⚡ 5-7 Days", "From ₹9,999", "Seed & Series A", "https://vrhere.in/pitch-deck-preparation"),
            ServiceItemModel("website-branding-consulting", "Corporate Branding & Website Consulting", "STARTUP", "Industrial & Setup", Icons.Default.Language, Color(0xFF0EA5E9), "⚡ Turnkey", "From ₹6,999", "Brand Identity", "https://vrhere.in/website-branding-consulting"),
            ServiceItemModel("vendor-empanelment-docs", "Vendor Empanelment Documentation", "STARTUP", "Industrial & Setup", Icons.Default.CreateNewFolder, Color(0xFFA855F7), "⚡ 2-3 Days", "From ₹4,999", "Corporate Onboarding", "https://vrhere.in/vendor-empanelment-docs"),
            ServiceItemModel("hr-policy-documentation", "HR Policy Manual & Offer Letters", "STARTUP", "Industrial & Setup", Icons.Default.ContactPage, Emerald500, "⚡ 3-5 Days", "From ₹4,999", "Legal HR Handbooks", "https://vrhere.in/hr-policy-documentation"),
            ServiceItemModel("sop-creation-services", "Standard Operating Procedures (SOPs)", "STARTUP", "Industrial & Setup", Icons.Default.Checklist, Amber500, "⚡ 5-7 Days", "From ₹6,999", "ISO Aligned", "https://vrhere.in/sop-creation-services"),
            ServiceItemModel("loan-file-documentation", "Bank Loan File Processing & Liaison", "STARTUP", "Industrial & Setup", Icons.Default.FactCheck, Slate500, "⚡ Banking Sync", "From ₹4,999", "Fast Sanctions", "https://vrhere.in/loan-file-documentation"),
            ServiceItemModel("commercial-business-insurance", "Business, Fire & Marine Insurance", "STARTUP", "Industrial & Setup", Icons.Default.HealthAndSafety, Color(0xFFEA580C), "⚡ 24 Hours", "From ₹2,999", "Risk Insured", "https://vrhere.in/commercial-business-insurance"),
            ServiceItemModel("digital-marketing-support", "B2B Digital Marketing & Lead Gen", "STARTUP", "Industrial & Setup", Icons.Default.Campaign, Color(0xFFEC4899), "⚡ Monthly Growth", "From ₹4,999/mo", "Verified Leads", "https://vrhere.in/digital-marketing-support"),
            ServiceItemModel("pan-tan-applications", "PAN & TAN New / Correction Filing", "STARTUP", "Industrial & Setup", Icons.Default.CreditCard, Color(0xFF3B82F6), "⚡ 24-48 Hours", "From ₹999", "NSDL / UTIITSL", "https://vrhere.in/pan-tan-applications"),
            ServiceItemModel("trademark-registration", "Trademark Registration (TM & ®)", "STARTUP", "Industrial & Setup", Icons.Default.Copyright, Indigo500, "⚡ 24 Hours (TM)", "From ₹1,999", "IP India", "https://vrhere.in/trademark-registration"),
            ServiceItemModel("wealth-portfolio-management", "Wealth & Corporate Treasury Advisory", "STARTUP", "Industrial & Setup", Icons.Default.AccountBalanceWallet, Emerald500, "⚡ Wealth Strategy", "From ₹9,999", "High Returns", "https://vrhere.in/wealth-portfolio-management"),
            ServiceItemModel("machinery-sourcing", "Turnkey Industrial Machinery Sourcing", "STARTUP", "Industrial & Setup", Icons.Default.Settings, PrimaryRed, "⚡ Domestic & Import", "From ₹9,999", "OEM Vetted", "https://vrhere.in/machinery-sourcing"),
            ServiceItemModel("vendor-verification-services", "Supplier Due Diligence & Verification", "STARTUP", "Industrial & Setup", Icons.Default.VerifiedUser, Color(0xFF0EA5E9), "⚡ 2-3 Days", "From ₹4,999", "Zero Fraud Risk", "https://vrhere.in/vendor-verification-services"),
            ServiceItemModel("turnkey-plant-engineering", "Turnkey Plant Setup & Engineering", "STARTUP", "Industrial & Setup", Icons.Default.Factory, Indigo600, "⚡ Complete Setup", "From ₹19,999", "Plant Engineers", "https://vrhere.in/turnkey-plant-engineering"),
            ServiceItemModel("technology-upgradation-consulting", "Technology Upgradation Consulting", "STARTUP", "Industrial & Setup", Icons.Default.Memory, Amber500, "⚡ Industry 4.0", "From ₹11,999", "Modernization", "https://vrhere.in/technology-upgradation-consulting"),
            ServiceItemModel("industrial-feasibility-analysis", "Industrial Feasibility & Location Report", "STARTUP", "Industrial & Setup", Icons.Default.Map, Color(0xFFA855F7), "⚡ 5-7 Days", "From ₹14,999", "Full Feasibility", "https://vrhere.in/industrial-feasibility-analysis")
        )
    }

    val filteredServices = remember(searchQuery, selectedCategory) {
        allServicesList.filter { item ->
            val matchesCategory = selectedCategory == "ALL" || item.categoryId == selectedCategory
            val query = searchQuery.trim()
            val matchesSearch = query.isEmpty() ||
                    item.title.contains(query, ignoreCase = true) ||
                    item.categoryName.contains(query, ignoreCase = true) ||
                    item.trustBadge.contains(query, ignoreCase = true)
            matchesCategory && matchesSearch
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BgLight)
    ) {
        // 1. Sleek Header & Dynamic Counter
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(BgLight)
                .padding(horizontal = 16.dp, vertical = 8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Services Directory",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Black,
                        color = TextDark
                    )
                    Text(
                        text = "Choose a legal or compliance service to begin",
                        fontSize = 11.5.sp,
                        fontWeight = FontWeight.Medium,
                        color = TextMuted
                    )
                }

                Box(
                    modifier = Modifier
                        .background(Indigo500.copy(alpha = 0.1f), RoundedCornerShape(12.dp))
                        .padding(horizontal = 10.dp, vertical = 5.dp)
                ) {
                    Text(
                        text = "${filteredServices.size} Available",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Black,
                        color = Indigo600
                    )
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // 2. Creative Glowing Search Capsule
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .shadow(4.dp, RoundedCornerShape(16.dp), ambientColor = Indigo500.copy(alpha = 0.1f))
                    .background(Color.White, RoundedCornerShape(16.dp))
                    .border(
                        1.5.dp,
                        Brush.horizontalGradient(
                            listOf(Indigo500.copy(alpha = 0.35f), Color(0xFF0EA5E9).copy(alpha = 0.25f))
                        ),
                        RoundedCornerShape(16.dp)
                    )
                    .padding(horizontal = 10.dp, vertical = 6.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(34.dp)
                            .background(
                                Brush.linearGradient(listOf(Indigo500, Indigo600)),
                                RoundedCornerShape(10.dp)
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Search,
                            contentDescription = "Search",
                            tint = Color.White,
                            modifier = Modifier.size(16.dp)
                        )
                    }

                    TextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it },
                        placeholder = {
                            Text(
                                text = "Search Company, GST, ISO, Licenses...",
                                fontSize = 13.sp,
                                color = TextMuted
                            )
                        },
                        colors = TextFieldDefaults.colors(
                            focusedContainerColor = Color.Transparent,
                            unfocusedContainerColor = Color.Transparent,
                            focusedIndicatorColor = Color.Transparent,
                            unfocusedIndicatorColor = Color.Transparent
                        ),
                        singleLine = true,
                        modifier = Modifier.weight(1f)
                    )

                    if (searchQuery.isNotBlank()) {
                        IconButton(
                            onClick = { searchQuery = "" },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Close,
                                contentDescription = "Clear",
                                tint = TextMuted,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    } else {
                        Box(
                            modifier = Modifier
                                .background(Indigo500.copy(alpha = 0.08f), RoundedCornerShape(8.dp))
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(3.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Default.AutoAwesome,
                                    contentDescription = null,
                                    tint = Indigo600,
                                    modifier = Modifier.size(10.dp)
                                )
                                Text(
                                    text = "Fast Find",
                                    fontSize = 9.5.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Indigo600
                                )
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // 3. Horizontal Category Filter Chips Bar
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                categoriesList.forEach { cat ->
                    val isSelected = selectedCategory == cat.id
                    Box(
                        modifier = Modifier
                            .scaleOnPress()
                            .clip(RoundedCornerShape(14.dp))
                            .background(if (isSelected) DarkSlate else Color.White)
                            .border(
                                1.dp,
                                if (isSelected) Color.Transparent else Slate200,
                                RoundedCornerShape(14.dp)
                            )
                            .clickable { selectedCategory = cat.id }
                            .padding(horizontal = 12.dp, vertical = 7.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Icon(
                                imageVector = cat.icon,
                                contentDescription = cat.name,
                                tint = if (isSelected) Color.White else Slate600,
                                modifier = Modifier.size(13.dp)
                            )
                            Text(
                                text = cat.name,
                                fontSize = 11.5.sp,
                                fontWeight = if (isSelected) FontWeight.Black else FontWeight.Bold,
                                color = if (isSelected) Color.White else Slate700
                            )
                        }
                    }
                }
            }
        }

        HorizontalDivider(thickness = 1.dp, color = Slate200)

        // 4. Vibrant Services List matching iOS & Web
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(top = 12.dp, bottom = 100.dp)
        ) {
            if (filteredServices.isEmpty()) {
                item {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 40.dp),
                        horizontalAlignment = Alignment.CenterVertically,
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.SearchOff,
                            contentDescription = null,
                            tint = TextMuted,
                            modifier = Modifier.size(44.dp)
                        )
                        Text(
                            text = "No matching services found",
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextDark
                        )
                        Text(
                            text = "Try searching with different terms or reset your category filter.",
                            fontSize = 11.5.sp,
                            color = TextMuted
                        )
                    }
                }
            } else {
                items(filteredServices, key = { it.id }) { service ->
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .scaleOnPress()
                            .shadow(2.dp, RoundedCornerShape(16.dp), ambientColor = Color.Black.copy(alpha = 0.03f))
                            .background(Color.White, RoundedCornerShape(16.dp))
                            .border(1.dp, Slate200, RoundedCornerShape(16.dp))
                            .clickable {
                                onOpenLiveService(service.title, service.targetUrl)
                            }
                            .padding(12.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            // Vibrant Icon Badge
                            Box(
                                modifier = Modifier
                                    .size(44.dp)
                                    .background(service.colorTheme.copy(alpha = 0.12f), RoundedCornerShape(14.dp)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = service.icon,
                                    contentDescription = service.title,
                                    tint = service.colorTheme,
                                    modifier = Modifier.size(20.dp)
                                )
                            }

                            // Title, Turnaround & Trust Badge
                            Column(
                                modifier = Modifier.weight(1f),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Text(
                                    text = service.title,
                                    fontSize = 13.5.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = TextDark,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )

                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .background(Color(0xFFEEF2FF), RoundedCornerShape(6.dp))
                                            .padding(horizontal = 6.dp, vertical = 2.dp)
                                    ) {
                                        Text(
                                            text = service.turnaround,
                                            fontSize = 9.5.sp,
                                            fontWeight = FontWeight.Black,
                                            color = Indigo600
                                        )
                                    }

                                    Text(
                                        text = service.trustBadge,
                                        fontSize = 9.5.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = TextMuted
                                    )
                                }
                            }

                            // Starting Price & Navigation Chevron
                            Column(
                                horizontalAlignment = Alignment.End,
                                verticalArrangement = Arrangement.spacedBy(2.dp)
                            ) {
                                Text(
                                    text = service.startingPrice,
                                    fontSize = 11.5.sp,
                                    fontWeight = FontWeight.Black,
                                    color = TextDark
                                )

                                Icon(
                                    imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                                    contentDescription = "View Service",
                                    tint = Slate400,
                                    modifier = Modifier.size(13.dp)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
