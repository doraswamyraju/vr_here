import SwiftUI

struct ServiceItemModel: Identifiable {
    let id: String
    let title: String
    let categoryId: String
    let categoryName: String
    let iconName: String
    let colorTheme: Color
    let turnaround: String
    let startingPrice: String
    let trustBadge: String
    let targetUrl: String
}

struct CustomerServicesTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    let onSelectTab: (String) -> Void
    let onOpenLiveService: (String, String) -> Void
    
    @State private var searchQuery = ""
    @State private var selectedCategory: String = "ALL"
    
    private let categoriesList: [(id: String, name: String, icon: String)] = [
        ("ALL", "All Services", "square.grid.2x2.fill"),
        ("CORP", "Corporate Entity", "building.2.fill"),
        ("TAX", "Tax & Accounting", "percent"),
        ("ISO", "ISO & Quality", "checkmark.seal.fill"),
        ("LICENSE", "Licensing & Govt", "doc.plaintext.fill"),
        ("MSME", "MSME & Schemes", "globe"),
        ("STARTUP", "Industrial & Setup", "lightbulb.fill")
    ]
    
    private let allServicesList: [ServiceItemModel] = [
        // 1. Corporate Entity Registrations
        ServiceItemModel(
            id: "pvt-ltd-registration",
            title: "Private Limited Company",
            categoryId: "CORP",
            categoryName: "Corporate Entity",
            iconName: "building.2.fill",
            colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255),
            turnaround: "⚡ 7 Days",
            startingPrice: "From ₹5,499",
            trustBadge: "MCA Verified",
            targetUrl: "https://vrhere.in/pvt-ltd-registration"
        ),
        ServiceItemModel(
            id: "public-limited-company",
            title: "Public Limited Company",
            categoryId: "CORP",
            categoryName: "Corporate Entity",
            iconName: "building.columns.fill",
            colorTheme: Color(red: 79/255, green: 70/255, blue: 229/255),
            turnaround: "⚡ 10-14 Days",
            startingPrice: "From ₹14,999",
            trustBadge: "MCA Verified",
            targetUrl: "https://vrhere.in/public-limited-company"
        ),
        ServiceItemModel(
            id: "llp-registration",
            title: "Limited Liability Partnership (LLP)",
            categoryId: "CORP",
            categoryName: "Corporate Entity",
            iconName: "person.2.fill",
            colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255),
            turnaround: "⚡ 5-7 Days",
            startingPrice: "From ₹4,899",
            trustBadge: "MCA Verified",
            targetUrl: "https://vrhere.in/llp-registration"
        ),
        ServiceItemModel(
            id: "one-person-company",
            title: "One Person Company (OPC)",
            categoryId: "CORP",
            categoryName: "Corporate Entity",
            iconName: "person.crop.circle.fill",
            colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255),
            turnaround: "⚡ 5-7 Days",
            startingPrice: "From ₹4,999",
            trustBadge: "Solo Founder",
            targetUrl: "https://vrhere.in/one-person-company"
        ),
        ServiceItemModel(
            id: "partnership-firm",
            title: "Partnership Firm Registration",
            categoryId: "CORP",
            categoryName: "Corporate Entity",
            iconName: "person.3.fill",
            colorTheme: Color(red: 236/255, green: 72/255, blue: 153/255),
            turnaround: "⚡ 3-5 Days",
            startingPrice: "From ₹3,499",
            trustBadge: "State ROF",
            targetUrl: "https://vrhere.in/partnership-firm"
        ),
        ServiceItemModel(
            id: "section-8-company",
            title: "Section 8 Company (NGO)",
            categoryId: "CORP",
            categoryName: "Corporate Entity",
            iconName: "heart.fill",
            colorTheme: Color(red: 239/255, green: 68/255, blue: 68/255),
            turnaround: "⚡ 10-12 Days",
            startingPrice: "From ₹8,499",
            trustBadge: "80G / 12A Ready",
            targetUrl: "https://vrhere.in/section-8-company"
        ),
        ServiceItemModel(
            id: "society-trust-registration",
            title: "Society / Trust Registration",
            categoryId: "CORP",
            categoryName: "Corporate Entity",
            iconName: "shield.lefthalf.filled",
            colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255),
            turnaround: "⚡ 7-10 Days",
            startingPrice: "From ₹6,999",
            trustBadge: "Trust Deed",
            targetUrl: "https://vrhere.in/society-trust-registration"
        ),
        ServiceItemModel(
            id: "proprietorship-setup",
            title: "Proprietorship Setup",
            categoryId: "CORP",
            categoryName: "Corporate Entity",
            iconName: "briefcase.fill",
            colorTheme: Color(red: 100/255, green: 116/255, blue: 139/255),
            turnaround: "⚡ 2-3 Days",
            startingPrice: "From ₹1,999",
            trustBadge: "Fast Setup",
            targetUrl: "https://vrhere.in/proprietorship-setup"
        ),

        // 2. Tax & Accounting Services
        ServiceItemModel(
            id: "cloud-accounting",
            title: "Cloud Accounting (Tally, Zoho Books)",
            categoryId: "TAX",
            categoryName: "Tax & Accounting",
            iconName: "chart.pie.fill",
            colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255),
            turnaround: "⚡ Monthly Retainer",
            startingPrice: "From ₹2,999/mo",
            trustBadge: "Monthly MIS",
            targetUrl: "https://vrhere.in/cloud-accounting"
        ),
        ServiceItemModel(
            id: "gst-return-filing",
            title: "GST Return Filing (GSTR 1, 3B, 9)",
            categoryId: "TAX",
            categoryName: "Tax & Accounting",
            iconName: "arrow.triangle.2.circlepath.doc.on.clipboard",
            colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255),
            turnaround: "⚡ Monthly / Qtr",
            startingPrice: "From ₹499/mo",
            trustBadge: "Zero Penalty",
            targetUrl: "https://vrhere.in/gst-return-filing"
        ),
        ServiceItemModel(
            id: "payroll-management",
            title: "Payroll Management & Payslips",
            categoryId: "TAX",
            categoryName: "Tax & Accounting",
            iconName: "person.text.rectangle",
            colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255),
            turnaround: "⚡ Monthly Cycle",
            startingPrice: "From ₹2,499/mo",
            trustBadge: "PF/ESI Compliant",
            targetUrl: "https://vrhere.in/payroll-management"
        ),
        ServiceItemModel(
            id: "professional-tax",
            title: "Professional Tax (PTEC / PTRC)",
            categoryId: "TAX",
            categoryName: "Tax & Accounting",
            iconName: "building.2.crop.circle",
            colorTheme: Color(red: 59/255, green: 130/255, blue: 246/255),
            turnaround: "⚡ 2-3 Days",
            startingPrice: "From ₹1,999",
            trustBadge: "Commercial Taxes",
            targetUrl: "https://vrhere.in/professional-tax"
        ),
        ServiceItemModel(
            id: "epf-esi-returns",
            title: "EPF & ESIC Registration & ECR Filing",
            categoryId: "TAX",
            categoryName: "Tax & Accounting",
            iconName: "person.crop.square.filled.and.at.rectangle",
            colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255),
            turnaround: "⚡ 2-3 Days",
            startingPrice: "From ₹1,999",
            trustBadge: "EPFO & ESIC",
            targetUrl: "https://vrhere.in/epf-esi-returns"
        ),
        ServiceItemModel(
            id: "tds-tcs-filing",
            title: "TDS / TCS Return Filing (24Q, 26Q)",
            categoryId: "TAX",
            categoryName: "Tax & Accounting",
            iconName: "doc.text.fill",
            colorTheme: Color(red: 168/255, green: 85/255, blue: 247/255),
            turnaround: "⚡ Quarterly",
            startingPrice: "From ₹1,999",
            trustBadge: "TRACES Form 16",
            targetUrl: "https://vrhere.in/tds-tcs-filing"
        ),
        ServiceItemModel(
            id: "mis-reporting",
            title: "Executive MIS & Financial Dashboards",
            categoryId: "TAX",
            categoryName: "Tax & Accounting",
            iconName: "chart.bar.xaxis",
            colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255),
            turnaround: "⚡ Monthly Delivery",
            startingPrice: "From ₹3,999",
            trustBadge: "Virtual CFO",
            targetUrl: "https://vrhere.in/mis-reporting"
        ),
        ServiceItemModel(
            id: "audit-services",
            title: "Internal, GST & Tax Audits (44AB)",
            categoryId: "TAX",
            categoryName: "Tax & Accounting",
            iconName: "checkmark.shield.fill",
            colorTheme: Color(red: 239/255, green: 68/255, blue: 68/255),
            turnaround: "⚡ Audit Cycle",
            startingPrice: "From ₹9,999",
            trustBadge: "ICAI CA Practice",
            targetUrl: "https://vrhere.in/audit-services"
        ),
        ServiceItemModel(
            id: "12aa-80g-certificates",
            title: "12A & 80G Tax Exemption for NGOs",
            categoryId: "TAX",
            categoryName: "Tax & Accounting",
            iconName: "gift.fill",
            colorTheme: Color(red: 234/255, green: 88/255, blue: 12/255),
            turnaround: "⚡ 5-7 Days",
            startingPrice: "From ₹6,999",
            trustBadge: "Income Tax Exempt",
            targetUrl: "https://vrhere.in/12aa-80g-certificates"
        ),
        ServiceItemModel(
            id: "income-tax-return",
            title: "Income Tax Return Filing (ITR 1-7)",
            categoryId: "TAX",
            categoryName: "Tax & Accounting",
            iconName: "calculator",
            colorTheme: Color(red: 59/255, green: 130/255, blue: 246/255),
            turnaround: "⚡ 24-48 Hours",
            startingPrice: "From ₹1,499",
            trustBadge: "CA Assisted",
            targetUrl: "https://vrhere.in/income-tax-return"
        ),

        // 3. ISO & Quality Management
        ServiceItemModel(
            id: "iso-9001-certification",
            title: "ISO 9001:2015 Quality Management",
            categoryId: "ISO",
            categoryName: "ISO & Quality",
            iconName: "checkmark.seal.fill",
            colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255),
            turnaround: "⚡ 5-7 Days",
            startingPrice: "From ₹3,499",
            trustBadge: "IAF Accredited",
            targetUrl: "https://vrhere.in/iso-9001-certification"
        ),
        ServiceItemModel(
            id: "iso-14001-certification",
            title: "ISO 14001:2015 Environmental (EMS)",
            categoryId: "ISO",
            categoryName: "ISO & Quality",
            iconName: "leaf.fill",
            colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255),
            turnaround: "⚡ 5-7 Days",
            startingPrice: "From ₹5,499",
            trustBadge: "Green & ESG",
            targetUrl: "https://vrhere.in/iso-14001-certification"
        ),
        ServiceItemModel(
            id: "iso-45001-certification",
            title: "ISO 45001:2018 Health & Safety (OH&S)",
            categoryId: "ISO",
            categoryName: "ISO & Quality",
            iconName: "cross.case.fill",
            colorTheme: Color(red: 239/255, green: 68/255, blue: 68/255),
            turnaround: "⚡ 5-7 Days",
            startingPrice: "From ₹5,999",
            trustBadge: "Workplace Safety",
            targetUrl: "https://vrhere.in/iso-45001-certification"
        ),
        ServiceItemModel(
            id: "iso-22000-certification",
            title: "ISO 22000:2018 Food Safety (FSMS)",
            categoryId: "ISO",
            categoryName: "ISO & Quality",
            iconName: "fork.knife.circle.fill",
            colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255),
            turnaround: "⚡ 5-7 Days",
            startingPrice: "From ₹6,999",
            trustBadge: "Food Safety",
            targetUrl: "https://vrhere.in/iso-22000-certification"
        ),
        ServiceItemModel(
            id: "iso-27001-certification",
            title: "ISO 27001:2022 InfoSec & Cybersecurity",
            categoryId: "ISO",
            categoryName: "ISO & Quality",
            iconName: "lock.shield.fill",
            colorTheme: Color(red: 79/255, green: 70/255, blue: 229/255),
            turnaround: "⚡ 7-10 Days",
            startingPrice: "From ₹8,999",
            trustBadge: "Cyber Verified",
            targetUrl: "https://vrhere.in/iso-27001-certification"
        ),
        ServiceItemModel(
            id: "gmp-haccp-certification",
            title: "GMP & HACCP Certification",
            categoryId: "ISO",
            categoryName: "ISO & Quality",
            iconName: "pills.fill",
            colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255),
            turnaround: "⚡ 5-7 Days",
            startingPrice: "From ₹6,499",
            trustBadge: "WHO-GMP",
            targetUrl: "https://vrhere.in/gmp-haccp-certification"
        ),
        ServiceItemModel(
            id: "ce-marking-certification",
            title: "CE Marking for European Exports",
            categoryId: "ISO",
            categoryName: "ISO & Quality",
            iconName: "globe.europe.africa.fill",
            colorTheme: Color(red: 234/255, green: 88/255, blue: 12/255),
            turnaround: "⚡ 7-10 Days",
            startingPrice: "From ₹12,499",
            trustBadge: "EU Conformity",
            targetUrl: "https://vrhere.in/ce-marking-certification"
        ),
        ServiceItemModel(
            id: "isi-bis-certification",
            title: "ISI Mark & BIS CRS Registration",
            categoryId: "ISO",
            categoryName: "ISO & Quality",
            iconName: "star.circle.fill",
            colorTheme: Color(red: 168/255, green: 85/255, blue: 247/255),
            turnaround: "⚡ 10-15 Days",
            startingPrice: "From ₹14,999",
            trustBadge: "Bureau Standards",
            targetUrl: "https://vrhere.in/isi-bis-certification"
        ),
        ServiceItemModel(
            id: "halal-kosher-certification",
            title: "Halal & Kosher Export Certification",
            categoryId: "ISO",
            categoryName: "ISO & Quality",
            iconName: "sparkles",
            colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255),
            turnaround: "⚡ 5-7 Days",
            startingPrice: "From ₹7,999",
            trustBadge: "Global Export",
            targetUrl: "https://vrhere.in/halal-kosher-certification"
        ),

        // 4. Mandatory Licensing & Governance
        ServiceItemModel(
            id: "fssai-license",
            title: "FSSAI Food License / Registration",
            categoryId: "LICENSE",
            categoryName: "Licensing & Govt",
            iconName: "fork.knife",
            colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255),
            turnaround: "⚡ 3-5 Days",
            startingPrice: "From ₹1,999",
            trustBadge: "FoSCoS Govt",
            targetUrl: "https://vrhere.in/fssai-license"
        ),
        ServiceItemModel(
            id: "shops-establishment-license",
            title: "Shops & Establishment Act License",
            categoryId: "LICENSE",
            categoryName: "Licensing & Govt",
            iconName: "storefront.fill",
            colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255),
            turnaround: "⚡ 2-4 Days",
            startingPrice: "From ₹1,499",
            trustBadge: "State Labour Dept",
            targetUrl: "https://vrhere.in/shops-establishment-license"
        ),
        ServiceItemModel(
            id: "import-export-code",
            title: "Import Export Code (IEC)",
            categoryId: "LICENSE",
            categoryName: "Licensing & Govt",
            iconName: "airplane.departure",
            colorTheme: Color(red: 168/255, green: 85/255, blue: 247/255),
            turnaround: "⚡ 24 Hours",
            startingPrice: "From ₹2,199",
            trustBadge: "DGFT Verified",
            targetUrl: "https://vrhere.in/import-export-code"
        ),
        ServiceItemModel(
            id: "trade-license",
            title: "Municipal Trade License",
            categoryId: "LICENSE",
            categoryName: "Licensing & Govt",
            iconName: "building.2.crop.circle.fill",
            colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255),
            turnaround: "⚡ 3-5 Days",
            startingPrice: "From ₹2,499",
            trustBadge: "Municipal Corp",
            targetUrl: "https://vrhere.in/trade-license"
        ),
        ServiceItemModel(
            id: "labour-license",
            title: "Contract Labour License (CLRA)",
            categoryId: "LICENSE",
            categoryName: "Licensing & Govt",
            iconName: "person.3.sequence.fill",
            colorTheme: Color(red: 100/255, green: 116/255, blue: 139/255),
            turnaround: "⚡ 5-7 Days",
            startingPrice: "From ₹5,499",
            trustBadge: "CLRA Act",
            targetUrl: "https://vrhere.in/labour-license"
        ),
        ServiceItemModel(
            id: "pollution-noc",
            title: "Pollution Control Board NOC (CTE/CTO)",
            categoryId: "LICENSE",
            categoryName: "Licensing & Govt",
            iconName: "smoke.fill",
            colorTheme: Color(red: 239/255, green: 68/255, blue: 68/255),
            turnaround: "⚡ 7-10 Days",
            startingPrice: "From ₹9,999",
            trustBadge: "SPCB Approved",
            targetUrl: "https://vrhere.in/pollution-noc"
        ),
        ServiceItemModel(
            id: "dsc-registration",
            title: "Class 3 Digital Signature (DSC + Token)",
            categoryId: "LICENSE",
            categoryName: "Licensing & Govt",
            iconName: "key.fill",
            colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255),
            turnaround: "⚡ 15 Mins",
            startingPrice: "From ₹1,499",
            trustBadge: "CCA India",
            targetUrl: "https://vrhere.in/dsc-registration"
        ),
        ServiceItemModel(
            id: "rera-registration",
            title: "RERA Real Estate Agent / Project",
            categoryId: "LICENSE",
            categoryName: "Licensing & Govt",
            iconName: "house.and.flag.fill",
            colorTheme: Color(red: 234/255, green: 88/255, blue: 12/255),
            turnaround: "⚡ 5-7 Days",
            startingPrice: "From ₹3,999",
            trustBadge: "State RERA",
            targetUrl: "https://vrhere.in/rera-registration"
        ),

        // 5. MSME Schemes, Subsidies & Govt Portals
        ServiceItemModel(
            id: "udyam-registration",
            title: "Udyam MSME Registration Certificate",
            categoryId: "MSME",
            categoryName: "MSME & Schemes",
            iconName: "bolt.badge.a.fill",
            colorTheme: Color(red: 59/255, green: 130/255, blue: 246/255),
            turnaround: "⚡ 24 Hours",
            startingPrice: "From ₹999",
            trustBadge: "Ministry of MSME",
            targetUrl: "https://vrhere.in/udyam-registration"
        ),
        ServiceItemModel(
            id: "startup-india-registration",
            title: "Startup India DPIIT Recognition & Tax Exemption",
            categoryId: "MSME",
            categoryName: "MSME & Schemes",
            iconName: "flame.fill",
            colorTheme: Color(red: 239/255, green: 68/255, blue: 68/255),
            turnaround: "⚡ 3-5 Days",
            startingPrice: "From ₹3,499",
            trustBadge: "3 Yr Tax Holiday",
            targetUrl: "https://vrhere.in/startup-india-registration"
        ),
        ServiceItemModel(
            id: "gem-registration",
            title: "GeM Govt Marketplace Seller & OEM Panel",
            categoryId: "MSME",
            categoryName: "MSME & Schemes",
            iconName: "cart.fill",
            colorTheme: Color(red: 234/255, green: 88/255, blue: 12/255),
            turnaround: "⚡ 3-5 Days",
            startingPrice: "From ₹2,999",
            trustBadge: "Govt Tenders",
            targetUrl: "https://vrhere.in/gem-registration"
        ),
        ServiceItemModel(
            id: "treds-registration",
            title: "TReDS Invoice Factoring (RXIL, M1xchange)",
            categoryId: "MSME",
            categoryName: "MSME & Schemes",
            iconName: "creditcard.circle.fill",
            colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255),
            turnaround: "⚡ 48 Hours",
            startingPrice: "From ₹3,499",
            trustBadge: "RBI Regulated",
            targetUrl: "https://vrhere.in/treds-registration"
        ),
        ServiceItemModel(
            id: "dpr-cma-preparation",
            title: "DPR & CMA Data for Bank Loans (CC/OD)",
            categoryId: "MSME",
            categoryName: "MSME & Schemes",
            iconName: "chart.line.uptrend.xyaxis",
            colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255),
            turnaround: "⚡ 3-5 Days",
            startingPrice: "From ₹4,999",
            trustBadge: "Bank Ready",
            targetUrl: "https://vrhere.in/dpr-cma-preparation"
        ),
        ServiceItemModel(
            id: "msme-subsidies-loans",
            title: "PMEGP, Mudra & State MSME Subsidies",
            categoryId: "MSME",
            categoryName: "MSME & Schemes",
            iconName: "indianrupeesign.circle.fill",
            colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255),
            turnaround: "⚡ Scheme Cycle",
            startingPrice: "From ₹6,999",
            trustBadge: "15-35% Subsidy",
            targetUrl: "https://vrhere.in/msme-subsidies-loans"
        ),

        // 6. Branding & Industrial Setup
        ServiceItemModel(
            id: "trademark-registration",
            title: "Trademark Registration & Brand TM",
            categoryId: "STARTUP",
            categoryName: "Industrial & Setup",
            iconName: "shield.righthalf.filled",
            colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255),
            turnaround: "⚡ 24 Hours (TM)",
            startingPrice: "From ₹1,999",
            trustBadge: "IP India",
            targetUrl: "https://vrhere.in/trademark-registration"
        ),
        ServiceItemModel(
            id: "machinery-sourcing",
            title: "Machinery Sourcing & Turnkey Plant Setup",
            categoryId: "STARTUP",
            categoryName: "Industrial & Setup",
            iconName: "gearshape.2.fill",
            colorTheme: Color(red: 100/255, green: 116/255, blue: 139/255),
            turnaround: "⚡ Project Scope",
            startingPrice: "From ₹9,999",
            trustBadge: "Vendor Verified",
            targetUrl: "https://vrhere.in/machinery-sourcing"
        ),
        ServiceItemModel(
            id: "roc-annual-filings",
            title: "ROC Annual Filings (AOC-4, MGT-7, Form 11)",
            categoryId: "STARTUP",
            categoryName: "Industrial & Setup",
            iconName: "doc.badge.gearshape.fill",
            colorTheme: Color(red: 168/255, green: 85/255, blue: 247/255),
            turnaround: "⚡ Annual Filing",
            startingPrice: "From ₹4,999",
            trustBadge: "MCA21 V3",
            targetUrl: "https://vrhere.in/roc-annual-filings"
        ),
        ServiceItemModel(
            id: "director-kyc",
            title: "Director KYC (DIR-3 KYC Web & eForm)",
            categoryId: "STARTUP",
            categoryName: "Industrial & Setup",
            iconName: "person.badge.key.fill",
            colorTheme: Color(red: 59/255, green: 130/255, blue: 246/255),
            turnaround: "⚡ 10 Mins",
            startingPrice: "From ₹499",
            trustBadge: "DIN Active",
            targetUrl: "https://vrhere.in/director-kyc"
        )
    ]
    
    private var filteredServices: [ServiceItemModel] {
        allServicesList.filter { item in
            let matchesCategory = selectedCategory == "ALL" || item.categoryId == selectedCategory
            let matchesSearch = searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                item.title.localizedCaseInsensitiveContains(searchQuery) ||
                item.categoryName.localizedCaseInsensitiveContains(searchQuery)
            return matchesCategory && matchesSearch
        }
    }
    
    var body: some View {
        VStack(spacing: 0) {
            // 1. Sleek Compact Header & Search
            VStack(spacing: 10) {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Services Directory")
                            .font(.system(size: 20, weight: .black))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        Text("Choose a legal or compliance service to begin")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                    }
                    Spacer()
                    
                    Text("\(filteredServices.count) Available")
                        .font(.system(size: 10, weight: .black))
                        .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                        .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                        .cornerRadius(12)
                }
                .padding(.horizontal, 16)
                .padding(.top, 8)
                
                // Creative Glowing Search Capsule
                HStack(spacing: 10) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 10)
                            .fill(
                                LinearGradient(
                                    colors: [Color(red: 99/255, green: 102/255, blue: 241/255), Color(red: 79/255, green: 70/255, blue: 229/255)],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                )
                            )
                            .frame(width: 32, height: 32)
                        Image(systemName: "magnifyingglass")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.white)
                    }
                    
                    TextField("Search Company, GST, ISO, Licenses...", text: $searchQuery)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    
                    if !searchQuery.isEmpty {
                        Button(action: { searchQuery = "" }) {
                            Image(systemName: "xmark.circle.fill")
                                .font(.system(size: 16))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                        }
                    } else {
                        HStack(spacing: 3) {
                            Image(systemName: "sparkles")
                                .font(.system(size: 10, weight: .bold))
                            Text("Fast Find")
                                .font(.system(size: 9.5, weight: .black))
                        }
                        .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                        .cornerRadius(8)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 6)
                .background(Color.white)
                .cornerRadius(16)
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(
                            LinearGradient(
                                colors: [Color(red: 99/255, green: 102/255, blue: 241/255).opacity(0.4), Color(red: 14/255, green: 165/255, blue: 233/255).opacity(0.3)],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            ),
                            lineWidth: 1.5
                        )
                )
                .shadow(color: Color(red: 99/255, green: 102/255, blue: 241/255).opacity(0.08), radius: 8, x: 0, y: 3)
                .padding(.horizontal, 16)
                
                // 2. Horizontal Category Filter Chips Bar
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(categoriesList, id: \.id) { cat in
                            let isSelected = selectedCategory == cat.id
                            Button(action: {
                                withAnimation(.spring(response: 0.3, dampingFraction: 0.75)) {
                                    selectedCategory = cat.id
                                }
                                let impact = UIImpactFeedbackGenerator(style: .light)
                                impact.impactOccurred()
                            }) {
                                HStack(spacing: 5) {
                                    Image(systemName: cat.icon)
                                        .font(.system(size: 10, weight: .bold))
                                    Text(cat.name)
                                        .font(.system(size: 11, weight: isSelected ? .black : .bold))
                                }
                                .padding(.horizontal, 12)
                                .padding(.vertical, 6)
                                .background(
                                    isSelected
                                        ? Color(red: 15/255, green: 23/255, blue: 42/255)
                                        : Color.white
                                )
                                .foregroundColor(isSelected ? .white : Color(red: 71/255, green: 85/255, blue: 105/255))
                                .cornerRadius(14)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 14)
                                        .stroke(isSelected ? Color.clear : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                                )
                                .shadow(color: isSelected ? Color.black.opacity(0.12) : Color.clear, radius: 4, y: 2)
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 2)
                }
            }
            .padding(.bottom, 6)
            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
            
            Divider()
                .background(Color(red: 241/255, green: 245/255, blue: 249/255))
            
            // 3. Vibrant Services Cards List
            ScrollView(showsIndicators: false) {
                LazyVStack(spacing: 10) {
                    if filteredServices.isEmpty {
                        VStack(spacing: 12) {
                            Image(systemName: "doc.text.magnifyingglass")
                                .font(.system(size: 36))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                .padding(.top, 40)
                            Text("No matching services found")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                            Text("Try searching with different terms or reset your filters.")
                                .font(.system(size: 11))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                        }
                        .padding(.horizontal, 20)
                    } else {
                        ForEach(filteredServices) { service in
                            Button(action: {
                                UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
                                let impact = UIImpactFeedbackGenerator(style: .medium)
                                impact.impactOccurred()
                                onOpenLiveService(service.title, service.targetUrl)
                            }) {
                                HStack(spacing: 12) {
                                    // Vibrant Icon Badge
                                    ZStack {
                                        RoundedRectangle(cornerRadius: 14)
                                            .fill(service.colorTheme.opacity(0.12))
                                            .frame(width: 44, height: 44)
                                        Image(systemName: service.iconName)
                                            .font(.system(size: 18))
                                            .foregroundColor(service.colorTheme)
                                    }
                                    
                                    // Title & Highlights
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(service.title)
                                            .font(.system(size: 13.5, weight: .bold))
                                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                            .lineLimit(1)
                                        
                                        HStack(spacing: 6) {
                                            Text(service.turnaround)
                                                .font(.system(size: 9.5, weight: .black))
                                                .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                                .padding(.horizontal, 6)
                                                .padding(.vertical, 2)
                                                .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                                                .cornerRadius(6)
                                            
                                            Text(service.trustBadge)
                                                .font(.system(size: 9.5, weight: .bold))
                                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                        }
                                    }
                                    
                                    Spacer()
                                    
                                    // Price & Arrow
                                    VStack(alignment: .trailing, spacing: 2) {
                                        Text(service.startingPrice)
                                            .font(.system(size: 11, weight: .black))
                                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                        
                                        Image(systemName: "chevron.right")
                                            .font(.system(size: 11, weight: .bold))
                                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                    }
                                }
                                .padding(12)
                                .background(Color.white)
                                .cornerRadius(16)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 16)
                                        .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                                )
                                .shadow(color: Color.black.opacity(0.02), radius: 4, y: 2)
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 10)
                .padding(.bottom, 120) // extra bottom clearance so content scrolls cleanly above the dock
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
    }
}
