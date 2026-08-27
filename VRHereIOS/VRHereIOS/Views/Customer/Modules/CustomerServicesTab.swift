import SwiftUI

struct ServiceCategory: Identifiable {
    let id: String
    let title: String
    let iconName: String
    let columns: [ServiceColumn]
}

struct ServiceColumn: Identifiable {
    var id: String { title }
    let title: String
    let items: [String]
}

struct CustomerServicesTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    let onSelectTab: (String) -> Void
    let onOpenLiveService: (String, String) -> Void
    
    @State private var searchQuery = ""
    
    private let categories: [ServiceCategory] = [
        ServiceCategory(
            id: "accounting-compliance-taxation",
            title: "Accounting, Compliance & Taxation Services",
            iconName: "percent",
            columns: [
                ServiceColumn(
                    title: "Accounting-as-a-Service (AaaS)",
                    items: [
                        "Cloud Accounting (Tally Prime, Zoho Books, QuickBooks, Marg)",
                        "GST Return Filing",
                        "Payroll Management (Payslips, Leave, Form 16)",
                        "Professional Tax (PT) Returns",
                        "EPF / ESI Returns",
                        "Gratuity Management",
                        "TDS/TCS Filing",
                        "Inventory & Stock Management",
                        "Invoice Generation Support",
                        "Expense Tracking Consultancy",
                        "Monthly MIS Reports"
                    ]
                ),
                ServiceColumn(
                    title: "Taxation & Legal Compliance",
                    items: [
                        "Companies Compliance Scheme 2026 (CCFS)",
                        "GST Registration",
                        "Income Tax Return Filing (ITR 1-7)",
                        "12AA/80G Certificates",
                        "Tax Planning Support",
                        "15CA Certification"
                    ]
                ),
                ServiceColumn(
                    title: "Audit Services",
                    items: [
                        "Internal Audit",
                        "GST Audit",
                        "SOX Audit",
                        "Stock & Compliance Audit",
                        "Other Audits (Need Basis)"
                    ]
                )
            ]
        ),
        ServiceCategory(
            id: "certification-quality-management",
            title: "Certification & Quality Management Services",
            iconName: "checkmark.seal.fill",
            columns: [
                ServiceColumn(
                    title: "ISO Services",
                    items: [
                        "ISO 9001:2015 - Quality Management",
                        "ISO 14001:2015 - Environmental Management",
                        "ISO 45001:2018 - Occupational Health & Safety",
                        "ISO 22000:2018 - Food Safety",
                        "ISO 27001:2022 - Information Security",
                        "ISO 50001:2018 - Energy Management",
                        "ISO 13485:2016 - Medical Devices",
                        "ISO 20000-1:2018 - IT Service Management",
                        "ISO 22301:2019 - Business Continuity"
                    ]
                ),
                ServiceColumn(
                    title: "Quality & Compliance",
                    items: [
                        "GMP / HACCP",
                        "CE Marking",
                        "ISI / BIS Certification",
                        "FDA Compliance Support"
                    ]
                ),
                ServiceColumn(
                    title: "Product & System Certifications",
                    items: [
                        "BRCGS",
                        "Kosher Certification",
                        "Halal Certification"
                    ]
                )
            ]
        ),
        ServiceCategory(
            id: "business-registration-licensing-corporate",
            title: "Business Registrations, Licensing & Corporate Services",
            iconName: "briefcase.fill",
            columns: [
                ServiceColumn(
                    title: "Company / Business Entity Registrations",
                    items: [
                        "Private Limited Company",
                        "Public Limited Company",
                        "LLP Registration",
                        "Partnership Firm Registration",
                        "Proprietorship Setup",
                        "Section 8 Company (NGO)",
                        "One Person Company",
                        "Society / Trust Registration"
                    ]
                ),
                ServiceColumn(
                    title: "Mandatory Registrations",
                    items: [
                        "Udyam Registration (MSME)",
                        "Shops & Establishment Registration",
                        "EPFO (PF) Registration",
                        "ESIC Registration",
                        "Professional Tax Registration",
                        "Startup India Registration",
                        "Import Export Code (IEC)"
                    ]
                ),
                ServiceColumn(
                    title: "Licensing Services",
                    items: [
                        "FSSAI Registration / License",
                        "LEI Certificate",
                        "Trade License",
                        "Labour / Contract Labour License",
                        "Pollution Control Board NOC / CFE / CFO",
                        "Factory License",
                        "FCRA",
                        "DARPAN for NGO"
                    ]
                ),
                ServiceColumn(
                    title: "Corporate Compliances",
                    items: [
                        "ROC Annual Filings (AOC-4, MGT-7)",
                        "Companies Compliance Scheme 2026 (CCFS)",
                        "Director KYC (DIR-3 KYC)",
                        "ROC Search Certificate",
                        "Charge Creation",
                        "Change in Shareholding",
                        "Change in Directorship",
                        "Merger / Demerger / Winding Up Compliance",
                        "Bonus / Loans / Buyback Compliance",
                        "Share Allotment & Transfer",
                        "Increase in Share Capital",
                        "Change in Name, Address, Objective",
                        "Digital Signatures (DSC Class 3)"
                    ]
                )
            ]
        ),
        ServiceCategory(
            id: "government-msme-services",
            title: "Government & MSME Services",
            iconName: "globe",
            columns: [
                ServiceColumn(
                    title: "GeM (Govt e-Marketplace)",
                    items: [
                        "GeM Seller Registration",
                        "OEM Panel Registration",
                        "Brand Approval",
                        "Product Listing",
                        "Bid Participation & Tender Management"
                    ]
                ),
                ServiceColumn(
                    title: "Other Portal Registrations",
                    items: [
                        "TReDS Registration",
                        "RERA Registration",
                        "AP/TS Single Window",
                        "NPCI Registrations",
                        "Amazon/Flipkart Seller Registration Support"
                    ]
                ),
                ServiceColumn(
                    title: "Project & Finance Support",
                    items: [
                        "DPR Preparation",
                        "CMA Data Preparation",
                        "Bank Loans - Term Loan + Working Capital",
                        "CGTMSE Loan Support",
                        "PMEGP Loan Support",
                        "Mudra Loans",
                        "Stand-Up India Loan Assistance"
                    ]
                ),
                ServiceColumn(
                    title: "MSME & Subsidy Schemes",
                    items: [
                        "CLCSS / ZED Scheme Support",
                        "PMFME (Food Processing Units)",
                        "NSIC Schemes",
                        "NABARD Schemes",
                        "Cold Chain & Food Processing Subsidy",
                        "AP/TS State Industrial Subsidy Schemes"
                    ]
                )
            ]
        ),
        ServiceCategory(
            id: "branding-industrial-setup",
            title: "Branding & Industrial Setup",
            iconName: "lightbulb.fill",
            columns: [
                ServiceColumn(
                    title: "Startup & Branding Support",
                    items: [
                        "Business Plan Preparation",
                        "Pitch Decks for Funding",
                        "Website & Branding Consulting",
                        "Vendor Empanelment Documentation",
                        "HR Policy Documentation",
                        "SOP Creation"
                    ]
                ),
                ServiceColumn(
                    title: "Additional Services",
                    items: [
                        "Loan File Documentation & Follow-up",
                        "Insurance Services (Business, Fire, Marine)",
                        "Digital Marketing Support",
                        "PAN / TAN Applications",
                        "Trademark & IP Services",
                        "Wealth Portfolio Management"
                    ]
                ),
                ServiceColumn(
                    title: "Industrial Support",
                    items: [
                        "Machinery Sourcing & Imports",
                        "Vendor Identification & Supplier Verification",
                        "Turnkey Machinery Setup Assistance",
                        "Technology Upgradation Consulting",
                        "Industry Selection & Feasibility Analysis"
                    ]
                )
            ]
        )
    ]
    
    private let liveServicesMap = [
        "Private Limited Company": "https://vrhere.in/pvt-ltd-registration",
        "Public Limited Company": "https://vrhere.in/public-limited-company",
        "LLP Registration": "https://vrhere.in/llp-registration",
        "Limited Liability Partnership (LLP)": "https://vrhere.in/llp-registration",
        "Partnership Firm Registration": "https://vrhere.in/partnership-firm",
        "Proprietorship Setup": "https://vrhere.in/proprietorship-setup",
        "Section 8 Company (NGO)": "https://vrhere.in/section-8-company",
        "One Person Company": "https://vrhere.in/one-person-company",
        "Society / Trust Registration": "https://vrhere.in/society-trust-registration",
        "GST Registration": "https://vrhere.in/gst-registration",
        "Income Tax Return Filing (ITR 1-7)": "https://vrhere.in/income-tax-return",
        "Companies Compliance Scheme 2026 (CCFS)": "https://vrhere.in/compliance-scheme-2026",
        "Cloud Accounting (Tally Prime, Zoho Books, QuickBooks, Marg)": "https://vrhere.in/accounting-services",
        "GST Return Filing": "https://vrhere.in/accounting-services",
        "Payroll Management (Payslips, Leave, Form 16)": "https://vrhere.in/accounting-services"
    ]
    
    private var filteredCategories: [ServiceCategory] {
        if searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return categories
        } else {
            let q = searchQuery.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
            return categories.compactMap { category in
                let filteredColumns = category.columns.compactMap { column -> ServiceColumn? in
                    let filteredItems = column.items.filter { item in
                        item.lowercased().contains(q) ||
                        column.title.lowercased().contains(q) ||
                        category.title.lowercased().contains(q)
                    }
                    if !filteredItems.isEmpty {
                        return ServiceColumn(title: column.title, items: filteredItems)
                    } else {
                        return nil
                    }
                }
                if !filteredColumns.isEmpty {
                    return ServiceCategory(id: category.id, title: category.title, iconName: category.iconName, columns: filteredColumns)
                } else {
                    return nil
                }
            }
        }
    }
    
    private var totalResults: Int {
        filteredCategories.reduce(0) { sum, cat in
            sum + cat.columns.reduce(0) { colSum, col in
                colSum + col.items.count
            }
        }
    }
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header Title & Subtitle
                VStack(alignment: .leading, spacing: 4) {
                    Text("Services Catalog")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.textDark)
                    Text("Select a specialized service to initiate your business journey.")
                        .font(.system(size: 13))
                        .foregroundColor(.textMuted)
                }
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Search Field
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.textMuted)
                    
                    TextField("Search for legal, tax or industrial services...", text: $searchQuery)
                        .font(.system(size: 13))
                        .foregroundColor(.textDark)
                    
                    if !searchQuery.isEmpty {
                        Button(action: {
                            searchQuery = ""
                            UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
                        }) {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundColor(.textMuted)
                        }
                    }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
                .background(Color.white)
                .cornerRadius(16)
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(Color.borderLight, lineWidth: 1)
                )
                .padding(.horizontal, 20)
                
                // Search Results Indicator
                if !searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    HStack(spacing: 8) {
                        Text("\"\(searchQuery)\"")
                            .font(.system(size: 11, weight: .black))
                            .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 4)
                            .background(Color(red: 238/255, green: 242/255, blue: 246/255))
                            .cornerRadius(8)
                    }
                    .padding(.horizontal, 20)
                }
                
                // Categories List
                if !filteredCategories.isEmpty {
                    VStack(spacing: 20) {
                        ForEach(filteredCategories) { category in
                            VStack(alignment: .leading, spacing: 20) {
                                // Category Header
                                HStack(alignment: .center, spacing: 14) {
                                    ZStack {
                                        RoundedRectangle(cornerRadius: 14)
                                            .fill(Color(red: 238/255, green: 242/255, blue: 246/255))
                                            .frame(width: 48, height: 48)
                                        Image(systemName: category.iconName)
                                            .font(.system(size: 20))
                                            .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                    }
                                    
                                    Text(category.title)
                                        .font(.system(size: 16, weight: .black))
                                        .foregroundColor(.textDark)
                                        .lineLimit(2)
                                        .multilineTextAlignment(.leading)
                                }
                                
                                // Columns
                                ForEach(category.columns) { column in
                                    VStack(alignment: .leading, spacing: 6) {
                                        Text(column.title.uppercased())
                                            .font(.system(size: 10, weight: .black))
                                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                            .tracking(1.0)
                                            .padding(.bottom, 2)
                                        
                                        Divider().background(Color.borderLight)
                                        
                                        ForEach(column.items, id: \.self) { item in
                                            Button(action: {
                                                UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
                                                if let liveUrl = liveServicesMap[item] {
                                                    onOpenLiveService(item, liveUrl)
                                                } else {
                                                    viewModel.toastMessage = "Initiating inquiry for: \(item)"
                                                    onSelectTab("Support")
                                                }
                                            }) {
                                                HStack(alignment: .center) {
                                                    Text(item)
                                                        .font(.system(size: 13, weight: .bold))
                                                        .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                                                        .multilineTextAlignment(.leading)
                                                        .frame(maxWidth: .infinity, alignment: .leading)
                                                        .padding(.vertical, 8)
                                                    
                                                    Image(systemName: "chevron.right")
                                                        .font(.system(size: 12))
                                                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                                }
                                            }
                                            .buttonStyle(PlainButtonStyle())
                                        }
                                    }
                                    .padding(.top, 4)
                                }
                            }
                            .padding(24)
                            .glassCard()
                        }
                    }
                    .padding(.horizontal, 20)
                } else {
                    // Empty Results Card
                    VStack(spacing: 16) {
                        Image(systemName: "magnifyingglass.obscured")
                            .font(.system(size: 48))
                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                        
                        Text("No services found")
                            .font(.system(size: 17, weight: .black))
                            .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                        
                        Text("We couldn't find any match for \"\(searchQuery)\".\nTry different terms or request a custom setup.")
                            .font(.system(size: 12))
                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                            .multilineTextAlignment(.center)
                            .lineSpacing(4)
                            .padding(.horizontal, 20)
                        
                        Button(action: {
                            searchQuery = ""
                            onSelectTab("Support")
                        }) {
                            Text("Consult Support Expert")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.white)
                                .padding(.horizontal, 16)
                                .padding(.vertical, 10)
                                .background(Color(red: 99/255, green: 102/255, blue: 241/255))
                                .cornerRadius(12)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }
                    .padding(.vertical, 40)
                    .frame(maxWidth: .infinity)
                    .background(Color.white)
                    .cornerRadius(28)
                    .overlay(
                        RoundedRectangle(cornerRadius: 28)
                            .stroke(Color.borderLight, lineWidth: 1)
                    )
                    .padding(.horizontal, 20)
                }
                
                // Custom Request Card (shown only when search query is empty)
                if searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    VStack(alignment: .leading, spacing: 16) {
                        HStack(spacing: 12) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 12)
                                    .fill(Color.white.opacity(0.1))
                                    .frame(width: 44, height: 44)
                                Image(systemName: "lightbulb.fill")
                                    .font(.system(size: 18))
                                    .foregroundColor(Color(red: 251/255, green: 191/255, blue: 36/255))
                            }
                            
                            Text("Need a custom business solution?")
                                .font(.system(size: 16, weight: .black))
                                .foregroundColor(.white)
                        }
                        
                        Text("Our multidisciplinary experts can create tailored end-to-end setups, feasibility reports, and turnkey projects specifically for your industry.")
                            .font(.system(size: 12))
                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                            .lineSpacing(4)
                        
                        Button(action: {
                            onSelectTab("Support")
                        }) {
                            Text("Consult Support Expert")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 12)
                                .background(Color(red: 99/255, green: 102/255, blue: 241/255))
                                .cornerRadius(12)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }
                    .padding(24)
                    .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                    .cornerRadius(28)
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 120)
            }
        }
    }
}
