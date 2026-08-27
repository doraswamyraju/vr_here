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
        // Corporate Entity Registrations
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

        // Tax & Accounting
        ServiceItemModel(
            id: "gst-registration",
            title: "GST Registration",
            categoryId: "TAX",
            categoryName: "Tax & Accounting",
            iconName: "percent",
            colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255),
            turnaround: "⚡ 3-5 Days",
            startingPrice: "From ₹2,569",
            trustBadge: "GST Portal",
            targetUrl: "https://vrhere.in/gst-registration"
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
        ServiceItemModel(
            id: "compliance-scheme-2026",
            title: "Companies Compliance Scheme 2026",
            categoryId: "TAX",
            categoryName: "Tax & Accounting",
            iconName: "shield.checkerboard",
            colorTheme: Color(red: 168/255, green: 85/255, blue: 247/255),
            turnaround: "⚡ Active Scheme",
            startingPrice: "From ₹4,999",
            trustBadge: "Penalty Amnesty",
            targetUrl: "https://vrhere.in/compliance-scheme-2026"
        ),
        ServiceItemModel(
            id: "accounting-services",
            title: "Cloud Accounting (Tally, Zoho Books)",
            categoryId: "TAX",
            categoryName: "Tax & Accounting",
            iconName: "chart.pie.fill",
            colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255),
            turnaround: "⚡ Monthly Retainer",
            startingPrice: "From ₹3,999/mo",
            trustBadge: "Monthly MIS",
            targetUrl: "https://vrhere.in/accounting-services"
        ),
        ServiceItemModel(
            id: "gst-return-filing",
            title: "GST Return Filing (GSTR 1 & 3B)",
            categoryId: "TAX",
            categoryName: "Tax & Accounting",
            iconName: "arrow.triangle.2.circlepath.doc.on.clipboard",
            colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255),
            turnaround: "⚡ Monthly / Qtr",
            startingPrice: "From ₹999/mo",
            trustBadge: "Zero Penalty",
            targetUrl: "https://vrhere.in/accounting-services"
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
            targetUrl: "https://vrhere.in/accounting-services"
        ),

        // ISO & Quality Management
        ServiceItemModel(
            id: "iso-9001-certification",
            title: "ISO 9001:2015 Quality Management",
            categoryId: "ISO",
            categoryName: "ISO & Quality",
            iconName: "checkmark.seal.fill",
            colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255),
            turnaround: "⚡ 5-7 Days",
            startingPrice: "From ₹4,499",
            trustBadge: "IAF Accredited",
            targetUrl: "https://vrhere.in/iso-certification"
        ),
        ServiceItemModel(
            id: "iso-27001-certification",
            title: "ISO 27001:2022 InfoSec Security",
            categoryId: "ISO",
            categoryName: "ISO & Quality",
            iconName: "lock.shield.fill",
            colorTheme: Color(red: 79/255, green: 70/255, blue: 229/255),
            turnaround: "⚡ 7-10 Days",
            startingPrice: "From ₹8,999",
            trustBadge: "Cyber Verified",
            targetUrl: "https://vrhere.in/iso-certification"
        ),
        ServiceItemModel(
            id: "ce-marking-bis",
            title: "CE Marking & ISI/BIS Certification",
            categoryId: "ISO",
            categoryName: "ISO & Quality",
            iconName: "star.circle.fill",
            colorTheme: Color(red: 234/255, green: 88/255, blue: 12/255),
            turnaround: "⚡ 10-15 Days",
            startingPrice: "From ₹12,499",
            trustBadge: "Global Standards",
            targetUrl: "https://vrhere.in/iso-certification"
        ),

        // Licensing & Compliance
        ServiceItemModel(
            id: "fssai-registration",
            title: "FSSAI Food License / Registration",
            categoryId: "LICENSE",
            categoryName: "Licensing & Govt",
            iconName: "fork.knife",
            colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255),
            turnaround: "⚡ 3-5 Days",
            startingPrice: "From ₹1,999",
            trustBadge: "Food Safety",
            targetUrl: "https://vrhere.in/fssai-license"
        ),
        ServiceItemModel(
            id: "shops-establishment",
            title: "Shops & Establishment Act License",
            categoryId: "LICENSE",
            categoryName: "Licensing & Govt",
            iconName: "storefront.fill",
            colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255),
            turnaround: "⚡ 2-4 Days",
            startingPrice: "From ₹1,499",
            trustBadge: "Municipal Reg.",
            targetUrl: "https://vrhere.in/shops-establishment"
        ),
        ServiceItemModel(
            id: "udyam-msme",
            title: "Udyam Registration (MSME)",
            categoryId: "LICENSE",
            categoryName: "Licensing & Govt",
            iconName: "bolt.badge.a.fill",
            colorTheme: Color(red: 59/255, green: 130/255, blue: 246/255),
            turnaround: "⚡ 24 Hours",
            startingPrice: "From ₹999",
            trustBadge: "Govt Subsidies",
            targetUrl: "https://vrhere.in/udyam-msme"
        ),
        ServiceItemModel(
            id: "import-export-code",
            title: "Import Export Code (IEC)",
            categoryId: "LICENSE",
            categoryName: "Licensing & Govt",
            iconName: "airplane.departure",
            colorTheme: Color(red: 168/255, green: 85/255, blue: 247/255),
            turnaround: "⚡ 2 Days",
            startingPrice: "From ₹2,199",
            trustBadge: "DGFT Verified",
            targetUrl: "https://vrhere.in/iec-code"
        ),

        // MSME & Schemes
        ServiceItemModel(
            id: "gem-portal-registration",
            title: "GeM Govt Marketplace Seller Portal",
            categoryId: "MSME",
            categoryName: "MSME & Schemes",
            iconName: "cart.fill",
            colorTheme: Color(red: 234/255, green: 88/255, blue: 12/255),
            turnaround: "⚡ 3-5 Days",
            startingPrice: "From ₹3,999",
            trustBadge: "Govt Tenders",
            targetUrl: "https://vrhere.in/gem-portal"
        ),
        ServiceItemModel(
            id: "treds-rera",
            title: "TReDS & RERA Project Registration",
            categoryId: "MSME",
            categoryName: "MSME & Schemes",
            iconName: "building.2.crop.circle",
            colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255),
            turnaround: "⚡ 7 Days",
            startingPrice: "From ₹7,499",
            trustBadge: "Statutory",
            targetUrl: "https://vrhere.in/rera-registration"
        ),

        // Industrial & Startup
        ServiceItemModel(
            id: "dpr-pitch-decks",
            title: "DPR & Pitch Decks for Bank Loans",
            categoryId: "STARTUP",
            categoryName: "Industrial & Setup",
            iconName: "chart.line.uptrend.xyaxis",
            colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255),
            turnaround: "⚡ 5-7 Days",
            startingPrice: "From ₹9,999",
            trustBadge: "CMA & Bank Ready",
            targetUrl: "https://vrhere.in/dpr-preparation"
        ),
        ServiceItemModel(
            id: "machinery-turnkey-setup",
            title: "Machinery Sourcing & Turnkey Setup",
            categoryId: "STARTUP",
            categoryName: "Industrial & Setup",
            iconName: "gearshape.2.fill",
            colorTheme: Color(red: 100/255, green: 116/255, blue: 139/255),
            turnaround: "⚡ Advisory",
            startingPrice: "From ₹15,000",
            trustBadge: "Vendor Verified",
            targetUrl: "https://vrhere.in/machinery-sourcing"
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
                
                // Search Input Field
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                    
                    TextField("Search Company, GST, ISO, Licenses...", text: $searchQuery)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    
                    if !searchQuery.isEmpty {
                        Button(action: { searchQuery = "" }) {
                            Image(systemName: "xmark.circle.fill")
                                .font(.system(size: 14))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                        }
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color.white)
                .cornerRadius(12)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                )
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
