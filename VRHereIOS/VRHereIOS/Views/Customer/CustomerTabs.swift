import SwiftUI
import Combine

// --- Service Package & Service Detail Models ---
struct ServicePackage: Codable, Identifiable {
    let id: String
    let name: String
    let price: Double
    var isAdjustable: Bool = false
    var isPopular: Bool = false
    let description: String
    let features: [String]
    let creativeButtonText: String
}

struct ServiceDetail: Codable, Identifiable {
    let id: String
    let title: String
    let description: String
    let iconKey: String
    let packages: [ServicePackage]
}

class ServiceCatalog: ObservableObject {
    static let shared = ServiceCatalog()
    
    @Published var items: [String: ServiceDetail] = [
        "pvt-ltd-registration": ServiceDetail(
            id: "pvt-ltd-registration",
            title: "Private Limited Registration",
            description: "Launch your startup with the most credible legal structure. Get Certificate of Incorporation, MOA, AOA, PAN & TAN in 7 days.",
            iconKey: "building",
            packages: [
                ServicePackage(id: "consultation", name: "Expert Consultation", price: 499.0, isAdjustable: true, description: "Start here if you are unsure. Fee fully adjusted against registration.", features: ["30 Mins CA/CS Call", "Business Structure Advice", "Name Availability Check", "Compliance Roadmap"], creativeButtonText: "Consult CA/CS Now"),
                ServicePackage(id: "basic", name: "Basic Plan", price: 5499.0, description: "Essential registration for verified startups.", features: ["Name Approval (RUN)", "COI, PAN & TAN", "MOA & AOA", "2 DIN & 2 DSC", "PF/ESI/MSME registration"], creativeButtonText: "Launch Basic Setup"),
                ServicePackage(id: "advance", name: "Advance Plan", price: 11399.0, isPopular: true, description: "Complete compliance & web presence.", features: ["Everything in Basic", "GST Registration", "Import Export Code (IEC)", "ISO Certification", "Professional Website"], creativeButtonText: "Unlock Premium Growth")
            ]
        ),
        "gst-registration": ServiceDetail(
            id: "gst-registration",
            title: "GST Registration",
            description: "Get your GST number quickly and start filing returns. Essential for businesses with turnover above thresholds.",
            iconKey: "file",
            packages: [
                ServicePackage(id: "consultation", name: "Expert Consultation", price: 499.0, isAdjustable: true, description: "Speak with our tax expert about your GST eligibility and documents.", features: ["30 Mins Call", "Eligibility Check", "Documents List Review", "State-Specific Rules"], creativeButtonText: "Speak with Tax Expert"),
                ServicePackage(id: "basic", name: "Basic Plan", price: 2569.0, description: "Essential GST registration package.", features: ["New GST Registration", "Updating Bank Account", "1st Month GST Return"], creativeButtonText: "Get Registered Now"),
                ServicePackage(id: "expert", name: "Expert Plan", price: 9059.0, isPopular: true, description: "Complete tax compliance suite.", features: ["Everything in Basic", "LUT Filing", "IEC Code Application", "2 Months GST Returns", "Priority Support"], creativeButtonText: "Go Pro Compliance")
            ]
        ),
        "partnership-firm": ServiceDetail(
            id: "partnership-firm",
            title: "Partnership Firm Registration",
            description: "Ideal for small businesses with multiple owners. Shared responsibilities and faster decision making.",
            iconKey: "people",
            packages: [
                ServicePackage(id: "consultation", name: "Expert Consultation", price: 499.0, isAdjustable: true, description: "Discuss partnership clauses and legal requirements with our experts.", features: ["Partnership Deed Advice", "Clause Review", "Tax Implication Call"], creativeButtonText: "Draft Partners Deed"),
                ServicePackage(id: "basic", name: "Basic Plan", price: 4899.0, description: "Essential registration for partnership firms.", features: ["Deed Drafting", "PAN & TAN Applications", "Firm Registration", "Notary Assistance"], creativeButtonText: "Establish Partnership")
            ]
        ),
        "income-tax-return": ServiceDetail(
            id: "income-tax-return",
            title: "Income Tax Return (ITR)",
            description: "End-to-end ITR filing support for salaried, professionals, and businesses with compliance-first review.",
            iconKey: "calculator",
            packages: [
                ServicePackage(id: "consultation", name: "Expert Consultation", price: 499.0, isAdjustable: true, description: "Review your tax computation and self-assessment with a CA.", features: ["Tax Planning Call", "Computation Review", "Deduction Guidance"], creativeButtonText: "Solve Tax Doubts"),
                ServicePackage(id: "itr-filing", name: "ITR Filing", price: 1499.0, isPopular: true, description: "Standard filing service for individuals/professionals.", features: ["ITR 1 to 4 Support", "Computation Review", "Notice Response Guidance"], creativeButtonText: "Secure My Tax Filing")
            ]
        )
    ]
    
    private init() {}
    
    func updateFromApi(apiData: [MobileServiceDetail]) {
        for apiDetail in apiData {
            let pkgs = apiDetail.packages.map { apiPkg in
                ServicePackage(
                    id: apiPkg.id,
                    name: apiPkg.name,
                    price: apiPkg.price,
                    isAdjustable: apiPkg.isAdjustable,
                    isPopular: apiPkg.isPopular,
                    description: apiPkg.description,
                    features: apiPkg.features,
                    creativeButtonText: apiPkg.buttonText
                )
            }
            items[apiDetail.pageId] = ServiceDetail(
                id: apiDetail.pageId,
                title: apiDetail.title,
                description: apiDetail.description,
                iconKey: apiDetail.iconKey,
                packages: pkgs
            )
        }
    }
}

func getIconName(key: String) -> String {
    switch key.lowercased() {
    case "apartment", "building": return "building.2"
    case "description", "file": return "doc.text"
    case "people", "group": return "person.3"
    case "calculate", "calculator": return "calculator"
    case "star": return "star"
    case "phone": return "phone"
    default: return "briefcase"
    }
}

// ==========================================
// 1. CUSTOMER HOME TAB
// ==========================================
struct CustomerHomeTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    let userName: String
    @Binding var searchQuery: String
    let onSelectTab: (String) -> Void
    let onOpenProject: (String) -> Void
    let onOpenLiveService: (String, String) -> Void
    let onLogout: () -> Void
    
    @State private var showNotifications = false
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                // 1. Welcome banner with Notifications and Refresh buttons
                HStack(alignment: .center) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Hello, \(userName)")
                            .font(.system(size: 24, weight: .black))
                            .foregroundColor(.textDark)
                        Text("Here's what's happening today.")
                            .font(.system(size: 13))
                            .foregroundColor(.textMuted)
                    }
                    
                    Spacer()
                    
                    HStack(spacing: 8) {
                        let unreadNotifications = viewModel.notifications.filter { !$0.isRead }
                        let unreadCount = unreadNotifications.count
                        
                        // Notification Bell Button
                        Button(action: { showNotifications = true }) {
                            ZStack(alignment: .topTrailing) {
                                Image(systemName: unreadCount > 0 ? "bell.badge.fill" : "bell.fill")
                                    .font(.system(size: 18, weight: .semibold))
                                    .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                    .frame(width: 42, height: 42)
                                    .background(Color.bgInput)
                                    .cornerRadius(12)
                                
                                if unreadCount > 0 {
                                    Circle()
                                        .fill(Color.red)
                                        .frame(width: 8, height: 8)
                                        .padding(.trailing, 8)
                                        .padding(.top, 8)
                                }
                            }
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                        
                        // Refresh Button
                        Button(action: { viewModel.refreshAllData(silent: false) }) {
                            Image(systemName: "arrow.clockwise")
                                .font(.system(size: 18, weight: .bold))
                                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                .frame(width: 42, height: 42)
                                .background(Color.bgInput)
                                .cornerRadius(12)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }
                }
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // 2. Active Search Bar
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Image(systemName: "magnifyingglass")
                            .foregroundColor(.textMuted)
                        TextField("Search services (e.g. GST, Company...)", text: $searchQuery)
                            .font(.system(size: 14))
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
                    .cornerRadius(14)
                    .shadow(color: Color.black.opacity(0.04), radius: 6, x: 0, y: 2)
                    .overlay(
                        RoundedRectangle(cornerRadius: 14)
                            .stroke(Color.borderLight, lineWidth: 1)
                    )
                    
                    // Search Autocomplete Suggestions List
                    if !searchQuery.isEmpty {
                        VStack(alignment: .leading, spacing: 0) {
                            let matches = ServiceCatalog.shared.items.values.filter {
                                $0.title.lowercased().contains(searchQuery.lowercased())
                            }
                            
                            if matches.isEmpty {
                                Text("No services matched")
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundColor(.textMuted)
                                    .padding(12)
                            } else {
                                ForEach(Array(matches.prefix(4))) { item in
                                    Button(action: {
                                        let selectedTitle = item.title
                                        searchQuery = ""
                                        UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
                                        onOpenLiveService(selectedTitle, "https://vrhere.in/services/\(item.id)")
                                    }) {
                                        HStack {
                                            Image(systemName: "arrow.up.right.circle.fill")
                                                .foregroundColor(.primaryRed)
                                            Text(item.title)
                                                .font(.system(size: 13, weight: .bold))
                                                .foregroundColor(.textDark)
                                            Spacer()
                                            Image(systemName: "chevron.right")
                                                .font(.caption2)
                                                .foregroundColor(.textMuted)
                                        }
                                        .padding(.horizontal, 14)
                                        .padding(.vertical, 12)
                                    }
                                    .buttonStyle(PlainButtonStyle())
                                    
                                    Divider().background(Color.borderLight)
                                }
                            }
                        }
                        .background(Color.white)
                        .cornerRadius(12)
                        .shadow(color: Color.black.opacity(0.08), radius: 10, x: 0, y: 4)
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .stroke(Color.borderLight, lineWidth: 1)
                        )
                    }
                }
                .padding(.horizontal, 20)
                
                // 3. Active Portfolio Overview Metric Card
                let activeOrders = viewModel.orders.filter { $0.status != "Completed" }
                VStack(alignment: .leading, spacing: 12) {
                    ZStack {
                        LinearGradient(gradient: Gradient(colors: [Color(red: 79/255, green: 70/255, blue: 229/255), Color(red: 109/255, green: 40/255, blue: 217/255)]), startPoint: .topLeading, endPoint: .bottomTrailing)
                        
                        VStack(alignment: .leading, spacing: 14) {
                            HStack {
                                Image(systemName: "briefcase.fill")
                                    .foregroundColor(.white.opacity(0.8))
                                    .font(.system(size: 12))
                                Text("ACTIVE PORTFOLIO")
                                    .font(.system(size: 10, weight: .black))
                                    .foregroundColor(.white.opacity(0.8))
                                    .tracking(1.0)
                            }
                            
                            HStack(alignment: .bottom) {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text("\(activeOrders.count)")
                                        .font(.system(size: 40, weight: .black))
                                        .foregroundColor(.white)
                                    Text("Projects currently in progress")
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(Color(red: 224/255, green: 231/255, blue: 255/255))
                                }
                                Spacer()
                                
                                Button(action: { onSelectTab("Orders") }) {
                                    Text("Track Status")
                                        .font(.system(size: 12, weight: .black))
                                        .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                        .padding(.horizontal, 16)
                                        .padding(.vertical, 10)
                                        .background(Color.white)
                                        .cornerRadius(12)
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                            }
                        }
                        .padding(20)
                    }
                    .cornerRadius(24)
                    .padding(.horizontal, 20)
                }
                
                // 4. Latest Services Image Slider (Carousel Banner Ad)
                VStack(alignment: .leading, spacing: 12) {
                    Text("Latest Services & Promos")
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                    
                    TabView {
                        ForEach([
                            ("compliance_ad", "CCFS Compliance Scheme 2026", "Ensure your company stays compliant. Get up to 40% discount on filings.", Color.indigo),
                            ("trademark_ad", "Protect Your Brand Identity", "Register your trademark today. Prevent competitors from copying your logo.", Color.purple),
                            ("funding_ad", "Startup Funding Accelerator", "Launch your fundraising campaign with structured investor pitch reviews.", Color.blue)
                        ], id: \.0) { id, title, subtitle, color in
                            ZStack {
                                LinearGradient(gradient: Gradient(colors: [color, color.opacity(0.8)]), startPoint: .topLeading, endPoint: .bottomTrailing)
                                
                                VStack(alignment: .leading, spacing: 8) {
                                    Spacer()
                                    Text("SPECIAL EVENT")
                                        .font(.system(size: 8, weight: .black))
                                        .foregroundColor(.white.opacity(0.9))
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 3)
                                        .background(Color.white.opacity(0.2))
                                        .cornerRadius(4)
                                    Text(title)
                                        .font(.system(size: 16, weight: .black))
                                        .foregroundColor(.white)
                                    Text(subtitle)
                                        .font(.system(size: 11, weight: .semibold))
                                        .foregroundColor(.white.opacity(0.85))
                                        .lineLimit(2)
                                }
                                .padding(16)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .cornerRadius(16)
                            .padding(.horizontal, 20)
                        }
                    }
                    .tabViewStyle(PageTabViewStyle(indexDisplayMode: .always))
                    .frame(height: 140)
                }
                
                // 5. Redesigned Current Orders Section (formerly Operational Pipeline)
                if !activeOrders.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Current Orders")
                            .font(.system(size: 14, weight: .black))
                            .foregroundColor(.textDark)
                            .padding(.horizontal, 20)
                        
                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 16) {
                                ForEach(activeOrders) { order in
                                    Button(action: { onOpenProject(order.id) }) {
                                        VStack(alignment: .leading, spacing: 12) {
                                            HStack(alignment: .top) {
                                                VStack(alignment: .leading, spacing: 2) {
                                                    Text(order.serviceName)
                                                        .font(.system(size: 14, weight: .black))
                                                        .foregroundColor(.textDark)
                                                        .lineLimit(1)
                                                    Text(order.packageName)
                                                        .font(.system(size: 11, weight: .semibold))
                                                        .foregroundColor(.textMuted)
                                                }
                                                Spacer()
                                                
                                                let statusColor: Color = {
                                                    switch order.status.lowercased() {
                                                    case "drafting", "in progress": return Color.blue
                                                    case "pending documents", "awaiting details": return Color.orange
                                                    case "completed": return Color.green
                                                    default: return Color.primaryRed
                                                    }
                                                }()
                                                
                                                Text(order.status)
                                                    .font(.system(size: 8, weight: .black))
                                                    .foregroundColor(statusColor)
                                                    .padding(.horizontal, 6)
                                                    .padding(.vertical, 3)
                                                    .background(statusColor.opacity(0.1))
                                                    .cornerRadius(6)
                                            }
                                            
                                            let completedTasks = order.tasks.filter { $0.status == "Completed" }.count
                                            let totalTasks = order.tasks.count
                                            let progress = totalTasks > 0 ? Double(completedTasks) / Double(totalTasks) : 0.0
                                            
                                            VStack(alignment: .leading, spacing: 6) {
                                                HStack {
                                                    Text("Completeness: \(Int(progress * 100))%")
                                                        .font(.system(size: 10, weight: .bold))
                                                        .foregroundColor(.textMuted)
                                                    Spacer()
                                                    Text("\(completedTasks)/\(totalTasks) Milestones")
                                                        .font(.system(size: 9, weight: .semibold))
                                                        .foregroundColor(.textMuted)
                                                }
                                                
                                                ZStack(alignment: .leading) {
                                                    RoundedRectangle(cornerRadius: 4)
                                                        .fill(Color.borderLight)
                                                        .frame(height: 6)
                                                    RoundedRectangle(cornerRadius: 4)
                                                        .fill(LinearGradient(gradient: Gradient(colors: [.primaryRed, .red]), startPoint: .leading, endPoint: .trailing))
                                                        .frame(width: max(0, min(218, 218 * CGFloat(progress))), height: 6)
                                                }
                                            }
                                        }
                                        .frame(width: 218)
                                        .padding(16)
                                        .glassCard()
                                    }
                                    .buttonStyle(PlainButtonStyle())
                                }
                            }
                            .padding(.horizontal, 20)
                        }
                    }
                }
                
                // 6. Attention Needed (Tasks)
                let pendingReqs = viewModel.orders.flatMap { $0.customerRequirements }.filter { $0.status.lowercased() != "verified" }
                VStack(alignment: .leading, spacing: 12) {
                    Text("Attention Needed (Tasks)")
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                    
                    if pendingReqs.isEmpty {
                        // Display clean simulated action items
                        VStack(spacing: 8) {
                            HStack(spacing: 12) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundColor(.orange)
                                    .font(.system(size: 18))
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("Verify Business Address Proof")
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Text("Please upload registration details to continue.")
                                        .font(.system(size: 11))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                                Image(systemName: "chevron.right")
                                    .font(.caption)
                                    .foregroundColor(.textMuted)
                            }
                            .padding(14)
                            .background(Color.orange.opacity(0.06))
                            .cornerRadius(12)
                            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.orange.opacity(0.15), lineWidth: 1))
                        }
                        .padding(.horizontal, 20)
                    } else {
                        VStack(spacing: 8) {
                            ForEach(Array(pendingReqs.prefix(2))) { req in
                                Button(action: { onSelectTab("Orders") }) {
                                    HStack(spacing: 12) {
                                        Image(systemName: "doc.badge.ellipsis")
                                            .foregroundColor(.red)
                                            .font(.system(size: 18))
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(req.title)
                                                .font(.system(size: 13, weight: .bold))
                                                .foregroundColor(.textDark)
                                            Text(req.description)
                                                .font(.system(size: 11))
                                                .foregroundColor(.textMuted)
                                                .lineLimit(1)
                                        }
                                        Spacer()
                                        Image(systemName: "chevron.right")
                                            .font(.caption)
                                            .foregroundColor(.textMuted)
                                    }
                                    .padding(14)
                                    .glassCard()
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                        .padding(.horizontal, 20)
                    }
                }
                
                // 7. Investment & Funding Desk Section
                VStack(alignment: .leading, spacing: 12) {
                    Text("Investment & Funding Desk")
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                    
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 16) {
                            VStack(alignment: .leading, spacing: 8) {
                                Image(systemName: "chart.line.uptrend.xyaxis")
                                    .font(.title3)
                                    .foregroundColor(.white)
                                    .frame(width: 38, height: 38)
                                    .background(Color.blue)
                                    .cornerRadius(8)
                                
                                Text("Startup Seed Funding")
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("Pitch to 100+ active venture capitalists.")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                                    .lineLimit(2)
                                Spacer()
                            }
                            .frame(width: 150, height: 130)
                            .padding(12)
                            .glassCard()
                            
                            VStack(alignment: .leading, spacing: 8) {
                                Image(systemName: "signature")
                                    .font(.title3)
                                    .foregroundColor(.white)
                                    .frame(width: 38, height: 38)
                                    .background(Color.purple)
                                    .cornerRadius(8)
                                
                                Text("Pitch Deck Optimization")
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("Expert review to refine business plans.")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                                    .lineLimit(2)
                                Spacer()
                            }
                            .frame(width: 150, height: 130)
                            .padding(12)
                            .glassCard()
                        }
                        .padding(.horizontal, 20)
                    }
                }
                
                // 8. Accounting & GST Returns
                VStack(alignment: .leading, spacing: 12) {
                    Text("Accounting & GST Returns")
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                    
                    VStack(spacing: 10) {
                        ForEach([
                            ("GST Monthly Filings", "book.closed.fill", "Regular commercial filings with zero penalties.", Color.green),
                            ("Bookkeeping & Audit Support", "doc.text.magnifyingglass", "Accounting sheets checked by experienced CAs.", Color.indigo)
                        ], id: \.0) { title, icon, desc, color in
                            Button(action: { onSelectTab("Services") }) {
                                HStack(spacing: 14) {
                                    Image(systemName: icon)
                                        .foregroundColor(color)
                                        .font(.title3)
                                        .frame(width: 36, height: 36)
                                        .background(color.opacity(0.1))
                                        .cornerRadius(8)
                                    
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(title)
                                            .font(.system(size: 13, weight: .bold))
                                            .foregroundColor(.textDark)
                                        Text(desc)
                                            .font(.system(size: 11))
                                            .foregroundColor(.textMuted)
                                    }
                                    Spacer()
                                    Image(systemName: "chevron.right")
                                        .font(.caption)
                                        .foregroundColor(.textMuted)
                                }
                                .padding(12)
                                .glassCard()
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                // 9. Standard Services list (Business Setup Services)
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("Business Setup Services")
                            .font(.system(size: 14, weight: .black))
                            .foregroundColor(.textDark)
                        Spacer()
                        Button(action: { onSelectTab("Services") }) {
                            Text("See All")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.primaryRed)
                        }
                    }
                    .padding(.horizontal, 20)
                    
                    let filteredItems = ServiceCatalog.shared.items.values
                    VStack(spacing: 12) {
                        ForEach(Array(filteredItems)) { item in
                            Button(action: {
                                onOpenLiveService(item.title, "https://vrhere.in/services/\(item.id)")
                            }) {
                                HStack(spacing: 16) {
                                    Image(systemName: getIconName(key: item.iconKey))
                                        .font(.title2)
                                        .foregroundColor(.white)
                                        .frame(width: 44, height: 44)
                                        .background(Color.primaryRed)
                                        .cornerRadius(10)
                                    
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(item.title)
                                            .font(.system(size: 13, weight: .bold))
                                            .foregroundColor(.textDark)
                                        Text(item.description)
                                            .font(.system(size: 11))
                                            .foregroundColor(.textMuted)
                                            .lineLimit(1)
                                    }
                                    Spacer()
                                    Image(systemName: "chevron.right")
                                        .font(.caption)
                                        .foregroundColor(.textMuted)
                                }
                                .padding(12)
                                .glassCard()
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                // 10. Insights Feed
                VStack(alignment: .leading, spacing: 12) {
                    Text("Insights & Compliance Feed")
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                    
                    VStack(spacing: 12) {
                        ForEach([
                            ("GST Council Updates (2026)", "Important changes in e-invoicing limits for businesses.", "2 hours ago"),
                            ("New LLP Filing Deadlines", "Avoid penalties! MCA has declared new timelines for Form 11 filing.", "1 day ago"),
                            ("How to Protect Your Brand", "Complete guide to trademark search & registration.", "3 days ago")
                        ], id: \.0) { title, snippet, time in
                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Text("Compliance Alert")
                                        .font(.system(size: 9, weight: .bold))
                                        .foregroundColor(.primaryRed)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 3)
                                        .background(Color.primaryRed.opacity(0.1))
                                        .cornerRadius(4)
                                    Spacer()
                                    Text(time)
                                        .font(.system(size: 10))
                                        .foregroundColor(.textMuted)
                                }
                                Text(title)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text(snippet)
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                                    .lineLimit(2)
                            }
                            .padding(14)
                            .glassCard()
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 120) // Floating bar spacing
            }
        }
        .sheet(isPresented: $showNotifications) {
            NavigationView {
                ScrollView {
                    VStack(spacing: 12) {
                        if viewModel.notifications.isEmpty {
                            VStack(spacing: 8) {
                                Text("No notifications available.")
                                    .font(.system(size: 13))
                                    .foregroundColor(.textMuted)
                                    .padding(.top, 40)
                            }
                            .frame(maxWidth: .infinity)
                        } else {
                            ForEach(viewModel.notifications) { notification in
                                Button(action: {
                                    if !notification.isRead {
                                        viewModel.markNotificationAsRead(id: notification.id)
                                    }
                                }) {
                                    VStack(alignment: .leading, spacing: 8) {
                                        HStack {
                                            HStack(spacing: 6) {
                                                Text("VR")
                                                    .font(.system(size: 8, weight: .black))
                                                    .foregroundColor(.white)
                                                    .padding(4)
                                                    .background(Color(red: 99/255, green: 102/255, blue: 241/255))
                                                    .cornerRadius(4)
                                                Text("VR HERE")
                                                    .font(.system(size: 10, weight: .black))
                                                    .foregroundColor(.textDark)
                                                    .tracking(0.3)
                                                if !notification.isRead {
                                                    Circle()
                                                        .fill(Color(red: 99/255, green: 102/255, blue: 241/255))
                                                        .frame(width: 6, height: 6)
                                                }
                                            }
                                            
                                            Spacer()
                                            
                                            Text(notification.type.uppercased())
                                                .font(.system(size: 8, weight: .black))
                                                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                                .padding(.horizontal, 6)
                                                .padding(.vertical, 3)
                                                .background(Color.bgInput)
                                                .cornerRadius(4)
                                        }
                                        
                                        Text(notification.title)
                                            .font(.system(size: 13, weight: .black))
                                            .foregroundColor(.textDark)
                                            .multilineTextAlignment(.leading)
                                        
                                        Text(notification.message)
                                            .font(.system(size: 11))
                                            .foregroundColor(.textMuted)
                                            .lineSpacing(3)
                                            .multilineTextAlignment(.leading)
                                    }
                                    .padding(14)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(notification.isRead ? Color.bgLight : Color.white)
                                    .cornerRadius(16)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 16)
                                            .stroke(notification.isRead ? Color.borderLight : Color(red: 99/255, green: 102/255, blue: 241/255).opacity(0.25), lineWidth: 1)
                                    )
                                    .shadow(color: Color.black.opacity(0.02), radius: 4, x: 0, y: 2)
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                    }
                    .padding(20)
                }
                .background(Color.bgLight.ignoresSafeArea())
                .navigationTitle("Notifications")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button("Close") {
                            showNotifications = false
                        }
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                    }
                }
            }
        }
    }
}

// ==========================================
// 2. CUSTOMER SERVICES TAB
// ==========================================
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
                        "Private Limited / Public Limited Company",
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
        "Private Limited / Public Limited Company": "https://vrhere.in/pvt-ltd-registration",
        "GST Registration": "https://vrhere.in/gst-registration",
        "Income Tax Return Filing (ITR 1-7)": "https://vrhere.in/income-tax-return",
        "Partnership Firm Registration": "https://vrhere.in/partnership-firm",
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
                        .foregroundColor(.textDark) // high-contrast black text
                    
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
                        Text("\(totalResults) RESULT\(totalResults != 1 ? "S" : "") FOR")
                            .font(.system(size: 10, weight: .black))
                            .foregroundColor(.textMuted)
                            .tracking(0.5)
                        
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

// ==========================================
// 3. SERVICE DETAIL & PREFILL/CHECKOUT OVERLAY
// ==========================================
struct CustomerServiceDetailScreen: View {
    let serviceKey: String
    let onBackClick: () -> Void
    let onNeedAdviceClick: () -> Void
    let onCheckoutClick: (String, ServicePackage, String, String, String) -> Void
    
    @State private var selectedPackage: ServicePackage? = nil
    @State private var clientName = SessionManager.shared.getUserName()
    @State private var clientEmail = SessionManager.shared.getUserEmail()
    @State private var clientPhone = SessionManager.shared.getPhone()
    @State private var termsAccepted = false
    @State private var isPrefillOpen = false
    
    var body: some View {
        if let service = ServiceCatalog.shared.items[serviceKey] {
            ZStack {
                Color.bgLight.ignoresSafeArea()
                
                VStack(spacing: 0) {
                    // Header Bar
                    HStack {
                        Button(action: onBackClick) {
                            HStack(spacing: 6) {
                                Image(systemName: "chevron.backward")
                                Text("Back")
                            }
                            .font(.system(size: 14, weight: .bold))
                            .foregroundColor(.primaryRed)
                        }
                        Spacer()
                        Text(service.title)
                            .font(.system(size: 16, weight: .black))
                            .foregroundColor(.textDark)
                        Spacer()
                        Spacer().frame(width: 60)
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
                    .background(Color.white)
                    
                    Divider()
                        .background(Color.borderLight)
                    
                    ScrollView {
                        VStack(alignment: .leading, spacing: 20) {
                            VStack(alignment: .leading, spacing: 8) {
                                Text(service.title)
                                    .font(.system(size: 24, weight: .black))
                                    .foregroundColor(.textDark)
                                Text(service.description)
                                    .font(.system(size: 13))
                                    .foregroundColor(.textMuted)
                                    .lineSpacing(4)
                            }
                            .padding(.horizontal, 20)
                            .padding(.top, 16)
                            
                            // Plans
                            VStack(spacing: 16) {
                                ForEach(service.packages) { pkg in
                                    let isSelected = selectedPackage?.id == pkg.id
                                    
                                    VStack(alignment: .leading, spacing: 12) {
                                        HStack {
                                            Text(pkg.name)
                                                .font(.system(size: 16, weight: .bold))
                                                .foregroundColor(.textDark)
                                            Spacer()
                                            if pkg.isPopular {
                                                Text("POPULAR")
                                                    .font(.system(size: 8, weight: .black))
                                                    .foregroundColor(.white)
                                                    .padding(.horizontal, 8)
                                                    .padding(.vertical, 4)
                                                    .background(Color.primaryRed)
                                                    .cornerRadius(4)
                                            }
                                        }
                                        
                                        HStack(alignment: .bottom, spacing: 4) {
                                            Text("₹\(Int(pkg.price))")
                                                .font(.system(size: 24, weight: .black))
                                                .foregroundColor(.textDark)
                                            Text(pkg.isAdjustable ? "(Consultation credit adjusted)" : "+ Taxes")
                                                .font(.system(size: 10, weight: .bold))
                                                .foregroundColor(pkg.isAdjustable ? .blue : .textMuted)
                                                .padding(.bottom, 3)
                                        }
                                        
                                        Text(pkg.description)
                                            .font(.system(size: 12))
                                            .foregroundColor(.textMuted)
                                        
                                        VStack(alignment: .leading, spacing: 6) {
                                            ForEach(pkg.features, id: \.self) { feat in
                                                HStack(spacing: 8) {
                                                    Image(systemName: "checkmark.circle.fill")
                                                        .foregroundColor(.green)
                                                        .font(.system(size: 14))
                                                    Text(feat)
                                                        .font(.system(size: 12, weight: .semibold))
                                                        .foregroundColor(.textDark)
                                                }
                                            }
                                        }
                                        .padding(.vertical, 4)
                                        
                                        Button(action: {
                                            selectedPackage = pkg
                                            isPrefillOpen = true
                                        }) {
                                            Text(pkg.creativeButtonText.uppercased())
                                                .font(.system(size: 11, weight: .black))
                                                .foregroundColor(.white)
                                                .frame(maxWidth: .infinity)
                                                .frame(height: 44)
                                                .background(isSelected ? Color.blue : Color.primaryRed)
                                                .cornerRadius(10)
                                        }
                                        .buttonStyle(ScaleOnPressButtonStyle())
                                    }
                                    .padding(16)
                                    .glassCard()
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 16)
                                            .stroke(isSelected ? Color.blue : Color.clear, lineWidth: 2)
                                    )
                                    .onTapGesture {
                                        selectedPackage = pkg
                                    }
                                }
                            }
                            .padding(.horizontal, 20)
                            
                            // Advice Section
                            VStack(alignment: .center, spacing: 8) {
                                Text("Unsure about your package requirements?")
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Button(action: onNeedAdviceClick) {
                                    Text("CONNECT WITH CA/CS PROFESSIONAL")
                                        .font(.system(size: 11, weight: .black))
                                        .foregroundColor(.blue)
                                }
                            }
                            .frame(maxWidth: .infinity)
                            .padding(20)
                            .glassCard()
                            .padding(.horizontal, 20)
                            
                            Spacer().frame(height: 50)
                        }
                    }
                }
                
                // Prefill details sheet
                if isPrefillOpen, let pkg = selectedPackage {
                    ZStack {
                        Color.black.opacity(0.4)
                            .ignoresSafeArea()
                            .onTapGesture { isPrefillOpen = false }
                        
                        VStack(alignment: .leading, spacing: 16) {
                            Text("Confirm Details")
                                .font(.system(size: 18, weight: .black))
                                .foregroundColor(.textDark)
                            
                            CustomInputField(label: "Contact Name", placeholder: "Your Name", iconName: "person", text: $clientName)
                            CustomInputField(label: "Contact Email", placeholder: "Your Email", iconName: "envelope", text: $clientEmail)
                            CustomInputField(label: "Contact Phone", placeholder: "Your Phone", iconName: "phone", text: $clientPhone)
                            
                            Toggle(isOn: $termsAccepted) {
                                Text("I accept the Terms and Conditions of service.")
                                    .font(.system(size: 12))
                                    .foregroundColor(.textMuted)
                            }
                            
                            Button(action: {
                                isPrefillOpen = false
                                onCheckoutClick(service.title, pkg, clientName, clientEmail, clientPhone)
                            }) {
                                Text("PROCEED TO PAY ₹\(Int(pkg.price))")
                                    .font(.system(size: 13, weight: .black))
                                    .foregroundColor(.white)
                                    .frame(maxWidth: .infinity)
                                    .frame(height: 50)
                                    .background(termsAccepted ? Color.primaryRed : Color.gray)
                                    .cornerRadius(12)
                            }
                            .disabled(!termsAccepted)
                            .buttonStyle(ScaleOnPressButtonStyle())
                        }
                        .padding(24)
                        .background(Color.white)
                        .cornerRadius(20)
                        .padding(20)
                        .shadow(radius: 12)
                    }
                }
            }
        } else {
            Text("Service loading...")
        }
    }
}

// ==========================================
// 4. CUSTOMER ORDERS TAB
// ==========================================
struct CustomerOrdersTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    @Binding var selectedOrderId: String
    let onSelectTab: (String) -> Void
    
    @Environment(\.openURL) private var openURL
    @State private var selectedCategory = "All"
    
    private let categories = ["All", "Active", "Completed", "Action Required"]
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if selectedOrderId.isEmpty {
                    Text("Your Compliance Orders")
                        .font(.system(size: 18, weight: .black))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                        .padding(.top, 16)
                    
                    // Horizontal Categories Filter
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(categories, id: \.self) { category in
                                let isSelected = selectedCategory == category
                                Button(action: { selectedCategory = category }) {
                                    Text(category)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(isSelected ? .white : Color(red: 71/255, green: 85/255, blue: 105/255))
                                        .padding(.horizontal, 16)
                                        .padding(.vertical, 8)
                                        .background(isSelected ? Color(red: 99/255, green: 102/255, blue: 241/255) : Color(red: 238/255, green: 242/255, blue: 246/255))
                                        .cornerRadius(12)
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                            }
                        }
                        .padding(.horizontal, 20)
                    }
                    
                    let filteredOrders = viewModel.orders.filter { order in
                        switch selectedCategory {
                        case "Active":
                            return order.status != "Completed"
                        case "Completed":
                            return order.status == "Completed"
                        case "Action Required":
                            return order.status == "Pending Documents" || order.status == "Waiting for Clarification"
                        default:
                            return true
                        }
                    }
                    
                    if filteredOrders.isEmpty {
                        VStack(spacing: 16) {
                            Spacer().frame(height: 20)
                            VStack(spacing: 16) {
                                ZStack {
                                    Circle()
                                        .fill(Color(red: 238/255, green: 242/255, blue: 246/255))
                                        .frame(width: 64, height: 64)
                                    Image(systemName: "folder.badge.questionmark")
                                        .font(.system(size: 28))
                                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                }
                                
                                VStack(spacing: 4) {
                                    Text("No Orders Found")
                                        .font(.system(size: 16, weight: .black))
                                        .foregroundColor(.textDark)
                                    Text("Looks like you haven't started any projects in this category.")
                                        .font(.system(size: 11))
                                        .foregroundColor(.textMuted)
                                        .multilineTextAlignment(.center)
                                }
                                .padding(.horizontal, 24)
                                
                                Button(action: { onSelectTab("Services") }) {
                                    Text("Browse Services")
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.white)
                                        .padding(.horizontal, 16)
                                        .padding(.vertical, 10)
                                        .background(Color(red: 99/255, green: 102/255, blue: 241/255))
                                        .cornerRadius(12)
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                            }
                            .padding(.vertical, 32)
                            .frame(maxWidth: .infinity)
                            .background(Color.white)
                            .cornerRadius(24)
                            .overlay(
                                RoundedRectangle(cornerRadius: 24)
                                    .stroke(Color.borderLight, lineWidth: 1)
                            )
                            .shadow(color: Color.black.opacity(0.02), radius: 8)
                            .padding(.horizontal, 20)
                        }
                    } else {
                        VStack(spacing: 12) {
                            ForEach(filteredOrders) { order in
                                Button(action: { selectedOrderId = order.id }) {
                                    VStack(alignment: .leading, spacing: 14) {
                                        HStack(spacing: 12) {
                                            Image(systemName: "briefcase.fill")
                                                .font(.system(size: 16))
                                                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                                .frame(width: 44, height: 44)
                                                .background(Color.bgInput)
                                                .cornerRadius(12)
                                            
                                            VStack(alignment: .leading, spacing: 2) {
                                                Text(order.serviceName)
                                                    .font(.system(size: 13, weight: .bold))
                                                    .foregroundColor(.textDark)
                                                    .multilineTextAlignment(.leading)
                                                Text(order.packageName)
                                                    .font(.system(size: 11))
                                                    .foregroundColor(.textMuted)
                                            }
                                            
                                            Spacer()
                                            
                                            StatusBadgeWidgetView(status: order.status)
                                        }
                                        
                                        let completeness = getStatusProgressPercent(status: order.status)
                                        VStack(alignment: .leading, spacing: 6) {
                                            HStack {
                                                Text("COMPLETENESS")
                                                    .font(.system(size: 9, weight: .black))
                                                    .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                                    .tracking(0.5)
                                                Spacer()
                                                Text("\(completeness)%")
                                                    .font(.system(size: 11, weight: .black))
                                                    .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                            }
                                            
                                            GeometryReader { geo in
                                                ZStack(alignment: .leading) {
                                                    RoundedRectangle(cornerRadius: 3)
                                                        .fill(Color(red: 238/255, green: 242/255, blue: 246/255))
                                                        .frame(height: 6)
                                                    RoundedRectangle(cornerRadius: 3)
                                                        .fill(Color(red: 99/255, green: 102/255, blue: 241/255))
                                                        .frame(width: geo.size.width * CGFloat(Double(completeness) / 100.0), height: 6)
                                                }
                                            }
                                            .frame(height: 6)
                                        }
                                    }
                                    .padding(16)
                                    .glassCard()
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                        .padding(.horizontal, 20)
                    }
                } else if let order = viewModel.orders.first(where: { $0.id == selectedOrderId }) {
                    // Order Drilldown View
                    VStack(alignment: .leading, spacing: 16) {
                        Button(action: { selectedOrderId = "" }) {
                            HStack(spacing: 6) {
                                Image(systemName: "arrow.left")
                                    .font(.system(size: 14, weight: .bold))
                                Text("Back to Subscriptions")
                                    .font(.system(size: 13, weight: .bold))
                            }
                            .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                        }
                        .padding(.top, 16)
                        .buttonStyle(ScaleOnPressButtonStyle())
                        
                        // 1. Project Header & Milestone Card
                        VStack(alignment: .leading, spacing: 16) {
                            HStack(alignment: .top) {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(order.serviceName)
                                        .font(.system(size: 18, weight: .black))
                                        .foregroundColor(.textDark)
                                        .multilineTextAlignment(.leading)
                                    Text(order.packageName)
                                        .font(.system(size: 12))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                                StatusBadgeWidgetView(status: order.status)
                            }
                            
                            Divider().background(Color.borderLight)
                            
                            let completeness = getStatusProgressPercent(status: order.status)
                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Text("PROJECT COMPLETENESS")
                                        .font(.system(size: 10, weight: .black))
                                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                    Spacer()
                                    Text("\(completeness)%")
                                        .font(.system(size: 12, weight: .black))
                                        .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                }
                                
                                GeometryReader { geo in
                                    ZStack(alignment: .leading) {
                                        RoundedRectangle(cornerRadius: 4)
                                            .fill(Color(red: 238/255, green: 242/255, blue: 246/255))
                                            .frame(height: 8)
                                        RoundedRectangle(cornerRadius: 4)
                                            .fill(Color(red: 99/255, green: 102/255, blue: 241/255))
                                            .frame(width: geo.size.width * CGFloat(Double(completeness) / 100.0), height: 8)
                                    }
                                }
                                .frame(height: 8)
                            }
                            
                            Spacer().frame(height: 4)
                            
                            Text("Milestone Tracking Status")
                                .font(.system(size: 14, weight: .black))
                                .foregroundColor(.textDark)
                            
                            // Stepper vertical milestones
                            let milestones = ["Pending Documents", "Documents Verified", "Processing at Portal", "Waiting for Clarification", "Completed"]
                            let currentMilestoneIndex = milestones.firstIndex(of: order.status) ?? -1
                            
                            VStack(alignment: .leading, spacing: 12) {
                                ForEach(0..<milestones.count, id: \.self) { index in
                                    let milestone = milestones[index]
                                    let isCompleted = index < currentMilestoneIndex
                                    let isActive = index == currentMilestoneIndex
                                    
                                    HStack(spacing: 12) {
                                        ZStack {
                                            Circle()
                                                .fill(isActive ? Color(red: 99/255, green: 102/255, blue: 241/255) : (isCompleted ? Color(red: 16/255, green: 185/255, blue: 129/255) : Color(red: 203/255, green: 213/255, blue: 225/255)))
                                                .frame(width: 18, height: 18)
                                            
                                            if isCompleted {
                                                Image(systemName: "checkmark")
                                                    .font(.system(size: 10, weight: .bold))
                                                    .foregroundColor(.white)
                                            }
                                        }
                                        
                                        Text(milestone)
                                            .font(.system(size: 13, weight: isActive ? .black : .bold))
                                            .foregroundColor(isActive ? Color(red: 99/255, green: 102/255, blue: 241/255) : (isCompleted ? Color(red: 16/255, green: 185/255, blue: 129/255) : Color.textMuted))
                                    }
                                }
                            }
                        }
                        .padding(20)
                        .glassCard()
                        
                        // 2. Latest Updates & Tasks Timeline
                        VStack(alignment: .leading, spacing: 14) {
                            Text("Latest Updates & Tasks")
                                .font(.system(size: 15, weight: .black))
                                .foregroundColor(.textDark)
                            
                            if order.tasks.isEmpty {
                                HStack(spacing: 8) {
                                    Image(systemName: "info.circle")
                                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                    Text("No tasks or updates available yet.")
                                        .font(.system(size: 12))
                                        .foregroundColor(.textMuted)
                                }
                                .frame(maxWidth: .infinity, alignment: .center)
                                .padding(.vertical, 8)
                            } else {
                                VStack(alignment: .leading, spacing: 16) {
                                    ForEach(order.tasks) { task in
                                        HStack(alignment: .top, spacing: 12) {
                                            let (iconName, iconColor) = { () -> (String, Color) in
                                                switch task.status {
                                                case "Completed":
                                                    return ("checkmark.circle.fill", Color(red: 16/255, green: 185/255, blue: 129/255))
                                                case "In Progress":
                                                    return ("clock.fill", Color(red: 99/255, green: 102/255, blue: 241/255))
                                                default:
                                                    return ("circle", Color(red: 148/255, green: 163/255, blue: 184/255))
                                                }
                                            }()
                                            
                                            Image(systemName: iconName)
                                                .font(.system(size: 16))
                                                .foregroundColor(iconColor)
                                                .frame(width: 20, height: 20)
                                            
                                            VStack(alignment: .leading, spacing: 2) {
                                                Text(task.title)
                                                    .font(.system(size: 13, weight: .black))
                                                    .foregroundColor(task.status == "Completed" ? Color.textMuted : Color.textDark)
                                                if !task.description.isEmpty {
                                                    Text(task.description)
                                                        .font(.system(size: 11))
                                                        .foregroundColor(.textMuted)
                                                        .multilineTextAlignment(.leading)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        .padding(20)
                        .glassCard()
                        
                        // 3. Vault Requirements
                        VStack(alignment: .leading, spacing: 14) {
                            Text("Vault Requirements")
                                .font(.system(size: 15, weight: .black))
                                .foregroundColor(.textDark)
                            
                            if order.customerRequirements.isEmpty {
                                Text("No custom requirements requested for this order.")
                                    .font(.system(size: 12))
                                    .foregroundColor(.textMuted)
                            } else {
                                VStack(spacing: 12) {
                                    ForEach(order.customerRequirements) { req in
                                        HStack(alignment: .center, spacing: 12) {
                                            VStack(alignment: .leading, spacing: 2) {
                                                Text(req.title)
                                                    .font(.system(size: 12, weight: .black))
                                                    .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                                                    .multilineTextAlignment(.leading)
                                                Text(req.description)
                                                    .font(.system(size: 10))
                                                    .foregroundColor(.textMuted)
                                                    .multilineTextAlignment(.leading)
                                            }
                                            Spacer()
                                            
                                            let isVerified = req.status == "Verified"
                                            Text(req.status)
                                                .font(.system(size: 9, weight: .black))
                                                .foregroundColor(isVerified ? Color(red: 6/255, green: 95/255, blue: 70/255) : Color(red: 146/255, green: 64/255, blue: 14/255))
                                                .padding(.horizontal, 8)
                                                .padding(.vertical, 4)
                                                .background(isVerified ? Color(red: 209/255, green: 250/255, blue: 229/255) : Color(red: 254/255, green: 243/255, blue: 199/255))
                                                .cornerRadius(6)
                                        }
                                    }
                                }
                            }
                        }
                        .padding(20)
                        .glassCard()
                        
                        // 4. Documents Summary Card
                        VStack(alignment: .leading, spacing: 14) {
                            HStack {
                                Text("Documents Summary")
                                    .font(.system(size: 15, weight: .black))
                                    .foregroundColor(.textDark)
                                Spacer()
                                Button(action: { onSelectTab("Vault") }) {
                                    Text("Open Vault")
                                        .font(.system(size: 11, weight: .black))
                                        .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                            }
                            
                            HStack(spacing: 12) {
                                // Client Uploads
                                VStack(alignment: .leading, spacing: 8) {
                                    Text("MY UPLOADS")
                                        .font(.system(size: 9, weight: .black))
                                        .foregroundColor(.textMuted)
                                    Spacer().frame(height: 2)
                                    if order.clientDocuments.isEmpty {
                                        Text("No files uploaded")
                                            .font(.system(size: 11))
                                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                    } else {
                                        ForEach(Array(order.clientDocuments.prefix(3))) { doc in
                                            Button(action: {
                                                if let url = getAbsoluteURL(path: doc.url) {
                                                    openURL(url)
                                                }
                                            }) {
                                                HStack {
                                                    Text("• \(doc.name)")
                                                        .font(.system(size: 11))
                                                        .foregroundColor(.blue)
                                                        .lineLimit(1)
                                                        .multilineTextAlignment(.leading)
                                                    Spacer()
                                                }
                                            }
                                            .buttonStyle(PlainButtonStyle())
                                        }
                                        if order.clientDocuments.count > 3 {
                                            Text("+\(order.clientDocuments.count - 3) more...")
                                                .font(.system(size: 9, weight: .bold))
                                                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                        }
                                    }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(14)
                                .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                                .cornerRadius(16)
                                
                                // Admin Docs
                                VStack(alignment: .leading, spacing: 8) {
                                    Text("ADMIN DOCS")
                                        .font(.system(size: 9, weight: .black))
                                        .foregroundColor(.textMuted)
                                    Spacer().frame(height: 2)
                                    if order.adminDocuments.isEmpty {
                                        Text("No certificates yet")
                                            .font(.system(size: 11))
                                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                    } else {
                                        ForEach(Array(order.adminDocuments.prefix(3))) { doc in
                                            Button(action: {
                                                if let url = getAbsoluteURL(path: doc.url) {
                                                    openURL(url)
                                                }
                                            }) {
                                                HStack {
                                                    Text("• \(doc.name)")
                                                        .font(.system(size: 11))
                                                        .foregroundColor(.blue)
                                                        .lineLimit(1)
                                                        .multilineTextAlignment(.leading)
                                                    Spacer()
                                                }
                                            }
                                            .buttonStyle(PlainButtonStyle())
                                        }
                                        if order.adminDocuments.count > 3 {
                                            Text("+\(order.adminDocuments.count - 3) more...")
                                                .font(.system(size: 9, weight: .bold))
                                                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                        }
                                    }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(14)
                                .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                                .cornerRadius(16)
                            }
                        }
                        .padding(20)
                        .glassCard()
                        
                        // 5. Assigned Expert Card
                        VStack(alignment: .leading, spacing: 14) {
                            Text("Assigned Expert")
                                .font(.system(size: 15, weight: .black))
                                .foregroundColor(.textDark)
                            
                            if let expert = order.assignedEmployee {
                                HStack(spacing: 12) {
                                    ZStack {
                                        Circle()
                                            .fill(Color(red: 238/255, green: 242/255, blue: 246/255))
                                            .frame(width: 44, height: 44)
                                        Image(systemName: "person.fill")
                                            .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                    }
                                    
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(expert.name.isEmpty ? "Compliance Expert" : expert.name)
                                            .font(.system(size: 14, weight: .black))
                                            .foregroundColor(.textDark)
                                        Text(expert.role.isEmpty ? "Assigned Expert" : expert.role.uppercased())
                                            .font(.system(size: 9, weight: .black))
                                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                    }
                                }
                                
                                Divider().background(Color.borderLight)
                                
                                VStack(alignment: .leading, spacing: 10) {
                                    if !expert.email.isEmpty {
                                        Button(action: {
                                            if let url = URL(string: "mailto:\(expert.email)") {
                                                UIApplication.shared.open(url)
                                            }
                                        }) {
                                            HStack(spacing: 8) {
                                                Image(systemName: "envelope.fill")
                                                    .font(.system(size: 14))
                                                    .foregroundColor(.textMuted)
                                                Text(expert.email)
                                                    .font(.system(size: 12))
                                                    .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                                            }
                                        }
                                        .buttonStyle(PlainButtonStyle())
                                    }
                                    
                                    Button(action: {
                                        if let url = URL(string: "tel:918008530606") {
                                            UIApplication.shared.open(url)
                                        }
                                    }) {
                                        HStack(spacing: 8) {
                                            Image(systemName: "phone.fill")
                                                .font(.system(size: 14))
                                                .foregroundColor(.textMuted)
                                            Text("+91 80085 30606")
                                                .font(.system(size: 12))
                                                .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                                        }
                                    }
                                    .buttonStyle(PlainButtonStyle())
                                }
                            } else {
                                HStack(spacing: 8) {
                                    Image(systemName: "person.fill")
                                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                    Text("Expert assignment pending.")
                                        .font(.system(size: 12))
                                        .foregroundColor(.textMuted)
                                }
                                .frame(maxWidth: .infinity, alignment: .center)
                                .padding(.vertical, 8)
                            }
                        }
                        .padding(20)
                        .glassCard()
                        
                        // 6. Financial Summary Card
                        let orderPayments = viewModel.payments.filter {
                            $0.serviceName == order.serviceName && $0.packageName == order.packageName
                        }
                        let totalPaid = orderPayments.filter { $0.status == "Completed" }.reduce(0.0) { $0 + $1.amount }
                        let balance = max(0.0, order.price - totalPaid)
                        
                        VStack(alignment: .leading, spacing: 14) {
                            HStack(spacing: 8) {
                                Image(systemName: "receipt")
                                    .font(.system(size: 16, weight: .bold))
                                    .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                                Text("Financial Summary")
                                    .font(.system(size: 15, weight: .black))
                                    .foregroundColor(Color(red: 6/255, green: 78/255, blue: 59/255))
                            }
                            
                            VStack(spacing: 8) {
                                HStack {
                                    Text("Total Price")
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(Color(red: 6/255, green: 95/255, blue: 70/255))
                                    Spacer()
                                    Text("₹\(Int(order.price))")
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(Color(red: 6/255, green: 78/255, blue: 59/255))
                                }
                                
                                HStack {
                                    Text("Amount Paid")
                                        .font(.system(size: 13))
                                        .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                                    Spacer()
                                    Text("₹\(Int(totalPaid))")
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(Color(red: 6/255, green: 78/255, blue: 59/255))
                                }
                                
                                Divider().background(Color(red: 167/255, green: 243/255, blue: 208/255))
                                
                                HStack {
                                    Text("Balance Due")
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(Color(red: 6/255, green: 78/255, blue: 59/255))
                                    Spacer()
                                    Text("₹\(Int(balance))")
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(Color(red: 6/255, green: 78/255, blue: 59/255))
                                }
                            }
                            
                            if !orderPayments.isEmpty {
                                Spacer().frame(height: 4)
                                Text("RECENT INVOICES")
                                    .font(.system(size: 9, weight: .black))
                                    .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                                    .tracking(0.5)
                                
                                VStack(spacing: 8) {
                                    ForEach(orderPayments) { p in
                                        HStack {
                                            let dateString = p.createdAt.count >= 10 ? String(p.createdAt.prefix(10)) : "Recent"
                                            Text(dateString)
                                                .font(.system(size: 11))
                                                .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                                            Spacer()
                                            Text("₹\(Int(p.amount)) (\(p.status))")
                                                .font(.system(size: 11, weight: .bold))
                                                .foregroundColor(Color(red: 6/255, green: 78/255, blue: 59/255))
                                        }
                                    }
                                }
                            }
                        }
                        .padding(20)
                        .background(Color(red: 236/255, green: 253/255, blue: 245/255))
                        .cornerRadius(24)
                        .overlay(
                            RoundedRectangle(cornerRadius: 24)
                                .stroke(Color(red: 167/255, green: 243/255, blue: 208/255), lineWidth: 1)
                        )
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

struct StatusBadgeWidgetView: View {
    let status: String
    
    var body: some View {
        let (bg, text) = colorsForStatus(status)
        Text(status)
            .font(.system(size: 9, weight: .black))
            .foregroundColor(text)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(bg)
            .cornerRadius(12)
    }
    
    private func colorsForStatus(_ status: String) -> (Color, Color) {
        switch status {
        case "Processing at Portal":
            return (Color(red: 219/255, green: 234/255, blue: 254/255), Color(red: 30/255, green: 64/255, blue: 175/255))
        case "Waiting for Clarification":
            return (Color(red: 243/255, green: 232/255, blue: 255/255), Color(red: 107/255, green: 33/255, blue: 168/255))
        case "Completed":
            return (Color(red: 209/255, green: 250/255, blue: 229/255), Color(red: 6/255, green: 95/255, blue: 70/255))
        case "Pending Documents":
            return (Color(red: 254/255, green: 243/255, blue: 199/255), Color(red: 146/255, green: 64/255, blue: 14/255))
        case "Documents Verified":
            return (Color(red: 236/255, green: 253/255, blue: 245/255), Color(red: 4/255, green: 120/255, blue: 87/255))
        default:
            return (Color(red: 241/255, green: 245/255, blue: 249/255), Color(red: 71/255, green: 85/255, blue: 105/255))
        }
    }
}

func getStatusProgressPercent(status: String) -> Int {
    switch status {
    case "Pending Documents": return 20
    case "Documents Verified": return 40
    case "Processing at Portal": return 60
    case "Waiting for Clarification": return 70
    case "Completed": return 100
    default: return 0
    }
}

// ==========================================
// 5. CUSTOMER BILLS & INVOICES TAB
// ==========================================
struct CustomerInvoicesTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    @Environment(\.openURL) private var openURL
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Bills & Payment Receipts")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                if viewModel.payments.isEmpty {
                    Text("No billing receipts found.")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                } else {
                    VStack(spacing: 12) {
                        ForEach(viewModel.payments) { pay in
                            VStack(alignment: .leading, spacing: 10) {
                                HStack {
                                    Text(pay.serviceName)
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    Text(pay.status)
                                        .font(.system(size: 9, weight: .bold))
                                        .foregroundColor(.white)
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .background(pay.status == "Completed" ? Color.green : Color.orange)
                                        .cornerRadius(6)
                                }
                                
                                Text(pay.packageName)
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                                
                                HStack {
                                    Text("ID: \(pay.paymentId)")
                                        .font(.system(size: 10))
                                        .foregroundColor(.textMuted)
                                    Spacer()
                                    Text("₹\(Int(pay.amount))")
                                        .font(.system(size: 14, weight: .black))
                                        .foregroundColor(.textDark)
                                }
                                
                                if let invUrl = pay.invoiceUrl, !invUrl.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                                    Divider().background(Color.borderLight)
                                    Button(action: {
                                        if let url = getAbsoluteURL(path: invUrl) {
                                            openURL(url)
                                        }
                                    }) {
                                        HStack {
                                            Image(systemName: "arrow.down.circle.fill")
                                                .foregroundColor(.blue)
                                            Text("Download Invoice PDF")
                                                .font(.system(size: 11, weight: .bold))
                                                .foregroundColor(.blue)
                                            Spacer()
                                        }
                                        .padding(.top, 4)
                                    }
                                    .buttonStyle(PlainButtonStyle())
                                }
                            }
                            .padding(14)
                            .glassCard()
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 6. CUSTOMER VAULT TAB
// ==========================================
struct CustomerVaultTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    @Environment(\.openURL) private var openURL
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Document Vault")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                let documents = viewModel.orders.flatMap { $0.clientDocuments + $0.adminDocuments }
                
                if documents.isEmpty {
                    Text("Your uploaded certificates will display here once verified.")
                        .font(.system(size: 13))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                } else {
                    VStack(spacing: 12) {
                        ForEach(documents) { doc in
                            HStack {
                                Image(systemName: "doc.fill")
                                    .foregroundColor(.primaryRed)
                                    .font(.title2)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(doc.name)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Text(doc.uploadedAt)
                                        .font(.system(size: 9))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                                Button(action: {
                                    if let url = getAbsoluteURL(path: doc.url) {
                                        openURL(url)
                                    }
                                }) {
                                    Image(systemName: "arrow.down.circle")
                                        .font(.title3)
                                        .foregroundColor(.blue)
                                }
                            }
                            .padding(12)
                            .glassCard()
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 7. CUSTOMER SUPPORT TAB
// ==========================================
struct CustomerSupportTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Support Communication Desk")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                // Raise new ticket card
                VStack(alignment: .leading, spacing: 12) {
                    Text("Open New Query Ticket")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textDark)
                    
                    CustomInputField(label: "Subject", placeholder: "Short summary", iconName: "tag", text: $viewModel.ticketSubject)
                    CustomInputField(label: "Description", placeholder: "Detail issues", iconName: "doc.text", text: $viewModel.ticketDescription)
                    
                    Button(action: {
                        viewModel.createSupportTicket()
                    }) {
                        Text("SUBMIT TICKET QUERY")
                            .font(.system(size: 11, weight: .black))
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .frame(height: 44)
                            .background(Color.primaryRed)
                            .cornerRadius(10)
                    }
                    .buttonStyle(ScaleOnPressButtonStyle())
                }
                .padding(16)
                .glassCard()
                .padding(.horizontal, 20)
                
                // History of tickets
                if !viewModel.tickets.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Ticket Logs")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.textDark)
                            .padding(.horizontal, 20)
                        
                        ForEach(viewModel.tickets) { ticket in
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Text(ticket.subject)
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    Text(ticket.status)
                                        .font(.system(size: 9, weight: .bold))
                                        .foregroundColor(ticket.status == "Open" ? .green : .gray)
                                }
                                Text(ticket.description)
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                                
                                ForEach(ticket.messages) { msg in
                                    HStack {
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(msg.sender?.name ?? "System Executive")
                                                .font(.system(size: 9, weight: .bold))
                                                .foregroundColor(.blue)
                                            Text(msg.message)
                                                .font(.system(size: 11))
                                                .foregroundColor(.textDark)
                                        }
                                        Spacer()
                                    }
                                    .padding(8)
                                    .background(Color.bgLight)
                                    .cornerRadius(8)
                                }
                                
                                // Reply block
                                HStack {
                                    TextField("Type reply...", text: $viewModel.ticketReplyMessage)
                                        .font(.system(size: 12))
                                    Button(action: {
                                        viewModel.replyToTicket(ticketId: ticket.id)
                                    }) {
                                        Image(systemName: "paperplane.fill")
                                            .foregroundColor(.blue)
                                    }
                                }
                                .padding(8)
                                .background(Color.bgInput)
                                .cornerRadius(8)
                            }
                            .padding(14)
                            .glassCard()
                        }
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 8. CUSTOMER ACCOUNT TAB
// ==========================================
struct CustomerAccountTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    let onSelectTab: (String) -> Void
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Account Settings")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(alignment: .leading, spacing: 12) {
                    Text("User Profile Information")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(.textDark)
                    
                    HStack {
                        Text("Name:")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textMuted)
                        Spacer()
                        Text(SessionManager.shared.getUserName())
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textDark)
                    }
                    
                    HStack {
                        Text("Email:")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textMuted)
                        Spacer()
                        Text(SessionManager.shared.getUserEmail())
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textDark)
                    }
                    
                    HStack {
                        Text("Role:")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textMuted)
                        Spacer()
                        Text(SessionManager.shared.getUserRole().capitalized)
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textDark)
                    }
                }
                .padding(16)
                .glassCard()
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
}
