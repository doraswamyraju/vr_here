import SwiftUI

struct CustomerHomeTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    let userName: String
    @Binding var searchQuery: String
    let onSelectTab: (String) -> Void
    let onOpenProject: (String) -> Void
    let onOpenLiveService: (String, String) -> Void
    let onLogout: () -> Void
    
    @State private var showNotifications = false
    @State private var promoBannerIndex = 0
    
    // Greeting based on time of day
    private var greetingTimeText: String {
        let hour = Calendar.current.component(.hour, from: Date())
        if hour < 12 { return "Good Morning" }
        if hour < 17 { return "Good Afternoon" }
        return "Good Evening"
    }
    
    private var activeOrders: [Order] {
        viewModel.orders.filter { $0.status.lowercased() != "completed" }
    }
    
    private var completedOrdersCount: Int {
        viewModel.orders.filter { $0.status.lowercased() == "completed" }.count
    }
    
    private var complianceScore: Int {
        let total = viewModel.orders.count
        if total == 0 { return 98 }
        let completed = completedOrdersCount
        let ratio = Double(completed) / Double(total)
        return min(100, max(85, Int(85 + (ratio * 15))))
    }
    
    var body: some View {
        ScrollView(showsIndicators: false) {
            VStack(alignment: .leading, spacing: 20) {
                
                // ==========================================
                // 1. EXECUTIVE HEADER & USER PROFILE
                // ==========================================
                VStack(spacing: 14) {
                    HStack(alignment: .center) {
                        // User Avatar with Gradient Ring
                        ZStack {
                            Circle()
                                .fill(
                                    LinearGradient(
                                        colors: [Color(red: 99/255, green: 102/255, blue: 241/255), Color(red: 168/255, green: 85/255, blue: 247/255)],
                                        startPoint: .topLeading,
                                        endPoint: .bottomTrailing
                                    )
                                )
                                .frame(width: 48, height: 48)
                            
                            Text(String(userName.prefix(1)).uppercased())
                                .font(.system(size: 20, weight: .black))
                                .foregroundColor(.white)
                        }
                        .shadow(color: Color(red: 99/255, green: 102/255, blue: 241/255).opacity(0.3), radius: 8, y: 3)
                        
                        VStack(alignment: .leading, spacing: 3) {
                            Text("\(greetingTimeText), \(userName)")
                                .font(.system(size: 18, weight: .black))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                .lineLimit(1)
                            
                            HStack(spacing: 6) {
                                Circle()
                                    .fill(Color(red: 16/255, green: 185/255, blue: 129/255))
                                    .frame(width: 6, height: 6)
                                Text("Verified Enterprise Member")
                                    .font(.system(size: 10.5, weight: .bold))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            }
                        }
                        
                        Spacer()
                        
                        // Header Actions (Notifications & Refresh)
                        HStack(spacing: 8) {
                            let unreadCount = viewModel.notifications.filter { !$0.isRead }.count
                            
                            Button(action: { showNotifications = true }) {
                                ZStack(alignment: .topTrailing) {
                                    Image(systemName: unreadCount > 0 ? "bell.badge.fill" : "bell.fill")
                                        .font(.system(size: 16, weight: .bold))
                                        .foregroundColor(Color(red: 30/255, green: 41/255, blue: 59/255))
                                        .frame(width: 40, height: 40)
                                        .background(Color.white)
                                        .cornerRadius(12)
                                        .shadow(color: Color.black.opacity(0.04), radius: 4, y: 2)
                                    
                                    if unreadCount > 0 {
                                        Circle()
                                            .fill(Color.red)
                                            .frame(width: 8, height: 8)
                                            .padding(.trailing, 8)
                                            .padding(.top, 8)
                                        }
                                }
                            }
                            .buttonStyle(PlainButtonStyle())
                            
                            Button(action: { viewModel.refreshAllData(silent: false) }) {
                                Image(systemName: "arrow.clockwise")
                                    .font(.system(size: 15, weight: .bold))
                                    .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                    .frame(width: 40, height: 40)
                                    .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                                    .cornerRadius(12)
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                    }
                    
                    // Quick Action Micro Pills
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            QuickActionChip(icon: "phone.fill", label: "₹499 CA Call", color: Color(red: 239/255, green: 68/255, blue: 68/255)) {
                                onOpenLiveService("Private Limited Consultation", "https://vrhere.in/pvt-ltd-registration")
                            }
                            QuickActionChip(icon: "archivebox.fill", label: "Doc Vault", color: Color(red: 99/255, green: 102/255, blue: 241/255)) {
                                onSelectTab("Vault")
                            }
                            QuickActionChip(icon: "doc.text.fill", label: "Invoices", color: Color(red: 16/255, green: 185/255, blue: 129/255)) {
                                onSelectTab("Invoices")
                            }
                            QuickActionChip(icon: "bubble.left.and.bubble.right.fill", label: "Helpdesk", color: Color(red: 245/255, green: 158/255, blue: 11/255)) {
                                onSelectTab("Support")
                            }
                        }
                        .padding(.horizontal, 2)
                    }
                }
                .padding(.horizontal, 20)
                .padding(.top, 10)
                
                // ==========================================
                // 2. CREATIVE GLOWING SEARCH CAPSULE
                // ==========================================
                VStack(alignment: .leading, spacing: 8) {
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
                                .frame(width: 34, height: 34)
                            Image(systemName: "magnifyingglass")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(.white)
                        }
                        
                        TextField("Search across all 106 services & licenses...", text: $searchQuery)
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        
                        if !searchQuery.isEmpty {
                            Button(action: {
                                searchQuery = ""
                                UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
                            }) {
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
                    
                    // Search Autocomplete Suggestions List
                    if !searchQuery.isEmpty {
                        VStack(alignment: .leading, spacing: 0) {
                            let matches = ServiceCatalog.shared.items.values.filter {
                                $0.title.lowercased().contains(searchQuery.lowercased())
                            }
                            
                            if matches.isEmpty {
                                Text("No services matched. Switching to catalog...")
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
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
                                                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                            Text(item.title)
                                                .font(.system(size: 13, weight: .bold))
                                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                            Spacer()
                                            Image(systemName: "chevron.right")
                                                .font(.caption2)
                                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                        }
                                        .padding(.horizontal, 14)
                                        .padding(.vertical, 12)
                                    }
                                    .buttonStyle(PlainButtonStyle())
                                    
                                    Divider().background(Color(red: 241/255, green: 245/255, blue: 249/255))
                                }
                            }
                        }
                        .background(Color.white)
                        .cornerRadius(12)
                        .shadow(color: Color.black.opacity(0.08), radius: 10, x: 0, y: 4)
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                        )
                    }
                }
                .padding(.horizontal, 20)
                
                // ==========================================
                // 3. STATUTORY HEALTH & COMPLIANCE PULSE WIDGET
                // ==========================================
                VStack(spacing: 0) {
                    ZStack {
                        // Sleek Dark Executive Gradient
                        LinearGradient(
                            colors: [Color(red: 15/255, green: 23/255, blue: 42/255), Color(red: 30/255, green: 41/255, blue: 59/255)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                        
                        VStack(spacing: 16) {
                            // Top Row: Compliance Ring + Title
                            HStack(alignment: .center, spacing: 14) {
                                ZStack {
                                    Circle()
                                        .stroke(Color.white.opacity(0.12), lineWidth: 5)
                                        .frame(width: 54, height: 54)
                                    
                                    Circle()
                                        .trim(from: 0.0, to: CGFloat(complianceScore) / 100.0)
                                        .stroke(
                                            LinearGradient(
                                                colors: [Color(red: 16/255, green: 185/255, blue: 129/255), Color(red: 52/255, green: 211/255, blue: 153/255)],
                                                startPoint: .topLeading,
                                                endPoint: .bottomTrailing
                                            ),
                                            style: StrokeStyle(lineWidth: 5, lineCap: .round)
                                        )
                                        .rotationEffect(.degrees(-90))
                                        .frame(width: 54, height: 54)
                                    
                                    Text("\(complianceScore)%")
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(.white)
                                }
                                
                                VStack(alignment: .leading, spacing: 3) {
                                    HStack(spacing: 6) {
                                        Text("STATUTORY HEALTH")
                                            .font(.system(size: 9.5, weight: .black))
                                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                            .tracking(0.8)
                                        
                                        Text("ACTIVE")
                                            .font(.system(size: 8, weight: .black))
                                            .foregroundColor(Color(red: 16/255, green: 185/255, blue: 129/255))
                                            .padding(.horizontal, 5)
                                            .padding(.vertical, 2)
                                            .background(Color(red: 16/255, green: 185/255, blue: 129/255).opacity(0.2))
                                            .cornerRadius(4)
                                    }
                                    
                                    Text("All ROC & Tax Filings Up-to-Date")
                                        .font(.system(size: 13.5, weight: .bold))
                                        .foregroundColor(.white)
                                    
                                    Text("Next statutory cycle: GSTR-3B & TDS due in 4 days")
                                        .font(.system(size: 10.5, weight: .medium))
                                        .foregroundColor(Color(red: 203/255, green: 213/255, blue: 225/255))
                                }
                                
                                Spacer()
                            }
                            
                            Divider()
                                .background(Color.white.opacity(0.12))
                            
                            // Bottom Stats Strip
                            HStack(spacing: 0) {
                                HealthStatItem(title: "Active Orders", value: "\(activeOrders.count)", icon: "hourglass.badge.plus", color: Color(red: 99/255, green: 102/255, blue: 241/255))
                                
                                Rectangle()
                                    .fill(Color.white.opacity(0.12))
                                    .frame(width: 1, height: 28)
                                
                                HealthStatItem(title: "Completed", value: "\(completedOrdersCount)", icon: "checkmark.seal.fill", color: Color(red: 16/255, green: 185/255, blue: 129/255))
                                
                                Rectangle()
                                    .fill(Color.white.opacity(0.12))
                                    .frame(width: 1, height: 28)
                                
                                HealthStatItem(title: "Assigned CA", value: "Available", icon: "person.badge.shield.checkmark.fill", color: Color(red: 245/255, green: 158/255, blue: 11/255))
                            }
                        }
                        .padding(18)
                    }
                    .cornerRadius(22)
                    .shadow(color: Color(red: 15/255, green: 23/255, blue: 42/255).opacity(0.18), radius: 12, y: 5)
                }
                .padding(.horizontal, 20)
                
                // ==========================================
                // 4. LIVE MILESTONE PIPELINE (ACTIVE ORDERS)
                // ==========================================
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("Active Projects & Filings")
                            .font(.system(size: 15, weight: .black))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        Spacer()
                        if !activeOrders.isEmpty {
                            Button(action: { onSelectTab("Orders") }) {
                                Text("View All (\(activeOrders.count))")
                                    .font(.system(size: 11.5, weight: .bold))
                                    .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                    
                    if activeOrders.isEmpty {
                        // Empty State / Launchpad Prompt Card
                        Button(action: { onSelectTab("Services") }) {
                            HStack(spacing: 14) {
                                ZStack {
                                    RoundedRectangle(cornerRadius: 14)
                                        .fill(Color(red: 238/255, green: 242/255, blue: 255/255))
                                        .frame(width: 48, height: 48)
                                    Image(systemName: "plus.app.fill")
                                        .font(.system(size: 24))
                                        .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                }
                                
                                VStack(alignment: .leading, spacing: 3) {
                                    Text("No Active Filings in Progress")
                                        .font(.system(size: 13.5, weight: .bold))
                                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                    Text("Incorporate a company, file GST, or register your brand today.")
                                        .font(.system(size: 11))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                        .lineLimit(1)
                                }
                                
                                Spacer()
                                
                                Image(systemName: "chevron.right")
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                            }
                            .padding(14)
                            .background(Color.white)
                            .cornerRadius(18)
                            .overlay(
                                RoundedRectangle(cornerRadius: 18)
                                    .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                            )
                            .shadow(color: Color.black.opacity(0.02), radius: 6, y: 2)
                        }
                        .buttonStyle(PlainButtonStyle())
                        .padding(.horizontal, 20)
                    } else {
                        // Horizontal Card Stepper
                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 14) {
                                ForEach(activeOrders) { order in
                                    Button(action: { onOpenProject(order.id) }) {
                                        VStack(alignment: .leading, spacing: 12) {
                                            HStack(alignment: .top) {
                                                VStack(alignment: .leading, spacing: 2) {
                                                    Text(order.serviceName)
                                                        .font(.system(size: 13.5, weight: .black))
                                                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                                        .lineLimit(1)
                                                    Text(order.packageName)
                                                        .font(.system(size: 11, weight: .semibold))
                                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                                }
                                                Spacer()
                                                
                                                Text(order.status)
                                                    .font(.system(size: 8.5, weight: .black))
                                                    .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                                    .padding(.horizontal, 7)
                                                    .padding(.vertical, 3)
                                                    .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                                                    .cornerRadius(6)
                                            }
                                            
                                            let completedTasks = order.tasks.filter { $0.status == "Completed" }.count
                                            let totalTasks = max(1, order.tasks.count)
                                            let progress = Double(completedTasks) / Double(totalTasks)
                                            
                                            VStack(alignment: .leading, spacing: 6) {
                                                HStack {
                                                    Text("Milestone: \(completedTasks)/\(totalTasks) Completed")
                                                        .font(.system(size: 10, weight: .bold))
                                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                                    Spacer()
                                                    Text("\(Int(progress * 100))%")
                                                        .font(.system(size: 10, weight: .black))
                                                        .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                                }
                                                
                                                ZStack(alignment: .leading) {
                                                    RoundedRectangle(cornerRadius: 4)
                                                        .fill(Color(red: 241/255, green: 245/255, blue: 249/255))
                                                        .frame(height: 6)
                                                    RoundedRectangle(cornerRadius: 4)
                                                        .fill(
                                                            LinearGradient(
                                                                colors: [Color(red: 99/255, green: 102/255, blue: 241/255), Color(red: 168/255, green: 85/255, blue: 247/255)],
                                                                startPoint: .leading,
                                                                endPoint: .trailing
                                                            )
                                                        )
                                                        .frame(width: max(10, 220 * CGFloat(progress)), height: 6)
                                                }
                                            }
                                        }
                                        .frame(width: 230)
                                        .padding(14)
                                        .background(Color.white)
                                        .cornerRadius(18)
                                        .overlay(
                                            RoundedRectangle(cornerRadius: 18)
                                                .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                                        )
                                        .shadow(color: Color.black.opacity(0.02), radius: 4, y: 2)
                                    }
                                    .buttonStyle(PlainButtonStyle())
                                }
                            }
                            .padding(.horizontal, 20)
                        }
                    }
                }
                
                // ==========================================
                // 5. 8-PILLARS QUICK SERVICE MATRIX
                // ==========================================
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("Core Legal & Business Services")
                            .font(.system(size: 15, weight: .black))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        Spacer()
                        Button(action: { onSelectTab("Services") }) {
                            Text("See All 106 →")
                                .font(.system(size: 11.5, weight: .bold))
                                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                        }
                    }
                    .padding(.horizontal, 20)
                    
                    LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)], spacing: 12) {
                        ServiceMatrixCard(
                            title: "Incorporate Company",
                            subtitle: "Pvt Ltd, LLP, OPC",
                            price: "From ₹4,899",
                            icon: "building.2.fill",
                            color: Color(red: 99/255, green: 102/255, blue: 241/255)
                        ) {
                            onOpenLiveService("Private Limited Company", "https://vrhere.in/pvt-ltd-registration")
                        }
                        
                        ServiceMatrixCard(
                            title: "GST & Tax Filing",
                            subtitle: "GSTR-1, 3B & ITR",
                            price: "From ₹499/mo",
                            icon: "percent",
                            color: Color(red: 16/255, green: 185/255, blue: 129/255)
                        ) {
                            onOpenLiveService("GST Registration", "https://vrhere.in/gst-registration")
                        }
                        
                        ServiceMatrixCard(
                            title: "Trademark & IP",
                            subtitle: "Brand TM in 24 Hrs",
                            price: "From ₹1,999",
                            icon: "shield.righthalf.filled",
                            color: Color(red: 236/255, green: 72/255, blue: 153/255)
                        ) {
                            onOpenLiveService("Trademark Registration", "https://vrhere.in/trademark-registration")
                        }
                        
                        ServiceMatrixCard(
                            title: "ISO Certification",
                            subtitle: "9001, 14001, 27001",
                            price: "From ₹3,499",
                            icon: "rosette",
                            color: Color(red: 245/255, green: 158/255, blue: 11/255)
                        ) {
                            onOpenLiveService("ISO 9001 Certification", "https://vrhere.in/iso-9001-certification")
                        }
                        
                        ServiceMatrixCard(
                            title: "FSSAI & Licenses",
                            subtitle: "Food, IEC, Trade, PT",
                            price: "From ₹1,499",
                            icon: "fork.knife",
                            color: Color(red: 14/255, green: 165/255, blue: 233/255)
                        ) {
                            onOpenLiveService("FSSAI License", "https://vrhere.in/fssai-license")
                        }
                        
                        ServiceMatrixCard(
                            title: "CMA & Bank Loans",
                            subtitle: "DPR, CC/OD, PMEGP",
                            price: "From ₹4,999",
                            icon: "chart.line.uptrend.xyaxis",
                            color: Color(red: 168/255, green: 85/255, blue: 247/255)
                        ) {
                            onOpenLiveService("CMA Data Preparation", "https://vrhere.in/cma-data-preparation")
                        }
                        
                        ServiceMatrixCard(
                            title: "Annual ROC Filings",
                            subtitle: "DIR-3 KYC, AOC-4",
                            price: "From ₹499",
                            icon: "doc.badge.gearshape.fill",
                            color: Color(red: 100/255, green: 116/255, blue: 139/255)
                        ) {
                            onOpenLiveService("ROC Annual Filings", "https://vrhere.in/roc-annual-filings")
                        }
                        
                        ServiceMatrixCard(
                            title: "₹499 CA/CS Advice",
                            subtitle: "Adjusted against fee",
                            price: "Instant Booking",
                            icon: "phone.badge.checkmark.fill",
                            color: Color(red: 239/255, green: 68/255, blue: 68/255)
                        ) {
                            onOpenLiveService("Private Limited Consultation", "https://vrhere.in/pvt-ltd-registration")
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                // ==========================================
                // 6. PROMOTIONAL CAROUSEL & GOVT SCHEMES
                // ==========================================
                VStack(alignment: .leading, spacing: 12) {
                    Text("Featured Schemes & Incentives")
                        .font(.system(size: 15, weight: .black))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .padding(.horizontal, 20)
                    
                    TabView(selection: $promoBannerIndex) {
                        PromoBannerCard(
                            tag: "MCA IMMUNITY SCHEME",
                            title: "Companies Compliance Scheme (CCFS 2026)",
                            desc: "Regularize pending ROC filings with up to 40% fee waiver and avoid strike-off notices.",
                            btnText: "File Under CCFS",
                            gradient: [Color(red: 79/255, green: 70/255, blue: 229/255), Color(red: 124/255, green: 58/255, blue: 237/255)]
                        ) {
                            onOpenLiveService("Companies Compliance Scheme 2026", "https://vrhere.in/compliance-scheme-2026")
                        }
                        .tag(0)
                        
                        PromoBannerCard(
                            tag: "STARTUP INDIA DPIIT",
                            title: "3-Year 100% Tax Exemption (Sec 80-IAC)",
                            desc: "Fast-track DPIIT certificate, angel tax relief, and priority access to Govt tenders.",
                            btnText: "Apply for DPIIT",
                            gradient: [Color(red: 225/255, green: 29/255, blue: 72/255), Color(red: 244/255, green: 63/255, blue: 94/255)]
                        ) {
                            onOpenLiveService("Startup India Registration", "https://vrhere.in/startup-india-registration")
                        }
                        .tag(1)
                        
                        PromoBannerCard(
                            tag: "INTELLECTUAL PROPERTY",
                            title: "Instant Trademark TM Application in 24 Hrs",
                            desc: "Safeguard your brand name and logo legally before someone else claims it.",
                            btnText: "Secure Brand TM",
                            gradient: [Color(red: 13/255, green: 148/255, blue: 136/255), Color(red: 20/255, green: 184/255, blue: 166/255)]
                        ) {
                            onOpenLiveService("Trademark Registration", "https://vrhere.in/trademark-registration")
                        }
                        .tag(2)
                    }
                    .tabViewStyle(PageTabViewStyle(indexDisplayMode: .automatic))
                    .frame(height: 165)
                    .padding(.horizontal, 20)
                }
                
                // ==========================================
                // 7. ATTENTION NEEDED (ACTIONABLE TASKS)
                // ==========================================
                let pendingReqs = viewModel.orders.flatMap { $0.customerRequirements }.filter { $0.status.lowercased() != "verified" }
                VStack(alignment: .leading, spacing: 12) {
                    Text("Action Items & Checklist")
                        .font(.system(size: 15, weight: .black))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .padding(.horizontal, 20)
                    
                    if pendingReqs.isEmpty {
                        HStack(spacing: 12) {
                            Image(systemName: "checkmark.seal.fill")
                                .font(.system(size: 22))
                                .foregroundColor(Color(red: 16/255, green: 185/255, blue: 129/255))
                            
                            VStack(alignment: .leading, spacing: 2) {
                                Text("All Action Items Complete")
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                Text("No pending document uploads or pending invoice payments.")
                                    .font(.system(size: 11))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            }
                            Spacer()
                        }
                        .padding(14)
                        .background(Color(red: 16/255, green: 185/255, blue: 129/255).opacity(0.08))
                        .cornerRadius(16)
                        .overlay(
                            RoundedRectangle(cornerRadius: 16)
                                .stroke(Color(red: 16/255, green: 185/255, blue: 129/255).opacity(0.2), lineWidth: 1)
                        )
                        .padding(.horizontal, 20)
                    } else {
                        VStack(spacing: 10) {
                            ForEach(Array(pendingReqs.prefix(2))) { req in
                                Button(action: { onSelectTab("Orders") }) {
                                    HStack(spacing: 12) {
                                        Image(systemName: "exclamationmark.circle.fill")
                                            .font(.system(size: 20))
                                            .foregroundColor(Color(red: 245/255, green: 158/255, blue: 11/255))
                                        
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(req.title)
                                                .font(.system(size: 13, weight: .bold))
                                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                            Text(req.description)
                                                .font(.system(size: 11))
                                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                                .lineLimit(1)
                                        }
                                        
                                        Spacer()
                                        
                                        Text("Upload")
                                            .font(.system(size: 10.5, weight: .black))
                                            .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                            .padding(.horizontal, 10)
                                            .padding(.vertical, 5)
                                            .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                                            .cornerRadius(8)
                                    }
                                    .padding(14)
                                    .background(Color.white)
                                    .cornerRadius(16)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 16)
                                            .stroke(Color(red: 245/255, green: 158/255, blue: 11/255).opacity(0.3), lineWidth: 1)
                                    )
                                    .shadow(color: Color.black.opacity(0.02), radius: 4, y: 2)
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                        .padding(.horizontal, 20)
                    }
                }
                
                // ==========================================
                // 8. REGULATORY & COMPLIANCE FEED
                // ==========================================
                VStack(alignment: .leading, spacing: 12) {
                    Text("Statutory & Compliance News")
                        .font(.system(size: 15, weight: .black))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .padding(.horizontal, 20)
                    
                    VStack(spacing: 10) {
                        NewsFeedCard(
                            tag: "MCA UPDATE",
                            title: "Annual ROC Return Filing Timelines (AOC-4 & MGT-7)",
                            desc: "Ensure board resolution approval before statutory cutoff to avoid ₹100/day penalties.",
                            time: "Updated Today"
                        )
                        NewsFeedCard(
                            tag: "GST NOTIFICATION",
                            title: "Mandatory E-Invoicing Thresholds for Commercial Entities",
                            desc: "B2B transactions must be validated via IRP portal. Connect with our tax desk for automated sync.",
                            time: "Yesterday"
                        )
                        NewsFeedCard(
                            tag: "MSME SUBSIDY",
                            title: "PMEGP & ZED Scheme 35% Capital Subsidy Portal Open",
                            desc: "Manufacturing and service units can claim capital reimbursement on verified machinery.",
                            time: "3 days ago"
                        )
                    }
                    .padding(.horizontal, 20)
                }
                
                // Extra clearance so content scrolls cleanly above the floating bottom dock
                Spacer().frame(height: 120)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
        .sheet(isPresented: $showNotifications) {
            NavigationView {
                ScrollView {
                    VStack(spacing: 12) {
                        if viewModel.notifications.isEmpty {
                            VStack(spacing: 8) {
                                Text("No notifications available.")
                                    .font(.system(size: 13))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
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
                                                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
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
                                                .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                                                .cornerRadius(4)
                                        }
                                        
                                        Text(notification.title)
                                            .font(.system(size: 13, weight: .black))
                                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                            .multilineTextAlignment(.leading)
                                        
                                        Text(notification.message)
                                            .font(.system(size: 11))
                                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                            .lineSpacing(3)
                                            .multilineTextAlignment(.leading)
                                    }
                                    .padding(14)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(notification.isRead ? Color(red: 248/255, green: 250/255, blue: 252/255) : Color.white)
                                    .cornerRadius(16)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 16)
                                            .stroke(notification.isRead ? Color(red: 226/255, green: 232/255, blue: 240/255) : Color(red: 99/255, green: 102/255, blue: 241/255).opacity(0.25), lineWidth: 1)
                                    )
                                    .shadow(color: Color.black.opacity(0.02), radius: 4, x: 0, y: 2)
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                    }
                    .padding(20)
                }
                .background(Color(red: 248/255, green: 250/255, blue: 252/255).ignoresSafeArea())
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
// SUBCOMPONENTS
// ==========================================

struct QuickActionChip: View {
    let icon: String
    let label: String
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: {
            let impact = UIImpactFeedbackGenerator(style: .light)
            impact.impactOccurred()
            action()
        }) {
            HStack(spacing: 5) {
                Image(systemName: icon)
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(color)
                Text(label)
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background(Color.white)
            .cornerRadius(14)
            .overlay(
                RoundedRectangle(cornerRadius: 14)
                    .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
            )
            .shadow(color: Color.black.opacity(0.02), radius: 3, y: 1)
        }
        .buttonStyle(PlainButtonStyle())
    }
}

struct HealthStatItem: View {
    let title: String
    let value: String
    let icon: String
    let color: Color
    
    var body: some View {
        VStack(spacing: 3) {
            HStack(spacing: 4) {
                Image(systemName: icon)
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(color)
                Text(title)
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
            }
            Text(value)
                .font(.system(size: 13, weight: .black))
                .foregroundColor(.white)
        }
        .frame(maxWidth: .infinity)
    }
}

struct ServiceMatrixCard: View {
    let title: String
    let subtitle: String
    let price: String
    let icon: String
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: {
            let impact = UIImpactFeedbackGenerator(style: .medium)
            impact.impactOccurred()
            action()
        }) {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    ZStack {
                        RoundedRectangle(cornerRadius: 12)
                            .fill(color.opacity(0.12))
                            .frame(width: 38, height: 38)
                        Image(systemName: icon)
                            .font(.system(size: 16, weight: .bold))
                            .foregroundColor(color)
                    }
                    Spacer()
                    Image(systemName: "arrow.up.forward")
                        .font(.system(size: 10, weight: .black))
                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                }
                
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.system(size: 12.5, weight: .bold))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .lineLimit(1)
                    Text(subtitle)
                        .font(.system(size: 10, weight: .medium))
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        .lineLimit(1)
                }
                
                Text(price)
                    .font(.system(size: 10.5, weight: .black))
                    .foregroundColor(color)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(color.opacity(0.08))
                    .cornerRadius(6)
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

struct PromoBannerCard: View {
    let tag: String
    let title: String
    let desc: String
    let btnText: String
    let gradient: [Color]
    let action: () -> Void
    
    var body: some View {
        ZStack {
            LinearGradient(colors: gradient, startPoint: .topLeading, endPoint: .bottomTrailing)
            
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(tag)
                        .font(.system(size: 8.5, weight: .black))
                        .foregroundColor(.white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 3)
                        .background(Color.white.opacity(0.25))
                        .cornerRadius(4)
                    Spacer()
                }
                
                Text(title)
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(.white)
                    .lineLimit(1)
                
                Text(desc)
                    .font(.system(size: 10.5, weight: .medium))
                    .foregroundColor(Color.white.opacity(0.9))
                    .lineLimit(2)
                    .lineSpacing(2)
                
                Spacer()
                
                Button(action: action) {
                    HStack(spacing: 4) {
                        Text(btnText)
                            .font(.system(size: 10.5, weight: .black))
                        Image(systemName: "arrow.right")
                            .font(.system(size: 9, weight: .bold))
                    }
                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Color.white)
                    .cornerRadius(8)
                }
                .buttonStyle(PlainButtonStyle())
            }
            .padding(14)
        }
        .cornerRadius(18)
        .shadow(color: gradient.first?.opacity(0.3) ?? Color.clear, radius: 8, y: 4)
    }
}

struct NewsFeedCard: View {
    let tag: String
    let title: String
    let desc: String
    let time: String
    
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(tag)
                    .font(.system(size: 8.5, weight: .black))
                    .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                    .cornerRadius(4)
                
                Spacer()
                
                Text(time)
                    .font(.system(size: 9.5, weight: .medium))
                    .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
            }
            
            Text(title)
                .font(.system(size: 12.5, weight: .bold))
                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
            
            Text(desc)
                .font(.system(size: 11))
                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                .lineLimit(2)
        }
        .padding(12)
        .background(Color.white)
        .cornerRadius(16)
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
        )
        .shadow(color: Color.black.opacity(0.02), radius: 3, y: 1)
    }
}
