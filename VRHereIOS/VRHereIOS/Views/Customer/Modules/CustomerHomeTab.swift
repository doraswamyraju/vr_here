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
    
    // Display name formatted cleanly
    private var cleanDisplayName: String {
        let trimmed = userName.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return "Entrepreneur" }
        let components = trimmed.components(separatedBy: " ")
        if let first = components.first, !first.isEmpty {
            return first
        }
        return trimmed
    }
    
    private var activeOrders: [Order] {
        viewModel.orders.filter { $0.status.lowercased() != "completed" }
    }
    
    private var completedOrdersCount: Int {
        viewModel.orders.filter { $0.status.lowercased() == "completed" }.count
    }
    
    private var pendingRequirements: [CustomerRequirement] {
        viewModel.orders.flatMap { $0.customerRequirements }.filter { $0.status.lowercased() != "verified" }
    }
    
    private var hasPendingDocuments: Bool {
        !pendingRequirements.isEmpty || activeOrders.contains(where: {
            let s = $0.status.lowercased()
            return s.contains("pending") || s.contains("document") || s.contains("awaiting")
        })
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
            VStack(alignment: .leading, spacing: 18) {
                
                // ==========================================
                // 1. EXECUTIVE USER GREETING & QUICK ACCESS
                // ==========================================
                VStack(spacing: 12) {
                    HStack(alignment: .center, spacing: 12) {
                        // User Avatar with Gradient Ring & Initials
                        ZStack {
                            Circle()
                                .fill(
                                    LinearGradient(
                                        colors: [Color(red: 99/255, green: 102/255, blue: 241/255), Color(red: 168/255, green: 85/255, blue: 247/255)],
                                        startPoint: .topLeading,
                                        endPoint: .bottomTrailing
                                    )
                                )
                                .frame(width: 44, height: 44)
                            
                            Text(String(cleanDisplayName.prefix(1)).uppercased())
                                .font(.system(size: 18, weight: .black))
                                .foregroundColor(.white)
                        }
                        .shadow(color: Color(red: 99/255, green: 102/255, blue: 241/255).opacity(0.25), radius: 6, y: 2)
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(greetingTimeText), \(cleanDisplayName)")
                                .font(.system(size: 17, weight: .black))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                .lineLimit(1)
                            
                            HStack(spacing: 5) {
                                Circle()
                                    .fill(Color(red: 16/255, green: 185/255, blue: 129/255))
                                    .frame(width: 6, height: 6)
                                Text("Verified Enterprise Member")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            }
                        }
                        
                        Spacer()
                        
                        // 1-Tap Refresh Button
                        Button(action: {
                            let impact = UIImpactFeedbackGenerator(style: .light)
                            impact.impactOccurred()
                            viewModel.refreshAllData(silent: false)
                        }) {
                            HStack(spacing: 4) {
                                Image(systemName: "arrow.clockwise")
                                    .font(.system(size: 11, weight: .bold))
                                Text("Sync")
                                    .font(.system(size: 10, weight: .bold))
                            }
                            .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                            .cornerRadius(12)
                        }
                        .buttonStyle(PlainButtonStyle())
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
                .padding(.top, 4)
                
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
                    
                    // Autocomplete Suggestions
                    if !searchQuery.isEmpty {
                        VStack(alignment: .leading, spacing: 0) {
                            let matches = ServiceCatalog.shared.items.values.filter {
                                $0.title.lowercased().contains(searchQuery.lowercased())
                            }
                            
                            if matches.isEmpty {
                                Text("No services matched. Tap below to see all 106 services.")
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
                // 3. HIGH-ATTENTION ACTION ITEMS BANNER (PROMOTED TO TOP)
                // ==========================================
                if hasPendingDocuments {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 6) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(Color(red: 239/255, green: 68/255, blue: 68/255))
                            Text("ACTION REQUIRED")
                                .font(.system(size: 10, weight: .black))
                                .foregroundColor(Color(red: 239/255, green: 68/255, blue: 68/255))
                                .tracking(0.6)
                            Spacer()
                        }
                        
                        let firstOrderWithPending = activeOrders.first(where: {
                            $0.status.lowercased().contains("pending") || $0.status.lowercased().contains("document")
                        }) ?? activeOrders.first
                        
                        let orderIdToOpen = firstOrderWithPending?.id ?? ""
                        let orderTitle = firstOrderWithPending?.serviceName ?? "Active Service"
                        
                        Button(action: {
                            let impact = UIImpactFeedbackGenerator(style: .medium)
                            impact.impactOccurred()
                            if !orderIdToOpen.isEmpty {
                                onOpenProject(orderIdToOpen)
                            } else {
                                onSelectTab("Orders")
                            }
                        }) {
                            HStack(spacing: 12) {
                                ZStack {
                                    RoundedRectangle(cornerRadius: 12)
                                        .fill(Color(red: 239/255, green: 68/255, blue: 68/255).opacity(0.15))
                                        .frame(width: 44, height: 44)
                                    Image(systemName: "doc.badge.plus")
                                        .font(.system(size: 20, weight: .bold))
                                        .foregroundColor(Color(red: 239/255, green: 68/255, blue: 68/255))
                                }
                                
                                VStack(alignment: .leading, spacing: 3) {
                                    Text("Upload Pending Documents for \(orderTitle)")
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                        .lineLimit(1)
                                    Text("KYC/Identity verification is required to submit government filing.")
                                        .font(.system(size: 10.5, weight: .medium))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                        .lineLimit(1)
                                }
                                
                                Spacer()
                                
                                HStack(spacing: 4) {
                                    Text("Upload")
                                        .font(.system(size: 11, weight: .black))
                                    Image(systemName: "arrow.right")
                                        .font(.system(size: 10, weight: .bold))
                                }
                                .foregroundColor(.white)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 7)
                                .background(
                                    LinearGradient(
                                        colors: [Color(red: 239/255, green: 68/255, blue: 68/255), Color(red: 220/255, green: 38/255, blue: 38/255)],
                                        startPoint: .topLeading,
                                        endPoint: .bottomTrailing
                                    )
                                )
                                .cornerRadius(10)
                                .shadow(color: Color(red: 239/255, green: 68/255, blue: 68/255).opacity(0.35), radius: 4, y: 2)
                            }
                            .padding(12)
                            .background(
                                LinearGradient(
                                    colors: [Color(red: 254/255, green: 242/255, blue: 242/255), Color.white],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                )
                            )
                            .cornerRadius(16)
                            .overlay(
                                RoundedRectangle(cornerRadius: 16)
                                    .stroke(Color(red: 252/255, green: 165/255, blue: 165/255), lineWidth: 1.2)
                            )
                            .shadow(color: Color(red: 239/255, green: 68/255, blue: 68/255).opacity(0.08), radius: 6, y: 2)
                        }
                        .buttonStyle(PlainButtonStyle())
                    }
                    .padding(.horizontal, 20)
                }
                
                // ==========================================
                // 4. STATUTORY HEALTH & COMPLIANCE PULSE
                // ==========================================
                VStack(spacing: 0) {
                    ZStack {
                        LinearGradient(
                            colors: [Color(red: 15/255, green: 23/255, blue: 42/255), Color(red: 30/255, green: 41/255, blue: 59/255)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                        
                        VStack(spacing: 14) {
                            HStack(alignment: .center, spacing: 14) {
                                ZStack {
                                    Circle()
                                        .stroke(Color.white.opacity(0.12), lineWidth: 5)
                                        .frame(width: 50, height: 50)
                                    
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
                                        .frame(width: 50, height: 50)
                                    
                                    Text("\(complianceScore)%")
                                        .font(.system(size: 12.5, weight: .black))
                                        .foregroundColor(.white)
                                }
                                
                                VStack(alignment: .leading, spacing: 3) {
                                    HStack(spacing: 6) {
                                        Text("STATUTORY COMPLIANCE")
                                            .font(.system(size: 9, weight: .black))
                                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                            .tracking(0.8)
                                        
                                        Text("ACTIVE")
                                            .font(.system(size: 7.5, weight: .black))
                                            .foregroundColor(Color(red: 16/255, green: 185/255, blue: 129/255))
                                            .padding(.horizontal, 5)
                                            .padding(.vertical, 2)
                                            .background(Color(red: 16/255, green: 185/255, blue: 129/255).opacity(0.2))
                                            .cornerRadius(4)
                                    }
                                    
                                    Text("Corporate & Tax Portfolio In Good Standing")
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.white)
                                    
                                    Text("Next deadline: GSTR-3B & TDS cycle in 4 days")
                                        .font(.system(size: 10, weight: .medium))
                                        .foregroundColor(Color(red: 203/255, green: 213/255, blue: 225/255))
                                }
                                
                                Spacer()
                            }
                            
                            Divider()
                                .background(Color.white.opacity(0.12))
                            
                            HStack(spacing: 0) {
                                HealthStatItem(title: "Active Filings", value: "\(activeOrders.count)", icon: "hourglass.badge.plus", color: Color(red: 99/255, green: 102/255, blue: 241/255))
                                
                                Rectangle()
                                    .fill(Color.white.opacity(0.12))
                                    .frame(width: 1, height: 26)
                                
                                HealthStatItem(title: "Completed", value: "\(completedOrdersCount)", icon: "checkmark.seal.fill", color: Color(red: 16/255, green: 185/255, blue: 129/255))
                                
                                Rectangle()
                                    .fill(Color.white.opacity(0.12))
                                    .frame(width: 1, height: 26)
                                
                                HealthStatItem(title: "Assigned CA", value: "Verified Desk", icon: "person.badge.shield.checkmark.fill", color: Color(red: 245/255, green: 158/255, blue: 11/255))
                            }
                        }
                        .padding(16)
                    }
                    .cornerRadius(20)
                    .shadow(color: Color(red: 15/255, green: 23/255, blue: 42/255).opacity(0.12), radius: 10, y: 4)
                }
                .padding(.horizontal, 20)
                
                // ==========================================
                // 5. HIGH-IMPACT ACTIVE PROJECT HERO TRACKER
                // ==========================================
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        HStack(spacing: 6) {
                            Text("Active Projects & Filings")
                                .font(.system(size: 15, weight: .black))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                            
                            if !activeOrders.isEmpty {
                                Text("\(activeOrders.count)")
                                    .font(.system(size: 10, weight: .black))
                                    .foregroundColor(.white)
                                    .padding(.horizontal, 7)
                                    .padding(.vertical, 2)
                                    .background(Color(red: 99/255, green: 102/255, blue: 241/255))
                                    .cornerRadius(10)
                            }
                        }
                        
                        Spacer()
                        
                        Button(action: { onSelectTab("Orders") }) {
                            Text("All Orders →")
                                .font(.system(size: 11.5, weight: .bold))
                                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
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
                                        .frame(width: 46, height: 46)
                                    Image(systemName: "plus.app.fill")
                                        .font(.system(size: 22))
                                        .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                }
                                
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("Launch Your Next Business Entity")
                                        .font(.system(size: 13.5, weight: .bold))
                                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                    Text("Incorporate Private Limited, Register GST, or Trademark in 1-Click.")
                                        .font(.system(size: 10.5))
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
                        // High-Impact Highlighted Tracker Cards
                        VStack(spacing: 12) {
                            ForEach(activeOrders) { order in
                                HighlightedOrderTrackerCard(
                                    order: order,
                                    onTap: { onOpenProject(order.id) },
                                    onChatCA: {
                                        onSelectTab("Support")
                                    }
                                )
                            }
                        }
                        .padding(.horizontal, 20)
                    }
                }
                
                // ==========================================
                // 6. CREATIVE 8-PILLARS CORE SERVICES MATRIX
                // ==========================================
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Core Legal & Business Services")
                                .font(.system(size: 15, weight: .black))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                            Text("Verified government registration & compliance packages")
                                .font(.system(size: 10.5, weight: .medium))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        }
                        Spacer()
                        Button(action: { onSelectTab("Services") }) {
                            Text("See All 106 →")
                                .font(.system(size: 11.5, weight: .black))
                                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                        }
                    }
                    .padding(.horizontal, 20)
                    
                    LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)], spacing: 12) {
                        CreativeServiceCard(
                            title: "Incorporate Company",
                            subtitle: "Pvt Ltd, LLP, OPC",
                            tag: "MCA Verified",
                            price: "₹4,899",
                            icon: "building.2.crop.circle.fill",
                            themeColor: Color(red: 99/255, green: 102/255, blue: 241/255),
                            bgGradient: [Color(red: 238/255, green: 242/255, blue: 255/255), Color.white]
                        ) {
                            onOpenLiveService("Private Limited Company", "https://vrhere.in/pvt-ltd-registration")
                        }
                        
                        CreativeServiceCard(
                            title: "GST & Tax Filing",
                            subtitle: "GSTR-1, 3B & ITR",
                            tag: "Zero Penalty",
                            price: "₹499/mo",
                            icon: "percent",
                            themeColor: Color(red: 16/255, green: 185/255, blue: 129/255),
                            bgGradient: [Color(red: 236/255, green: 253/255, blue: 245/255), Color.white]
                        ) {
                            onOpenLiveService("GST Registration", "https://vrhere.in/gst-registration")
                        }
                        
                        CreativeServiceCard(
                            title: "Trademark & Brand",
                            subtitle: "Instant ™ in 24 Hrs",
                            tag: "IP India",
                            price: "₹1,999",
                            icon: "shield.lefthalf.filled",
                            themeColor: Color(red: 236/255, green: 72/255, blue: 153/255),
                            bgGradient: [Color(red: 253/255, green: 242/255, blue: 248/255), Color.white]
                        ) {
                            onOpenLiveService("Trademark Registration", "https://vrhere.in/trademark-registration")
                        }
                        
                        CreativeServiceCard(
                            title: "ISO Certification",
                            subtitle: "9001, 14001, 27001",
                            tag: "IAF Global",
                            price: "₹3,499",
                            icon: "rosette",
                            themeColor: Color(red: 245/255, green: 158/255, blue: 11/255),
                            bgGradient: [Color(red: 254/255, green: 243/255, blue: 199/255).opacity(0.6), Color.white]
                        ) {
                            onOpenLiveService("ISO 9001 Certification", "https://vrhere.in/iso-9001-certification")
                        }
                        
                        CreativeServiceCard(
                            title: "FSSAI & Licenses",
                            subtitle: "Food, IEC, Trade, PT",
                            tag: "FoSCoS Govt",
                            price: "₹1,499",
                            icon: "fork.knife",
                            themeColor: Color(red: 14/255, green: 165/255, blue: 233/255),
                            bgGradient: [Color(red: 240/255, green: 249/255, blue: 255/255), Color.white]
                        ) {
                            onOpenLiveService("FSSAI License", "https://vrhere.in/fssai-license")
                        }
                        
                        CreativeServiceCard(
                            title: "CMA & Bank Loans",
                            subtitle: "DPR, CC/OD, PMEGP",
                            tag: "Bank Ready",
                            price: "₹4,999",
                            icon: "chart.line.uptrend.xyaxis",
                            themeColor: Color(red: 168/255, green: 85/255, blue: 247/255),
                            bgGradient: [Color(red: 250/255, green: 245/255, blue: 255/255), Color.white]
                        ) {
                            onOpenLiveService("CMA Data Preparation", "https://vrhere.in/cma-data-preparation")
                        }
                        
                        CreativeServiceCard(
                            title: "Annual ROC Filings",
                            subtitle: "DIR-3 KYC, AOC-4",
                            tag: "MCA V3",
                            price: "₹499",
                            icon: "doc.badge.gearshape.fill",
                            themeColor: Color(red: 100/255, green: 116/255, blue: 139/255),
                            bgGradient: [Color(red: 241/255, green: 245/255, blue: 249/255), Color.white]
                        ) {
                            onOpenLiveService("ROC Annual Filings", "https://vrhere.in/roc-annual-filings")
                        }
                        
                        CreativeServiceCard(
                            title: "₹499 CA/CS Advice",
                            subtitle: "Fee credited on order",
                            tag: "Live CA Call",
                            price: "₹499",
                            icon: "phone.badge.checkmark.fill",
                            themeColor: Color(red: 239/255, green: 68/255, blue: 68/255),
                            bgGradient: [Color(red: 254/255, green: 242/255, blue: 242/255), Color.white]
                        ) {
                            onOpenLiveService("Private Limited Consultation", "https://vrhere.in/pvt-ltd-registration")
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                // ==========================================
                // 7. PROMOTIONAL CAROUSEL & GOVT SCHEMES
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
                // 8. STATUTORY & COMPLIANCE FEED
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
                    .font(.system(size: 9.5, weight: .semibold))
                    .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
            }
            Text(value)
                .font(.system(size: 12.5, weight: .black))
                .foregroundColor(.white)
        }
        .frame(maxWidth: .infinity)
    }
}

// Highly Prominent, Elevated Active Order Tracker Card
struct HighlightedOrderTrackerCard: View {
    let order: Order
    let onTap: () -> Void
    let onChatCA: () -> Void
    
    private var isPendingAction: Bool {
        let s = order.status.lowercased()
        return s.contains("pending") || s.contains("document") || s.contains("awaiting")
    }
    
    private var statusBadgeColor: Color {
        if isPendingAction { return Color(red: 239/255, green: 68/255, blue: 68/255) }
        return Color(red: 79/255, green: 70/255, blue: 229/255)
    }
    
    private var statusBadgeBg: Color {
        if isPendingAction { return Color(red: 254/255, green: 242/255, blue: 242/255) }
        return Color(red: 238/255, green: 242/255, blue: 255/255)
    }
    
    var body: some View {
        Button(action: {
            let impact = UIImpactFeedbackGenerator(style: .medium)
            impact.impactOccurred()
            onTap()
        }) {
            VStack(alignment: .leading, spacing: 14) {
                // Top Row: Service Name & Status Badge
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Circle()
                                .fill(isPendingAction ? Color(red: 239/255, green: 68/255, blue: 68/255) : Color(red: 16/255, green: 185/255, blue: 129/255))
                                .frame(width: 7, height: 7)
                            Text("ORDER ID: \(order.id.prefix(8).uppercased())")
                                .font(.system(size: 9.5, weight: .black))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                .tracking(0.5)
                        }
                        
                        Text(order.serviceName)
                            .font(.system(size: 15, weight: .black))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                            .lineLimit(1)
                    }
                    
                    Spacer()
                    
                    Text(order.status)
                        .font(.system(size: 9, weight: .black))
                        .foregroundColor(statusBadgeColor)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(statusBadgeBg)
                        .cornerRadius(8)
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(statusBadgeColor.opacity(0.2), lineWidth: 1)
                        )
                }
                
                // 4-Stage Segmented Visual Stepper
                let completedTasks = order.tasks.filter { $0.status == "Completed" }.count
                let totalTasks = max(1, order.tasks.count)
                let progress = Double(completedTasks) / Double(totalTasks)
                let progressPct = Int(progress * 100)
                
                VStack(spacing: 8) {
                    HStack(spacing: 4) {
                        ForEach(0..<4) { index in
                            let isCompleted = progress >= (Double(index + 1) / 4.0)
                            let isCurrent = !isCompleted && (progress >= (Double(index) / 4.0) || index == 0)
                            
                            RoundedRectangle(cornerRadius: 3)
                                .fill(
                                    isCompleted
                                        ? Color(red: 16/255, green: 185/255, blue: 129/255)
                                        : (isCurrent
                                           ? (isPendingAction ? Color(red: 239/255, green: 68/255, blue: 68/255) : Color(red: 99/255, green: 102/255, blue: 241/255))
                                           : Color(red: 226/255, green: 232/255, blue: 240/255))
                                )
                                .frame(height: 5)
                        }
                    }
                    
                    HStack {
                        Text("Stage: \(completedTasks)/\(totalTasks) Milestones Completed")
                            .font(.system(size: 10.5, weight: .bold))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        Spacer()
                        Text("\(progressPct)%")
                            .font(.system(size: 11, weight: .black))
                            .foregroundColor(isPendingAction ? Color(red: 239/255, green: 68/255, blue: 68/255) : Color(red: 99/255, green: 102/255, blue: 241/255))
                    }
                }
                
                Divider()
                    .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                
                // Bottom Action Buttons Strip
                HStack(spacing: 10) {
                    Button(action: onChatCA) {
                        HStack(spacing: 5) {
                            Image(systemName: "bubble.left.fill")
                                .font(.system(size: 10, weight: .bold))
                            Text("Chat with CA")
                                .font(.system(size: 11, weight: .bold))
                        }
                        .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                        .padding(.horizontal, 12)
                        .padding(.vertical, 7)
                        .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                        .cornerRadius(10)
                    }
                    .buttonStyle(PlainButtonStyle())
                    
                    Spacer()
                    
                    HStack(spacing: 4) {
                        Text(isPendingAction ? "Upload Docs Now" : "Track Milestones")
                            .font(.system(size: 11, weight: .black))
                        Image(systemName: "arrow.right")
                            .font(.system(size: 10, weight: .bold))
                    }
                    .foregroundColor(.white)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 7)
                    .background(
                        isPendingAction
                            ? LinearGradient(colors: [Color(red: 239/255, green: 68/255, blue: 68/255), Color(red: 220/255, green: 38/255, blue: 38/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                            : LinearGradient(colors: [Color(red: 99/255, green: 102/255, blue: 241/255), Color(red: 79/255, green: 70/255, blue: 229/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                    )
                    .cornerRadius(10)
                    .shadow(color: (isPendingAction ? Color(red: 239/255, green: 68/255, blue: 68/255) : Color(red: 99/255, green: 102/255, blue: 241/255)).opacity(0.3), radius: 5, y: 2)
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(20)
            .overlay(
                RoundedRectangle(cornerRadius: 20)
                    .stroke(isPendingAction ? Color(red: 252/255, green: 165/255, blue: 165/255) : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: isPendingAction ? 1.5 : 1)
            )
            .shadow(color: isPendingAction ? Color(red: 239/255, green: 68/255, blue: 68/255).opacity(0.08) : Color.black.opacity(0.03), radius: 8, y: 3)
        }
        .buttonStyle(PlainButtonStyle())
    }
}

// Creative Modern Service Card
struct CreativeServiceCard: View {
    let title: String
    let subtitle: String
    let tag: String
    let price: String
    let icon: String
    let themeColor: Color
    let bgGradient: [Color]
    let action: () -> Void
    
    var body: some View {
        Button(action: {
            let impact = UIImpactFeedbackGenerator(style: .medium)
            impact.impactOccurred()
            action()
        }) {
            VStack(alignment: .leading, spacing: 10) {
                // Top Row: Icon + Tag Pill
                HStack(alignment: .center) {
                    ZStack {
                        Circle()
                            .fill(themeColor.opacity(0.14))
                            .frame(width: 38, height: 38)
                        Image(systemName: icon)
                            .font(.system(size: 16, weight: .bold))
                            .foregroundColor(themeColor)
                    }
                    
                    Spacer()
                    
                    Text(tag)
                        .font(.system(size: 8.5, weight: .black))
                        .foregroundColor(themeColor)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2.5)
                        .background(themeColor.opacity(0.1))
                        .cornerRadius(6)
                }
                
                // Title & Subtitle
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .lineLimit(1)
                    Text(subtitle)
                        .font(.system(size: 10, weight: .medium))
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        .lineLimit(1)
                }
                
                // Bottom Row: Price Chip + Circle Arrow
                HStack {
                    Text("From \(price)")
                        .font(.system(size: 10.5, weight: .black))
                        .foregroundColor(themeColor)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .background(themeColor.opacity(0.08))
                        .cornerRadius(6)
                    
                    Spacer()
                    
                    ZStack {
                        Circle()
                            .fill(Color.white)
                            .frame(width: 22, height: 22)
                            .shadow(color: Color.black.opacity(0.05), radius: 2, y: 1)
                        Image(systemName: "arrow.up.right")
                            .font(.system(size: 9, weight: .black))
                            .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                    }
                }
            }
            .padding(12)
            .background(
                LinearGradient(colors: bgGradient, startPoint: .topLeading, endPoint: .bottomTrailing)
            )
            .cornerRadius(18)
            .overlay(
                RoundedRectangle(cornerRadius: 18)
                    .stroke(themeColor.opacity(0.18), lineWidth: 1)
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
