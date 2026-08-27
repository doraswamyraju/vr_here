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
                
                // 2. Creative Glowing Search Capsule
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
                        
                        TextField("Search legal, tax, ISO, licensing services...", text: $searchQuery)
                            .font(.system(size: 13.5, weight: .semibold))
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
                                Text("Discover")
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
                                borderLabel(text: "Compliance Alert")
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
    
    @ViewBuilder
    private func borderLabel(text: String) -> some View {
        Text(text)
            .font(.system(size: 9, weight: .bold))
            .foregroundColor(.primaryRed)
            .padding(.horizontal, 6)
            .padding(.vertical, 3)
            .background(Color.primaryRed.opacity(0.1))
            .cornerRadius(4)
    }
}
