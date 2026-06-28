import SwiftUI

struct AdminDashboardView: View {
    @ObservedObject var authViewModel: AuthViewModel
    @ObservedObject var adminViewModel: AdminDashboardViewModel
    let userName: String
    let onLogout: () -> Void
    
    @State private var activeTab = "Overview"
    @State private var isSidebarOpen = false
    @State private var showingToast = false
    @State private var toastMsg = ""
    
    var body: some View {
        ZStack {
            VStack(spacing: 0) {
                // Top Custom Header
                VRHeader(
                    title: "ADMIN PANEL",
                    showMenu: true,
                    onMenuClick: { withAnimation { isSidebarOpen.toggle() } },
                    showLogout: true,
                    onLogoutClick: onLogout
                )
                
                // Active tabs switcher with floating dock
                ZStack(alignment: .bottom) {
                    Color.bgLight.ignoresSafeArea()
                    
                    Group {
                        switch activeTab {
                        case "Overview":
                            AdminOverviewTab(viewModel: adminViewModel, userName: userName) { tab in
                                activeTab = tab
                            }
                        case "Orders":
                            AdminOrdersTab(viewModel: adminViewModel)
                        case "CRM":
                            AdminCrmTab(viewModel: adminViewModel)
                        case "HRMS":
                            AdminHrmsTab(viewModel: adminViewModel)
                        case "Users":
                            AdminUsersTab(viewModel: adminViewModel)
                        case "Todo":
                            AdminTodoTab(viewModel: adminViewModel)
                        case "Finance":
                            AdminFinanceTab(viewModel: adminViewModel)
                        case "Compliance":
                            AdminComplianceTab(viewModel: adminViewModel)
                        case "Performance":
                            AdminPerformanceTab(viewModel: adminViewModel)
                        case "Reports":
                            AdminReportsTab(viewModel: adminViewModel)
                        case "Notifications":
                            AdminNotificationsTab(viewModel: adminViewModel)
                        case "KB":
                            AdminKbTab(viewModel: adminViewModel)
                        case "Support":
                            AdminSupportTab(viewModel: adminViewModel)
                        case "Services":
                            AdminServicesTab(viewModel: adminViewModel)
                        case "Referral":
                            AdminReferralTab(viewModel: adminViewModel)
                        case "Recurring":
                            AdminRecurringTab(viewModel: adminViewModel)
                        case "Settings":
                            AdminSettingsTab(viewModel: adminViewModel)
                        case "ITChecklist":
                            AdminITChecklistTab(viewModel: adminViewModel)
                        case "Freelancers":
                            AdminFreelancersTab(viewModel: adminViewModel)
                        default:
                            Text("Unknown Tab")
                        }
                    }
                    .ignoresSafeArea(edges: .bottom)
                    
                    AdminFloatingDock(activeTab: $activeTab)
                }
            }
            
            // Drawer Menu overlay
            if isSidebarOpen {
                ZStack(alignment: .leading) {
                    Color.black.opacity(0.5)
                        .ignoresSafeArea()
                        .onTapGesture {
                            withAnimation { isSidebarOpen = false }
                        }
                    
                    AdminSidebarView(
                        userName: userName,
                        activeTab: $activeTab,
                        onLogout: onLogout,
                        onClose: {
                            withAnimation { isSidebarOpen = false }
                        }
                    )
                    .transition(.move(edge: .leading))
                }
            }
            
            // Global Toast
            if showingToast {
                VStack {
                    Spacer()
                    ToastView(message: toastMsg)
                }
                .onAppear {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
                        showingToast = false
                    }
                }
                .zIndex(20)
            }
        }
        .onAppear {
            adminViewModel.syncDashboardData(silent: false)
        }
        .onChange(of: adminViewModel.toastMessage) { val in
            if let msg = val {
                toastMsg = msg
                showingToast = true
                adminViewModel.toastMessage = nil
            }
        }
    }
}

// --- Admin Floating bottom Dock ---
struct AdminFloatingDock: View {
    @Binding var activeTab: String
    
    let tabs = [
        ("Overview", "chart.pie", "Overview"),
        ("Orders", "bag.badge.plus", "Orders"),
        ("CRM", "ticket", "CRM"),
        ("HRMS", "person.3", "HRMS"),
        ("Users", "person.badge.shield.check", "Users")
    ]
    
    var body: some View {
        HStack(spacing: 0) {
            ForEach(tabs, id: \.0) { tabId, iconName, label in
                let isSelected = activeTab == tabId
                Button(action: { activeTab = tabId }) {
                    VStack(spacing: 4) {
                        Image(systemName: iconName + (isSelected ? ".fill" : ""))
                            .font(.system(size: 16))
                            .foregroundColor(isSelected ? .white : .textMuted)
                        Text(label)
                            .font(.system(size: 9, weight: isSelected ? .black : .semibold))
                            .foregroundColor(isSelected ? .white : .textMuted)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                }
                .buttonStyle(PlainButtonStyle())
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 10)
        .background(Color.darkSlate)
        .cornerRadius(24)
        .overlay(
            AnimatedGradientBorder()
        )
        .shadow(color: Color.black.opacity(0.15), radius: 10, x: 0, y: 5)
        .padding(.horizontal, 16)
        .padding(.bottom, 10)
    }
}

// --- Admin Sidebar Content Drawer ---
struct AdminSidebarView: View {
    let userName: String
    @Binding var activeTab: String
    let onLogout: () -> Void
    let onClose: () -> Void
    
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header with App logo & Close action
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 4) {
                        Text("VR HERE")
                            .font(.system(size: 18, weight: .black))
                            .foregroundColor(.textDark)
                            .tracking(2)
                        Circle()
                            .fill(Color.primaryRed)
                            .frame(width: 6, height: 6)
                    }
                    Text("OPERATIONS HUB")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.textMuted)
                        .tracking(1)
                }
                Spacer()
                Button(action: onClose) {
                    Image(systemName: "xmark")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.textMuted)
                        .padding(8)
                        .background(Color.bgLight)
                        .clipShape(Circle())
                }
                .buttonStyle(PlainButtonStyle())
            }
            .padding(.horizontal, 20)
            .padding(.top, 24)
            .padding(.bottom, 20)
            
            // Premium Profile card (Light Glassmorphic look)
            HStack(spacing: 12) {
                // Circular Avatar with Gradient Border
                Image(systemName: "person.crop.circle.fill")
                    .resizable()
                    .frame(width: 38, height: 38)
                    .foregroundColor(.textMuted)
                    .padding(2)
                    .background(LinearGradient(gradient: Gradient(colors: [Color.primaryRed, Color.orange]), startPoint: .topLeading, endPoint: .bottomTrailing))
                    .clipShape(Circle())
                    .shadow(color: Color.primaryRed.opacity(0.15), radius: 4, x: 0, y: 2)
                
                VStack(alignment: .leading, spacing: 2) {
                    Text(userName)
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(.textDark)
                    Text("System Administrator")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(.textMuted)
                }
                Spacer()
            }
            .padding(12)
            .background(Color.bgLight)
            .cornerRadius(16)
            .overlay(
                RoundedRectangle(cornerRadius: 16)
                    .stroke(Color.borderLight, lineWidth: 1)
            )
            .padding(.horizontal, 20)
            .padding(.bottom, 20)
            
            Divider()
                .background(Color.borderLight)
                .padding(.horizontal, 20)
                .padding(.bottom, 12)
            
            // Scroll list Menu
            ScrollView(showsIndicators: false) {
                VStack(spacing: 4) {
                    AdminSidebarItem(label: "Dashboard Summary", iconName: "chart.pie.fill", tabId: "Overview", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Manage Orders", iconName: "bag.fill", tabId: "Orders", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Customer CRM", iconName: "ticket.fill", tabId: "CRM", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "HRMS Portal", iconName: "person.3.fill", tabId: "HRMS", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Users Matrix", iconName: "person.badge.shield.checkmark.fill", tabId: "Users", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Tasks Board", iconName: "checkmark.circle.fill", tabId: "Todo", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Finance Ledger", iconName: "banknote.fill", tabId: "Finance", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Compliance Panel", iconName: "doc.text.badge.checkmark", tabId: "Compliance", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Performance Metrics", iconName: "trending.up", tabId: "Performance", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Business Reports", iconName: "chart.bar.fill", tabId: "Reports", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Admin Notifications", iconName: "bell.fill", tabId: "Notifications", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "KB Hub", iconName: "book.fill", tabId: "KB", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Client Support", iconName: "envelope.fill", tabId: "Support", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Services Master", iconName: "gearshape.fill", tabId: "Services", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Referral Ledger", iconName: "square.and.arrow.up.fill", tabId: "Referral", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Recurring Hub", iconName: "arrow.triangle.2.circlepath", tabId: "Recurring", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Freelancer Hub", iconName: "person.2.fill", tabId: "Freelancers", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "IT Checklist", iconName: "doc.text.fill", tabId: "ITChecklist", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Global Settings", iconName: "slider.horizontal.3", tabId: "Settings", activeTab: $activeTab, onClose: onClose)
                }
                .padding(.horizontal, 16)
            }
            
            // Footer Section with Styled Sign Out Card
            VStack(spacing: 0) {
                Divider()
                    .background(Color.borderLight)
                    .padding(.bottom, 12)
                
                Button(action: {
                    onClose()
                    onLogout()
                }) {
                    HStack(spacing: 12) {
                        Image(systemName: "rectangle.portrait.and.arrow.right")
                            .font(.system(size: 15, weight: .bold))
                            .foregroundColor(.red)
                        Text("Sign Out Session")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.red)
                        Spacer()
                    }
                    .padding(14)
                    .background(Color.red.opacity(0.08))
                    .cornerRadius(14)
                    .overlay(
                        RoundedRectangle(cornerRadius: 14)
                            .stroke(Color.red.opacity(0.15), lineWidth: 1)
                    )
                }
                .buttonStyle(PlainButtonStyle())
                .padding(.horizontal, 20)
                .padding(.bottom, 30)
            }
        }
        .frame(width: 280)
        .background(Color.white)
        .edgesIgnoringSafeArea(.bottom)
    }
}

struct AdminSidebarItem: View {
    let label: String
    let iconName: String
    let tabId: String
    @Binding var activeTab: String
    let onClose: () -> Void
    
    var body: some View {
        let isSelected = activeTab == tabId
        Button(action: {
            withAnimation(.spring(response: 0.35, dampingFraction: 0.7)) {
                activeTab = tabId
            }
            onClose()
        }) {
            HStack(spacing: 12) {
                // Left indicator bar (Crimson/Red)
                if isSelected {
                    RoundedRectangle(cornerRadius: 2)
                        .fill(Color.primaryRed)
                        .frame(width: 4, height: 16)
                        .transition(.scale)
                } else {
                    Spacer().frame(width: 4)
                }
                
                Image(systemName: iconName)
                    .font(.system(size: 15, weight: isSelected ? .bold : .regular))
                    .foregroundColor(isSelected ? Color.primaryRed : .textMuted)
                    .frame(width: 24)
                
                Text(label)
                    .font(.system(size: 13, weight: isSelected ? .black : .semibold))
                    .foregroundColor(isSelected ? Color.primaryRed : .textDark)
                
                Spacer()
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(
                isSelected ? 
                AnyView(Color.primaryRed.opacity(0.08)) : 
                AnyView(Color.clear)
            )
            .cornerRadius(12)
            .overlay(
                RoundedRectangle(cornerRadius: 12)
                    .stroke(isSelected ? Color.primaryRed.opacity(0.12) : Color.clear, lineWidth: 1)
            )
        }
        .buttonStyle(PlainButtonStyle())
        .scaleEffect(isSelected ? 1.02 : 1.0)
    }
}
