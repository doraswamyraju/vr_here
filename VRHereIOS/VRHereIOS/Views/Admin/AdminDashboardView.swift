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
                
                // Active tabs switcher
                ZStack {
                    Color.bgLight.ignoresSafeArea()
                    
                    switch activeTab {
                    case "Overview":
                        AdminOverviewTab(viewModel: adminViewModel, userName: userName)
                    case "Orders":
                        AdminOrdersTab(viewModel: adminViewModel)
                    case "CRM":
                        AdminCrmTab(viewModel: adminViewModel)
                    case "HRMS":
                        AdminHrmsTab(viewModel: adminViewModel)
                    case "Users":
                        AdminUsersTab(viewModel: adminViewModel)
                    default:
                        Text("Unknown Tab")
                    }
                }
                
                // Floating Bottom Dock
                AdminFloatingDock(activeTab: $activeTab)
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
        VStack(spacing: 0) {
            Divider().background(Color.borderLight)
            HStack(spacing: 0) {
                ForEach(tabs, id: \.0) { tabId, iconName, label in
                    let isSelected = activeTab == tabId
                    Button(action: { activeTab = tabId }) {
                        VStack(spacing: 4) {
                            Image(systemName: iconName + (isSelected ? ".fill" : ""))
                                .font(.system(size: 18))
                                .foregroundColor(isSelected ? .primaryRed : .textMuted)
                            Text(label)
                                .font(.system(size: 9, weight: isSelected ? .black : .semibold))
                                .foregroundColor(isSelected ? .primaryRed : .textMuted)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                    }
                    .buttonStyle(PlainButtonStyle())
                }
            }
            .padding(.vertical, 6)
            .background(Color.white)
        }
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
            // Header
            VStack(alignment: .leading, spacing: 4) {
                Text("VR Here BMS Admin")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.white)
                Text(userName)
                    .font(.system(size: 12, weight: .bold))
                    .foregroundColor(.white.opacity(0.8))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
            .background(LinearGradient(gradient: Gradient(colors: [.red, .orange]), startPoint: .topLeading, endPoint: .bottomTrailing))
            
            // Scroll list Menu
            ScrollView {
                VStack(spacing: 4) {
                    AdminSidebarItem(label: "Dashboard Summary", iconName: "chart.pie", tabId: "Overview", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Manage Orders", iconName: "bag", tabId: "Orders", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Customer CRM", iconName: "ticket", tabId: "CRM", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "HRMS Portal", iconName: "person.3", tabId: "HRMS", activeTab: $activeTab, onClose: onClose)
                    AdminSidebarItem(label: "Users Matrix", iconName: "person.badge.shield.check", tabId: "Users", activeTab: $activeTab, onClose: onClose)
                    
                    Divider()
                        .background(Color.borderLight)
                        .padding(.vertical, 12)
                    
                    Button(action: {
                        onClose()
                        onLogout()
                    }) {
                        HStack(spacing: 12) {
                            Image(systemName: "rectangle.portrait.and.arrow.right")
                                .foregroundColor(.red)
                            Text("Sign Out")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(.red)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 12)
                    }
                }
                .padding(8)
            }
            Spacer()
        }
        .frame(width: 270)
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
            activeTab = tabId
            onClose()
        }) {
            HStack(spacing: 12) {
                Image(systemName: iconName)
                    .foregroundColor(isSelected ? .white : .textMuted)
                Text(label)
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(isSelected ? .white : .textDark)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(isSelected ? Color.primaryRed : Color.clear)
            .cornerRadius(10)
        }
        .buttonStyle(PlainButtonStyle())
    }
}
