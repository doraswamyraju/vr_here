import SwiftUI

struct FreelancerDashboardView: View {
    @ObservedObject var viewModel: FreelancerDashboardViewModel
    let userName: String
    let onLogout: () -> Void
    let onDeleteAccount: () -> Void
    
    @State private var activeTab = "Overview"
    @State private var selectedOrderForProcessing: OrderResponse? = nil
    
    @State private var isSidebarOpen = false
    @State private var showingToast = false
    @State private var toastMsg = ""
    @State private var isShowingNotifications = false
    
    var body: some View {
        ZStack {
            // Main Scaffold
            VStack(spacing: 0) {
                // Top Custom Header
                VRHeader(
                    title: "FREELANCER PANEL",
                    showMenu: true,
                    onMenuClick: { withAnimation { isSidebarOpen.toggle() } },
                    showLogout: true,
                    onLogoutClick: onLogout,
                    showBack: activeTab != "Overview",
                    onBackClick: { withAnimation { activeTab = "Overview" } },
                    showNotifications: true,
                    hasUnreadNotifications: viewModel.notifications.contains(where: { !$0.isRead }),
                    onNotificationsClick: { isShowingNotifications = true }
                )
                
                // Main Tab Switcher
                ZStack {
                    Color.bgLight.ignoresSafeArea()
                    
                    switch activeTab {
                    case "Overview":
                        FreelancerOverviewTab(viewModel: viewModel, userName: userName, onSelectTab: { activeTab = $0 })
                    case "Broadcasts":
                        FreelancerBroadcastsTab(viewModel: viewModel)
                    case "Queue":
                        FreelancerQueueTab(
                            viewModel: viewModel,
                            selectedOrder: $selectedOrderForProcessing
                        )
                    case "Ledger":
                        FreelancerLedgerTab(viewModel: viewModel)
                    case "Support":
                        FreelancerSupportTab(viewModel: viewModel)
                    case "Notifications":
                        FreelancerNotificationsTab(viewModel: viewModel)
                    case "Settings":
                        FreelancerSettingsTab(viewModel: viewModel, onDeleteAccount: onDeleteAccount)
                    default:
                        Text("Unknown Tab")
                    }
                }
                
                // Dock Navigation Bar at Bottom
                let dockItems = [
                    BMSDockItem(label: "Me", iconName: "square.grid.2x2", tabId: "Overview"),
                    BMSDockItem(label: "Broadcasts", iconName: "bell", tabId: "Broadcasts"),
                    BMSDockItem(label: "Queue", iconName: "briefcase", tabId: "Queue"),
                    BMSDockItem(label: "Ledger", iconName: "indianrupeesign", tabId: "Ledger")
                ]
                BMSAppFloatingDock(activeTab: $activeTab, dockItems: dockItems)
            }
            .refreshable {
                await viewModel.syncFreelancerDataAsync()
            }
            
            // Sidebar Drawer
            if isSidebarOpen {
                ZStack(alignment: .leading) {
                    Color.black.opacity(0.5)
                        .ignoresSafeArea()
                        .onTapGesture {
                            withAnimation { isSidebarOpen = false }
                        }
                    
                    let sidebarItems = [
                        BMSSidebarItem(label: "Overview", iconName: "house", tabId: "Overview"),
                        BMSSidebarItem(label: "Jobs Pools", iconName: "bell", tabId: "Broadcasts"),
                        BMSSidebarItem(label: "Work Queue", iconName: "briefcase", tabId: "Queue"),
                        BMSSidebarItem(label: "Payout Ledger", iconName: "indianrupeesign", tabId: "Ledger"),
                        BMSSidebarItem(label: "Support Desk", iconName: "headphones", tabId: "Support"),
                        BMSSidebarItem(label: "Notifications", iconName: "bell.badge", tabId: "Notifications"),
                        BMSSidebarItem(label: "Profile Details", iconName: "person.crop.circle", tabId: "Settings")
                    ]
                    BMSAppSidebar(
                        userName: userName,
                        roleName: "Freelancer Specialist",
                        menuItems: sidebarItems,
                        activeTab: $activeTab,
                        onLogout: onLogout,
                        onClose: { withAnimation { isSidebarOpen = false } }
                    )
                    .transition(.move(edge: .leading))
                }
            }
            
            // Global Toast layer
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
        .sheet(isPresented: $isShowingNotifications) {
            NotificationsSheet(
                notifications: viewModel.notifications,
                onMarkAsRead: { viewModel.markNotificationAsRead(id: $0) },
                onClose: { isShowingNotifications = false }
            )
        }
        .onAppear {
            viewModel.syncFreelancerData()
        }
        .onChange(of: viewModel.toastMessage) { msg in
            if let msg = msg {
                self.toastMsg = msg
                withAnimation { self.showingToast = true }
                viewModel.toastMessage = nil
            }
        }
    }
}
