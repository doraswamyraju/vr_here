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
    @State private var isShowingNotifications = false
    @State private var showCreateOrderSheet = false
    @State private var showCreateTodoSheet = false
    @StateObject private var hrmsViewModel = HrmsViewModel()
    
    private var pendingOrdersCount: Int {
        adminViewModel.orders.filter { $0.status.lowercased() == "pending" || $0.status.lowercased() == "processing" }.count
    }
    
    private var pendingLeavesCount: Int {
        hrmsViewModel.adminLeaves.filter { $0.status.lowercased() == "pending" }.count
    }
    
    private var adminDockItems: [BMSDockItem] {
        [
            BMSDockItem(label: "Overview", iconName: "chart.pie", tabId: "Overview"),
            BMSDockItem(label: "Orders", iconName: "bag.badge.plus", tabId: "Orders", badgeCount: pendingOrdersCount),
            BMSDockItem(label: "CRM", iconName: "person.crop.circle.badge.checkmark", tabId: "CRM"),
            BMSDockItem(label: "HRMS", iconName: "person.3", tabId: "HRMS", badgeCount: pendingLeavesCount),
            BMSDockItem(label: "Users", iconName: "person.badge.shield.checkmark", tabId: "Users")
        ]
    }
    
    var body: some View {
        ZStack {
            VStack(spacing: 0) {
                // Top Custom Header
                VRHeader(
                    title: "ADMIN PANEL",
                    showMenu: true,
                    onMenuClick: { withAnimation(.spring(response: 0.28, dampingFraction: 0.85)) { isSidebarOpen.toggle() } },
                    showLogout: true,
                    onLogoutClick: onLogout,
                    showBack: activeTab != "Overview" || !adminViewModel.selectedOrderId.isEmpty,
                    onBackClick: {
                        withAnimation {
                            if !adminViewModel.selectedOrderId.isEmpty {
                                adminViewModel.selectedOrderId = ""
                            } else {
                                activeTab = "Overview"
                                adminViewModel.selectedOrderFilter = "All"
                            }
                        }
                    },
                    onLogoClick: {
                        withAnimation {
                            if !adminViewModel.selectedOrderId.isEmpty {
                                adminViewModel.selectedOrderId = ""
                            } else {
                                activeTab = "Overview"
                                adminViewModel.selectedOrderFilter = "All"
                            }
                        }
                    },
                    showNotifications: true,
                    hasUnreadNotifications: adminViewModel.notifications.contains(where: { !$0.isRead }),
                    onNotificationsClick: { isShowingNotifications = true }
                )
                
                // Active tabs switcher with floating dock and Quick Action FAB
                ZStack(alignment: .bottom) {
                    Color.bgLight.ignoresSafeArea()
                    
                    Group {
                        switch activeTab {
                        case "Overview":
                            AdminOverviewTab(
                                viewModel: adminViewModel,
                                userName: userName,
                                onOpenNewOrder: { showCreateOrderSheet = true },
                                onOpenNewTodo: { showCreateTodoSheet = true }
                            ) { tab in
                                activeTab = tab
                            }
                        case "Orders":
                            AdminOrdersTab(viewModel: adminViewModel)
                        case "CRM":
                            AdminCrmTab(viewModel: adminViewModel)
                        case "HRMS":
                            AdminHrmsTab(viewModel: adminViewModel, hrmsViewModel: hrmsViewModel)
                        case "Users":
                            AdminUsersTab(viewModel: adminViewModel)
                        case "Todo":
                            AdminTodoTab(viewModel: adminViewModel)
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
                        case "Bookkeeping":
                            AdminBookkeepingTab(viewModel: adminViewModel)
                        case "Freelancers":
                            AdminFreelancersTab(viewModel: adminViewModel)
                        default:
                            Text("Unknown Tab")
                        }
                    }
                    
                    // 1:1 Floating Quick Action Button & Bottom Dock (Hidden inside Order details workspace)
                    if adminViewModel.selectedOrderId.isEmpty {
                        HStack {
                            Spacer()
                            BMSQuickActionFAB(
                                onNewOrder: {
                                    showCreateOrderSheet = true
                                },
                                onNewTodo: {
                                    showCreateTodoSheet = true
                                }
                            )
                        }
                        
                        BMSAppFloatingDock(activeTab: $activeTab, dockItems: adminDockItems)
                    }
                }
            }
            .refreshable {
                await adminViewModel.syncDashboardDataAsync(silent: false)
            }
            
            // Drawer Menu overlay
            if isSidebarOpen {
                ZStack(alignment: .leading) {
                    Color.black.opacity(0.5)
                        .ignoresSafeArea()
                        .onTapGesture {
                            withAnimation { isSidebarOpen = false }
                        }
                    
                    let sidebarItems = [
                        BMSSidebarItem(label: "Dashboard Summary", iconName: "chart.pie", tabId: "Overview"),
                        BMSSidebarItem(label: "Manage Orders", iconName: "bag", tabId: "Orders"),
                        BMSSidebarItem(label: "Customer CRM", iconName: "person.crop.circle.badge.checkmark", tabId: "CRM"),
                        BMSSidebarItem(label: "HRMS Portal", iconName: "person.3", tabId: "HRMS"),
                        BMSSidebarItem(label: "Users", iconName: "person.2.fill", tabId: "Users"),
                        BMSSidebarItem(label: "Tasks Board", iconName: "checkmark.circle", tabId: "Todo"),
                        BMSSidebarItem(label: "Compliance Panel", iconName: "checkmark.seal", tabId: "Compliance"),
                        BMSSidebarItem(label: "Bookkeeping Desk", iconName: "book.closed", tabId: "Bookkeeping"),
                        BMSSidebarItem(label: "Performance Metrics", iconName: "chart.bar.fill", tabId: "Performance"),
                        BMSSidebarItem(label: "Business Reports", iconName: "chart.bar", tabId: "Reports"),
                        BMSSidebarItem(label: "Admin Notifications", iconName: "bell", tabId: "Notifications"),
                        BMSSidebarItem(label: "KB Hub", iconName: "book", tabId: "KB"),
                        BMSSidebarItem(label: "Client Support", iconName: "envelope", tabId: "Support"),
                        BMSSidebarItem(label: "Services Master", iconName: "gearshape.fill", tabId: "Services"),
                        BMSSidebarItem(label: "Referral Ledger", iconName: "square.and.arrow.up", tabId: "Referral"),
                        BMSSidebarItem(label: "Recurring Hub", iconName: "arrow.triangle.2.circlepath", tabId: "Recurring"),
                        BMSSidebarItem(label: "Freelancer Hub", iconName: "person.2", tabId: "Freelancers"),
                        BMSSidebarItem(label: "IT Checklist", iconName: "doc.text", tabId: "ITChecklist"),
                        BMSSidebarItem(label: "Global Settings", iconName: "slider.horizontal.3", tabId: "Settings")
                    ]
                    BMSAppSidebar(
                        userName: userName,
                        roleName: "System Administrator",
                        menuItems: sidebarItems,
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
        .sheet(isPresented: $isShowingNotifications) {
            NotificationsSheet(
                notifications: adminViewModel.notifications,
                onMarkAsRead: { adminViewModel.markNotificationAsRead(id: $0) },
                onMarkAllAsRead: { adminViewModel.markAllNotificationsAsRead() },
                onClose: { isShowingNotifications = false }
            )
        }
        .sheet(isPresented: $showCreateOrderSheet) {
            AdminCreateOrderSheet(
                viewModel: adminViewModel,
                onDismiss: { showCreateOrderSheet = false }
            )
        }
        .sheet(isPresented: $showCreateTodoSheet) {
            AdminCreateTodoSheet(
                viewModel: adminViewModel,
                onDismiss: { showCreateTodoSheet = false }
            )
        }
    }
}
