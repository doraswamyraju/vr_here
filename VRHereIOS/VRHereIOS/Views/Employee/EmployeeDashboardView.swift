import SwiftUI
import Combine

struct EmployeeDashboardView: View {
    @ObservedObject var viewModel: EmployeeDashboardViewModel
    let userName: String
    let onLogout: () -> Void
    
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
                    title: "EMPLOYEE PANEL",
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
                
                // Active Shift Timer Banner
                if viewModel.isClockedIn, let clockInString = viewModel.currentAttendanceRecord?.clockInAt {
                    ShiftTimerBanner(clockInAt: clockInString)
                }
                
                // Main Tab Switcher
                ZStack {
                    Color.bgLight.ignoresSafeArea()
                    
                    switch activeTab {
                    case "Overview":
                        EmployeeOverviewTab(viewModel: viewModel, userName: userName, onSelectTab: { activeTab = $0 })
                    case "Queue":
                        EmployeeQueueTab(
                            viewModel: viewModel,
                            selectedOrder: $selectedOrderForProcessing
                        )
                    case "Attendance":
                        EmployeeAttendanceTab(viewModel: viewModel)
                    case "Support":
                        EmployeeSupportTab(viewModel: viewModel)
                    case "Notifications":
                        EmployeeNotificationsTab(viewModel: viewModel)
                    case "Security":
                        EmployeeSecurityTab()
                    case "HRMS":
                        HrmsEmployeeScreen()
                    default:
                        Text("Unknown Tab")
                    }
                }
                
                // Dock Navigation Bar at Bottom
                let dockItems = [
                    BMSDockItem(label: "Me", iconName: "square.grid.2x2", tabId: "Overview"),
                    BMSDockItem(label: "Queue", iconName: "briefcase", tabId: "Queue"),
                    BMSDockItem(label: "Attendance", iconName: "clock", tabId: "Attendance"),
                    BMSDockItem(label: "HRMS", iconName: "person.3", tabId: "HRMS")
                ]
                BMSAppFloatingDock(activeTab: $activeTab, dockItems: dockItems)
            }
            .refreshable {
                await viewModel.syncDashboardDataAsync()
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
                        BMSSidebarItem(label: "My Overview", iconName: "house", tabId: "Overview"),
                        BMSSidebarItem(label: "Work Queue", iconName: "briefcase", tabId: "Queue"),
                        BMSSidebarItem(label: "Attendance Clock", iconName: "clock", tabId: "Attendance"),
                        BMSSidebarItem(label: "Support Tickets", iconName: "headphones", tabId: "Support"),
                        BMSSidebarItem(label: "Notifications Feed", iconName: "bell", tabId: "Notifications"),
                        BMSSidebarItem(label: "Security Matrix", iconName: "shield", tabId: "Security"),
                        BMSSidebarItem(label: "HRMS Portal", iconName: "person.3", tabId: "HRMS")
                    ]
                    BMSAppSidebar(
                        userName: userName,
                        roleName: "Operations Specialist",
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
        .onAppear {
            viewModel.syncDashboardData()
        }
        .onChange(of: viewModel.toastMessage) { val in
            if let msg = val {
                toastMsg = msg
                showingToast = true
                viewModel.toastMessage = nil
            }
        }
        .sheet(isPresented: $isShowingNotifications) {
            NotificationsSheet(
                notifications: viewModel.notifications,
                onMarkAsRead: { viewModel.markNotificationAsRead(notificationId: $0) },
                onClose: { isShowingNotifications = false }
            )
        }
    }
}

// --- Active Shift Timer banner ---
struct ShiftTimerBanner: View {
    let clockInAt: String
    
    @State private var elapsedSeconds = 0.0
    let timer = Timer.publish(every: 1.0, on: .main, in: .common).autoconnect()
    
    private var timeInterval: TimeInterval {
        // Date Parsing
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: clockInAt) {
            return Date().timeIntervalSince(date)
        }
        return 0.0
    }
    
    var body: some View {
        HStack {
            HStack(spacing: 6) {
                Circle()
                    .fill(Color.green)
                    .frame(width: 8, height: 8)
                Text("Active Shift Session:")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.textMuted)
            }
            
            Spacer()
            
            Text(formattedDuration)
                .font(.system(size: 11, weight: .black))
                .foregroundColor(.blue)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(Color.bgInput)
        .onReceive(timer) { _ in
            elapsedSeconds = timeInterval
        }
        .onAppear {
            elapsedSeconds = timeInterval
        }
    }
    
    private var formattedDuration: String {
        let seconds = Int(elapsedSeconds)
        let h = seconds / 3600
        let m = (seconds % 3600) / 60
        let s = seconds % 60
        return String(format: "%02d:%02d:%02d", h, m, s)
    }
}


