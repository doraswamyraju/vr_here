import SwiftUI

struct CustomerDashboardView: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    let userName: String
    let onLogout: () -> Void
    let onDeleteAccount: () -> Void
    
    @Environment(\.openURL) private var openURL
    
    @State private var activeTab = "Home"
    @State private var selectedOrderId = ""
    @State private var searchQuery = ""
    
    @State private var isSidebarOpen = false
    
    // Webview overlays
    @State private var webviewUrl: String? = nil
    @State private var webviewTitle: String? = nil
    
    // Custom detail/checkout view overlays
    @State private var activeServiceKey: String? = nil
    @State private var checkoutOrderData: CheckoutOrderResponse? = nil
    @State private var checkoutPayloadData: CheckoutPayload? = nil
    
    @State private var showingToast = false
    @State private var toastMsg = ""
    @State private var isShowingNotifications = false
    
    var body: some View {
        ZStack {
            // Main Scaffold
            VStack(spacing: 0) {
                // Top Header Bar
                VRHeader(
                    title: "DASHBOARD",
                    showMenu: true,
                    onMenuClick: { withAnimation { isSidebarOpen.toggle() } },
                    showLogout: true,
                    onLogoutClick: onLogout,
                    showBack: activeTab != "Home",
                    onBackClick: { withAnimation { activeTab = "Home" } },
                    showNotifications: true,
                    hasUnreadNotifications: viewModel.notifications.contains(where: { !$0.isRead }),
                    onNotificationsClick: { isShowingNotifications = true }
                )
                
                // Tab Contents & Floating Dock
                ZStack(alignment: .bottom) {
                    Color.bgLight.ignoresSafeArea()
                    
                    Group {
                        switch activeTab {
                        case "Home":
                            CustomerHomeTab(
                                viewModel: viewModel,
                                userName: userName,
                                searchQuery: $searchQuery,
                                onSelectTab: { activeTab = $0 },
                                onOpenProject: { orderId in
                                    selectedOrderId = orderId
                                    activeTab = "Orders"
                                },
                                onOpenLiveService: { name, url in
                                    let key = url.components(separatedBy: "/").last ?? ""
                                    if ServiceCatalog.shared.items[key] != nil {
                                        activeServiceKey = key
                                    } else {
                                        webviewUrl = url
                                        webviewTitle = name
                                    }
                                },
                                onLogout: onLogout
                            )
                        case "Services":
                            CustomerServicesTab(
                                viewModel: viewModel,
                                onSelectTab: { activeTab = $0 },
                                onOpenLiveService: { name, url in
                                    let key = url.components(separatedBy: "/").last ?? ""
                                    if ServiceCatalog.shared.items[key] != nil {
                                        activeServiceKey = key
                                    } else {
                                        webviewUrl = url
                                        webviewTitle = name
                                    }
                                }
                            )
                        case "Orders":
                            CustomerOrdersTab(
                                viewModel: viewModel,
                                selectedOrderId: $selectedOrderId,
                                onSelectTab: { activeTab = $0 }
                            )
                        case "Invoices":
                            CustomerInvoicesTab(viewModel: viewModel)
                        case "Vault":
                            CustomerVaultTab(viewModel: viewModel)
                        case "Support":
                            CustomerSupportTab(viewModel: viewModel)
                        case "Account":
                            CustomerAccountTab(viewModel: viewModel, onSelectTab: { activeTab = $0 }, onDeleteAccount: onDeleteAccount)
                        default:
                            Text("Unknown Tab")
                        }
                    }
                    .ignoresSafeArea(edges: .bottom)
                    
                    // Persistence WhatsApp & Ticket floating triggers in Bottom Right
                    VStack(spacing: 12) {
                        Spacer()
                        HStack {
                            Spacer()
                            VStack(spacing: 12) {
                                // WhatsApp Trigger
                                Button(action: {
                                    if let url = URL(string: "https://wa.me/918008530606") {
                                        #if os(iOS)
                                        if UIApplication.shared.canOpenURL(url) {
                                            UIApplication.shared.open(url)
                                        } else {
                                            toastMsg = "WhatsApp is not installed."
                                            showingToast = true
                                        }
                                        #elseif os(macOS)
                                        openURL(url)
                                        #endif
                                    }
                                }) {
                                    Image(systemName: "message.fill")
                                        .font(.title2)
                                        .foregroundColor(.white)
                                        .frame(width: 52, height: 52)
                                        .background(Color.green)
                                        .cornerRadius(26)
                                        .shadow(color: Color.green.opacity(0.3), radius: 6, x: 0, y: 3)
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                                
                                // Support Ticket
                                Button(action: { activeTab = "Support" }) {
                                    Image(systemName: "headphones")
                                        .font(.title2)
                                        .foregroundColor(.white)
                                        .frame(width: 52, height: 52)
                                        .background(Color.blue)
                                        .cornerRadius(26)
                                        .shadow(color: Color.blue.opacity(0.3), radius: 6, x: 0, y: 3)
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                            }
                            .padding(.trailing, 20)
                            .padding(.bottom, 110) // clear the floating dock
                        }
                    }
                    
                    // Floating Glow Island Bottom Dock Navigation Bar
                    if activeServiceKey == nil {
                        let dockItems = [
                            BMSDockItem(label: "Me", iconName: "square.grid.2x2", tabId: "Home"),
                            BMSDockItem(label: "Services", iconName: "briefcase", tabId: "Services"),
                            BMSDockItem(label: "Orders", iconName: "bag", tabId: "Orders"),
                            BMSDockItem(label: "Invoices", iconName: "doc.text", tabId: "Invoices"),
                            BMSDockItem(label: "Docs", iconName: "folder", tabId: "Vault"),
                            BMSDockItem(label: "Account", iconName: "person", tabId: "Account")
                        ]
                        BMSAppFloatingDock(activeTab: $activeTab, dockItems: dockItems, onTabSelected: { tabId in
                            if tabId != "Orders" { selectedOrderId = "" }
                        })
                    }
                }
            }
            .refreshable {
                await viewModel.refreshAllDataAsync(silent: false)
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
                        BMSSidebarItem(label: "Dashboard", iconName: "square.grid.2x2", tabId: "Home"),
                        BMSSidebarItem(label: "Services Catalog", iconName: "briefcase", tabId: "Services"),
                        BMSSidebarItem(label: "My Orders", iconName: "bag", tabId: "Orders"),
                        BMSSidebarItem(label: "Invoices", iconName: "doc.text", tabId: "Invoices"),
                        BMSSidebarItem(label: "Vault Documents", iconName: "folder", tabId: "Vault"),
                        BMSSidebarItem(label: "Help & Support", iconName: "headphones", tabId: "Support"),
                        BMSSidebarItem(label: "My Profile", iconName: "person", tabId: "Account")
                    ]
                    BMSAppSidebar(
                        userName: userName,
                        roleName: "Customer Account",
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
            
            // Secure Webview Overlay for external live service pages
            if let url = webviewUrl {
                CustomerServiceWebView(url: url, title: webviewTitle ?? "Service Catalog") {
                    webviewUrl = nil
                    webviewTitle = nil
                }
                .transition(.move(edge: .bottom))
                .zIndex(10)
            }
            
            // Native Service detail overlay
            if let key = activeServiceKey {
                CustomerServiceDetailScreen(
                    serviceKey: key,
                    onBackClick: { activeServiceKey = nil },
                    onNeedAdviceClick: {
                        activeServiceKey = nil
                        activeTab = "Support"
                    },
                    onCheckoutClick: { serviceTitle, plan, name, email, phone in
                        toastMsg = "Initiating order checkout..."
                        showingToast = true
                        
                        let payload = CheckoutPayload(
                            serviceName: serviceTitle,
                            packageName: plan.name,
                            amount: plan.price,
                            customerName: name,
                            email: email,
                            phone: phone,
                            referralCode: ""
                        )
                        
                        Task {
                            do {
                                let order = try await NetworkManager.shared.checkoutOrder(payload: payload)
                                checkoutPayloadData = payload
                                checkoutOrderData = order
                            } catch {
                                toastMsg = "Connection error: \(error.localizedDescription)"
                                showingToast = true
                            }
                        }
                    }
                )
                .transition(.move(edge: .trailing))
                .zIndex(11)
            }
            
            // Secure Razorpay WebView payment interface overlay
            if let order = checkoutOrderData, let payload = checkoutPayloadData {
                CustomerPaymentWebView(
                    key: order.key,
                    orderId: order.orderId,
                    amount: order.amount,
                    currency: order.currency,
                    serviceName: payload.serviceName,
                    packageName: payload.packageName,
                    customerName: payload.customerName,
                    customerEmail: payload.email,
                    customerPhone: payload.phone,
                    onSuccess: { paymentId, ordId, signature in
                        checkoutOrderData = nil
                        checkoutPayloadData = nil
                        activeServiceKey = nil
                        
                        toastMsg = "Payment successful! Verifying transaction..."
                        showingToast = true
                        
                        let verifyPayload = VerifyPayload(
                            serviceName: payload.serviceName,
                            packageName: payload.packageName,
                            amount: payload.amount,
                            customerName: payload.customerName,
                            email: payload.email,
                            phone: payload.phone,
                            referralCode: "",
                            razorpay_order_id: ordId,
                            razorpay_payment_id: paymentId,
                            razorpay_signature: signature
                        )
                        
                        Task {
                            do {
                                let verifyRes = try await NetworkManager.shared.verifyPayment(payload: verifyPayload)
                                if verifyRes.success {
                                    toastMsg = "Compliance Order Registered Successfully!"
                                    showingToast = true
                                    viewModel.refreshAllData()
                                    activeTab = "Orders"
                                } else {
                                    toastMsg = "Verification Error: \(verifyRes.message ?? "Signature validation failed")"
                                    showingToast = true
                                }
                            } catch {
                                toastMsg = "Network Error: \(error.localizedDescription)"
                                showingToast = true
                            }
                        }
                    },
                    onFailure: { errorMsg in
                        checkoutOrderData = nil
                        checkoutPayloadData = nil
                        toastMsg = "Payment failed: \(errorMsg)"
                        showingToast = true
                    },
                    onClose: {
                        checkoutOrderData = nil
                        checkoutPayloadData = nil
                        toastMsg = "Payment closed"
                        showingToast = true
                    }
                )
                .transition(.move(edge: .bottom))
                .zIndex(12)
            }
            
            // Heads-up In-app Notification Banner (Locks at top, auto dismisses after 5s)
            if let banner = viewModel.activeBannerNotification {
                VStack {
                    BannerNotificationView(
                        title: banner.title,
                        message: banner.message,
                        type: banner.type,
                        onClose: {
                            viewModel.dismissBanner()
                        }
                    )
                    .padding(.horizontal, 16)
                    .padding(.top, 48)
                    .onAppear {
                        DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                            viewModel.dismissBanner()
                        }
                    }
                    .onTapGesture {
                        viewModel.dismissBanner()
                        activeTab = "Home"
                    }
                    Spacer()
                }
                .transition(.move(edge: .top).combined(with: .opacity))
                .zIndex(15)
            }
            
            // Global Toast Message layer
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
            viewModel.refreshAllData(silent: false)
            
            // Periodic sync (every 15 seconds)
            Timer.scheduledTimer(withTimeInterval: 15.0, repeats: true) { _ in
                Task { @MainActor in
                    viewModel.refreshAllData(silent: true)
                }
            }
            
            // Sync dynamic catalog
            Task {
                if let dynamicServices = try? await NetworkManager.shared.getDynamicServices() {
                    ServiceCatalog.shared.updateFromApi(apiData: dynamicServices)
                }
            }
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
                onMarkAsRead: { viewModel.markNotificationAsRead(id: $0) },
                onClose: { isShowingNotifications = false }
            )
        }
    }
}
