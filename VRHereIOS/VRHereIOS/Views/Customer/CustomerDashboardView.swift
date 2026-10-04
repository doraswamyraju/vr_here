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
    @State private var isFloatingMenuExpanded = false
    @State private var isLetsTrackChatOpen = false
    
    private var resolvedCustomerName: String {
        if let name = viewModel.userProfile?.name, !name.isEmpty { return name }
        if !userName.isEmpty { return userName }
        return SessionManager.shared.getUserName()
    }
    
    private var resolvedCustomerEmail: String {
        if let email = viewModel.userProfile?.email, !email.isEmpty { return email }
        return SessionManager.shared.getUserEmail()
    }
    
    private var resolvedCustomerPhone: String {
        if let phone = viewModel.userProfile?.phone, !phone.isEmpty { return phone }
        return SessionManager.shared.getPhone()
    }
    
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
                    showBack: false,
                    onBackClick: { withAnimation { activeTab = "Home" } },
                    onLogoClick: { withAnimation { activeTab = "Home"; selectedOrderId = "" } },
                    showNotifications: true,
                    hasUnreadNotifications: viewModel.notifications.contains(where: { !$0.isRead }),
                    unreadNotificationsCount: viewModel.notifications.filter { !$0.isRead }.count,
                    onNotificationsClick: { isShowingNotifications = true },
                    userProfilePhoto: (viewModel.userProfile?.profilePhoto ?? SessionManager.shared.getProfilePhoto()).isEmpty ? nil : (viewModel.userProfile?.profilePhoto ?? SessionManager.shared.getProfilePhoto()),
                    userName: userName,
                    onProfileClick: { withAnimation { activeTab = "Account" } }
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
                                    if !key.isEmpty && !key.hasPrefix("http") {
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
                                    if !key.isEmpty && !key.hasPrefix("http") {
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
                        case "Referrals":
                            CustomerReferralTab(viewModel: viewModel)
                        case "Invoices":
                            CustomerInvoicesTab(viewModel: viewModel)
                        case "Vault":
                            CustomerVaultTab(viewModel: viewModel)
                        case "Support":
                            CustomerSupportTab(viewModel: viewModel)
                        case "Account":
                            CustomerAccountTab(viewModel: viewModel, onSelectTab: { activeTab = $0 }, onDeleteAccount: onDeleteAccount)
                        case "Bookkeeping":
                            CustomerBookkeepingTab(viewModel: viewModel)
                        default:
                            Text("Unknown Tab")
                        }
                    }
                    .ignoresSafeArea(edges: .bottom)
                    
                    // Floating Expandable Action Stack matching Android
                    VStack(spacing: 12) {
                        Spacer()
                        HStack {
                            Spacer()
                            VStack(alignment: .trailing, spacing: 10) {
                                
                                // Expanded Action Options
                                if isFloatingMenuExpanded {
                                    VStack(alignment: .trailing, spacing: 10) {
                                        
                                        // Option 1: Live Support Chat
                                        Button(action: {
                                            isFloatingMenuExpanded = false
                                            isLetsTrackChatOpen = true
                                        }) {
                                            HStack(spacing: 8) {
                                                Text("Live Chat")
                                                    .font(.system(size: 10, weight: .black))
                                                    .foregroundColor(.white)
                                                    .padding(.horizontal, 8)
                                                    .padding(.vertical, 4)
                                                    .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                                                    .cornerRadius(8)
                                                
                                                ZStack {
                                                    Circle()
                                                        .fill(Color(red: 244/255, green: 63/255, blue: 94/255))
                                                        .frame(width: 44, height: 44)
                                                    Image(systemName: "bubble.left.and.bubble.right.fill")
                                                        .font(.system(size: 16))
                                                        .foregroundColor(.white)
                                                }
                                                .shadow(color: Color.black.opacity(0.15), radius: 4, y: 2)
                                            }
                                        }
                                        .buttonStyle(ScaleOnPressButtonStyle())
                                        .transition(.move(edge: .bottom).combined(with: .opacity))
                                        
                                        // Option 2: WhatsApp Chat
                                        Button(action: {
                                            isFloatingMenuExpanded = false
                                            if let url = URL(string: "https://wa.me/918008530606?text=Hi%20VR%20HERE%20Team,%20I%20am%20chatting%20from%20the%20Customer%20Portal.") {
                                                #if os(iOS)
                                                if UIApplication.shared.canOpenURL(url) {
                                                    UIApplication.shared.open(url)
                                                } else {
                                                    openURL(url)
                                                }
                                                #else
                                                openURL(url)
                                                #endif
                                            }
                                        }) {
                                            HStack(spacing: 8) {
                                                Text("WhatsApp Chat")
                                                    .font(.system(size: 10, weight: .black))
                                                    .foregroundColor(.white)
                                                    .padding(.horizontal, 8)
                                                    .padding(.vertical, 4)
                                                    .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                                                    .cornerRadius(8)
                                                
                                                ZStack {
                                                    Circle()
                                                        .fill(Color(red: 16/255, green: 185/255, blue: 129/255))
                                                        .frame(width: 44, height: 44)
                                                    Image(systemName: "message.fill")
                                                        .font(.system(size: 16))
                                                        .foregroundColor(.white)
                                                }
                                                .shadow(color: Color.black.opacity(0.15), radius: 4, y: 2)
                                            }
                                        }
                                        .buttonStyle(ScaleOnPressButtonStyle())
                                        .transition(.move(edge: .bottom).combined(with: .opacity))
                                        
                                        // Option 3: Call Helpline
                                        Button(action: {
                                            isFloatingMenuExpanded = false
                                            if let url = URL(string: "tel:918008530606") {
                                                openURL(url)
                                            }
                                        }) {
                                            HStack(spacing: 8) {
                                                Text("Call Helpline")
                                                    .font(.system(size: 10, weight: .black))
                                                    .foregroundColor(.white)
                                                    .padding(.horizontal, 8)
                                                    .padding(.vertical, 4)
                                                    .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                                                    .cornerRadius(8)
                                                
                                                ZStack {
                                                    Circle()
                                                        .fill(Color(red: 37/255, green: 99/255, blue: 235/255))
                                                        .frame(width: 44, height: 44)
                                                    Image(systemName: "phone.fill")
                                                        .font(.system(size: 16))
                                                        .foregroundColor(.white)
                                                }
                                                .shadow(color: Color.black.opacity(0.15), radius: 4, y: 2)
                                            }
                                        }
                                        .buttonStyle(ScaleOnPressButtonStyle())
                                        .transition(.move(edge: .bottom).combined(with: .opacity))
                                        
                                        // Option 4: Raise Support Ticket
                                        Button(action: {
                                            isFloatingMenuExpanded = false
                                            activeTab = "Support"
                                        }) {
                                            HStack(spacing: 8) {
                                                Text("Raise Support Ticket")
                                                    .font(.system(size: 10, weight: .black))
                                                    .foregroundColor(.white)
                                                    .padding(.horizontal, 8)
                                                    .padding(.vertical, 4)
                                                    .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                                                    .cornerRadius(8)
                                                
                                                ZStack {
                                                    Circle()
                                                        .fill(Color(red: 15/255, green: 23/255, blue: 42/255))
                                                        .frame(width: 44, height: 44)
                                                    Image(systemName: "headphones")
                                                        .font(.system(size: 16))
                                                        .foregroundColor(.white)
                                                }
                                                .shadow(color: Color.black.opacity(0.15), radius: 4, y: 2)
                                            }
                                        }
                                        .buttonStyle(ScaleOnPressButtonStyle())
                                        .transition(.move(edge: .bottom).combined(with: .opacity))
                                    }
                                }
                                
                                // Main Floating Action Button Trigger
                                Button(action: {
                                    withAnimation(.spring(response: 0.35, dampingFraction: 0.7)) {
                                        isFloatingMenuExpanded.toggle()
                                    }
                                }) {
                                    ZStack {
                                        Circle()
                                            .fill(
                                                LinearGradient(
                                                    colors: [Color(red: 220/255, green: 38/255, blue: 38/255), Color(red: 225/255, green: 29/255, blue: 72/255)],
                                                    startPoint: .topLeading,
                                                    endPoint: .bottomTrailing
                                                )
                                            )
                                            .frame(width: 54, height: 54)
                                            .shadow(color: Color(red: 220/255, green: 38/255, blue: 38/255).opacity(0.45), radius: 8, x: 0, y: 4)
                                        
                                        Image(systemName: isFloatingMenuExpanded ? "xmark" : "headphones")
                                            .font(.system(size: 22, weight: .bold))
                                            .foregroundColor(.white)
                                            .rotationEffect(.degrees(isFloatingMenuExpanded ? 90 : 0))
                                    }
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                            }
                            .padding(.trailing, 18)
                            .padding(.bottom, 95) // Clear the floating dock
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
            
            // Drawer Menu overlay (100% Matching Android Sidebar)
            if isSidebarOpen {
                ZStack(alignment: .leading) {
                    Color.black.opacity(0.55)
                        .ignoresSafeArea()
                        .onTapGesture {
                            withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) {
                                isSidebarOpen = false
                            }
                        }
                    
                    BMSCustomerSidebar(
                        userName: userName,
                        companyName: SessionManager.shared.getCompanyName(),
                        profilePhoto: (viewModel.userProfile?.profilePhoto ?? SessionManager.shared.getProfilePhoto()).isEmpty ? nil : (viewModel.userProfile?.profilePhoto ?? SessionManager.shared.getProfilePhoto()),
                        activeOrdersCount: viewModel.orders.filter { $0.status.lowercased() != "completed" }.count,
                        activeTab: $activeTab,
                        onLogout: onLogout,
                        onClose: {
                            withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) {
                                isSidebarOpen = false
                            }
                        }
                    )
                    .transition(.move(edge: .leading))
                }
                .zIndex(50)
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
            if let order = viewModel.checkoutOrderData ?? checkoutOrderData, let payload = viewModel.checkoutPayloadData ?? checkoutPayloadData {
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
                        viewModel.checkoutOrderData = nil
                        viewModel.checkoutPayloadData = nil
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
                        viewModel.checkoutOrderData = nil
                        viewModel.checkoutPayloadData = nil
                        checkoutOrderData = nil
                        checkoutPayloadData = nil
                        toastMsg = "Payment failed: \(errorMsg)"
                        showingToast = true
                    },
                    onClose: {
                        viewModel.checkoutOrderData = nil
                        viewModel.checkoutPayloadData = nil
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
            
            // Live Real-Time Customer Chat Dialog (100% Matching Android LetsTrackChatDialog)
            if isLetsTrackChatOpen {
                LetsTrackChatDialog(
                    isOpen: $isLetsTrackChatOpen,
                    customerName: resolvedCustomerName,
                    customerEmail: resolvedCustomerEmail,
                    customerPhone: resolvedCustomerPhone
                )
                .zIndex(60)
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
                onMarkAllAsRead: { viewModel.markAllNotificationsAsRead() },
                onNotificationClick: { notif in
                    viewModel.markNotificationAsRead(id: notif.id)
                    isShowingNotifications = false
                    
                    let typeLower = notif.type.lowercased()
                    let titleLower = notif.title.lowercased()
                    let msgLower = notif.message.lowercased()
                    
                    withAnimation {
                        if typeLower == "order" || titleLower.contains("order") || msgLower.contains("order") {
                            if let matchedOrder = viewModel.orders.first(where: { ord in
                                let idSuffix = String(ord.id.suffix(8))
                                return (!idSuffix.isEmpty && (notif.message.localizedCaseInsensitiveContains(idSuffix) || notif.title.localizedCaseInsensitiveContains(idSuffix))) ||
                                       notif.message.localizedCaseInsensitiveContains(ord.id) ||
                                       notif.title.localizedCaseInsensitiveContains(ord.id) ||
                                       (!ord.serviceName.isEmpty && (notif.title.localizedCaseInsensitiveContains(ord.serviceName) || notif.message.localizedCaseInsensitiveContains(ord.serviceName)))
                            }) {
                                selectedOrderId = matchedOrder.id
                            }
                            activeTab = "Orders"
                        } else if typeLower == "ticket" || titleLower.contains("ticket") || msgLower.contains("ticket") || titleLower.contains("support") || msgLower.contains("support") {
                            activeTab = "Support"
                        } else if typeLower == "payment" || titleLower.contains("invoice") || msgLower.contains("invoice") || titleLower.contains("payment") || msgLower.contains("payment") {
                            activeTab = "Invoices"
                        } else if typeLower.contains("bookkeeping") || titleLower.contains("bookkeeping") || msgLower.contains("bookkeeping") {
                            activeTab = "Bookkeeping"
                        } else if typeLower.contains("vault") || titleLower.contains("vault") || titleLower.contains("document") || msgLower.contains("document") {
                            activeTab = "Vault"
                        } else if typeLower.contains("referral") || titleLower.contains("referral") {
                            activeTab = "Referrals"
                        } else {
                            activeTab = "Home"
                        }
                    }
                },
                onClose: { isShowingNotifications = false }
            )
        }
    }
}
