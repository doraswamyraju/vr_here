import SwiftUI

struct CustomerDashboardView: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    let userName: String
    let onLogout: () -> Void
    
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
                    onLogoutClick: onLogout
                )
                
                // Tab Contents
                ZStack {
                    Color.bgLight.ignoresSafeArea()
                    
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
                        CustomerAccountTab(viewModel: viewModel, onSelectTab: { activeTab = $0 })
                    default:
                        Text("Unknown Tab")
                    }
                    
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
                            .padding(.bottom, 90) // clear the floating dock
                        }
                    }
                }
                
                // Floating Glow Island Bottom Dock Navigation Bar
                if activeServiceKey == nil {
                    CustomFloatingDock(activeTab: $activeTab, onTabSelected: {
                        if $0 != "Orders" { selectedOrderId = "" }
                    })
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
                    
                    CustomerSidebarView(
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
    }
}

struct AnimatedGradientBorder: View {
    @State private var rotateAngle: Double = 0.0
    
    var body: some View {
        RoundedRectangle(cornerRadius: 24)
            .stroke(
                AngularGradient(
                    gradient: Gradient(colors: [.red, .purple, .blue, .green, .yellow, .red]),
                    center: .center,
                    startAngle: .degrees(rotateAngle),
                    endAngle: .degrees(rotateAngle + 360)
                ),
                lineWidth: 1.5
            )
            .onAppear {
                withAnimation(Animation.linear(duration: 4.0).repeatForever(autoreverses: false)) {
                    rotateAngle = 360.0
                }
            }
    }
}

// --- Redesigned Floating Dock view ---
struct CustomFloatingDock: View {
    @Binding var activeTab: String
    var onTabSelected: (String) -> Void
    
    let tabs = [
        ("Home", "square.grid.2x2", "Me"),
        ("Services", "briefcase", "Services"),
        ("Orders", "bag", "Orders"),
        ("Invoices", "doc.text", "Invoices"),
        ("Vault", "folder", "Docs"),
        ("Account", "person", "Account")
    ]
    
    var body: some View {
        HStack(spacing: 0) {
            ForEach(tabs, id: \.0) { tabId, iconName, label in
                let isSelected = activeTab == tabId
                
                Button(action: {
                    activeTab = tabId
                    onTabSelected(tabId)
                }) {
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

// --- Customer Sidebar Content Drawer ---
struct CustomerSidebarView: View {
    let userName: String
    @Binding var activeTab: String
    let onLogout: () -> Void
    let onClose: () -> Void
    
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header Banner
            VStack(alignment: .leading, spacing: 4) {
                Text("VR Here BMS")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.white)
                Text(userName)
                    .font(.system(size: 12, weight: .bold))
                    .foregroundColor(.white.opacity(0.8))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
            .background(LinearGradient(gradient: Gradient(colors: [.blue, .purple]), startPoint: .topLeading, endPoint: .bottomTrailing))
            
            // Nav Items List
            ScrollView {
                VStack(spacing: 4) {
                    SidebarItem(label: "My Home", iconName: "house", tabId: "Home", activeTab: $activeTab, onClose: onClose)
                    SidebarItem(label: "Master Catalog", iconName: "briefcase", tabId: "Services", activeTab: $activeTab, onClose: onClose)
                    SidebarItem(label: "Manage Orders", iconName: "bag", tabId: "Orders", activeTab: $activeTab, onClose: onClose)
                    SidebarItem(label: "Bills & Receipts", iconName: "doc.text", tabId: "Invoices", activeTab: $activeTab, onClose: onClose)
                    SidebarItem(label: "Document Vault", iconName: "folder", tabId: "Vault", activeTab: $activeTab, onClose: onClose)
                    SidebarItem(label: "Support Tickets", iconName: "headphones", tabId: "Support", activeTab: $activeTab, onClose: onClose)
                    SidebarItem(label: "Profile Account", iconName: "person", tabId: "Account", activeTab: $activeTab, onClose: onClose)
                    
                    Divider()
                        .background(Color.borderLight)
                        .padding(.vertical, 12)
                    
                    // Logout
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

struct SidebarItem: View {
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
