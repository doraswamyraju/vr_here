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
                            CustomerAccountTab(viewModel: viewModel, onSelectTab: { activeTab = $0 })
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
                        CustomFloatingDock(activeTab: $activeTab, onTabSelected: {
                            if $0 != "Orders" { selectedOrderId = "" }
                        })
                    }
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
    
    private let menuItems = [
        ("Home", "square.grid.2x2", "Dashboard"),
        ("Services", "briefcase", "Services Catalog"),
        ("Orders", "bag", "My Orders"),
        ("Invoices", "doc.text", "Invoices"),
        ("Vault", "folder", "Vault Documents"),
        ("Support", "headphones", "Help & Support"),
        ("Account", "person", "My Profile")
    ]
    
    var body: some View {
        let initials = userName.components(separatedBy: " ")
            .compactMap { $0.first }
            .map { String($0).uppercased() }
            .prefix(2)
            .joined()
        
        VStack(alignment: .leading, spacing: 0) {
            // 1. Sidebar Header (Brand Logo + Close Button)
            HStack {
                HStack(spacing: 10) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 10)
                            .fill(Color(red: 99/255, green: 102/255, blue: 241/255))
                            .frame(width: 36, height: 36)
                        Text("VR")
                            .font(.system(size: 14, weight: .black))
                            .foregroundColor(.white)
                    }
                    
                    Text("VRHERE BMS")
                        .font(.system(size: 16, weight: .black))
                        .foregroundColor(.white)
                        .tracking(-0.3)
                }
                
                Spacer()
                
                Button(action: onClose) {
                    Image(systemName: "xmark")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(.white.opacity(0.8))
                        .frame(width: 36, height: 36)
                        .background(Color.white.opacity(0.05))
                        .clipShape(Circle())
                }
                .buttonStyle(PlainButtonStyle())
            }
            .padding(.horizontal, 24)
            .padding(.top, 60)
            .padding(.bottom, 20)
            
            Divider().background(Color.white.opacity(0.08))
            
            // 2. Profile Details Section (Premium glassmorphism wrapper + initials avatar)
            HStack(spacing: 14) {
                ZStack {
                    Circle()
                        .fill(LinearGradient(gradient: Gradient(colors: [Color(red: 99/255, green: 102/255, blue: 241/255), Color(red: 139/255, green: 92/255, blue: 246/255)]), startPoint: .topLeading, endPoint: .bottomTrailing))
                        .frame(width: 48, height: 48)
                        .overlay(Circle().stroke(Color.white.opacity(0.2), lineWidth: 2))
                    
                    Text(initials.isEmpty ? "C" : initials)
                        .font(.system(size: 16, weight: .black))
                        .foregroundColor(.white)
                }
                
                VStack(alignment: .leading, spacing: 2) {
                    Text(userName)
                        .font(.system(size: 15, weight: .bold))
                        .foregroundColor(.white)
                        .lineLimit(1)
                    Text("Customer Account")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                }
                Spacer()
            }
            .padding(16)
            .background(Color.white.opacity(0.02))
            .cornerRadius(20)
            .overlay(RoundedRectangle(cornerRadius: 20).stroke(Color.white.opacity(0.04), lineWidth: 1))
            .padding(.horizontal, 16)
            .padding(.vertical, 20)
            
            Divider().background(Color.white.opacity(0.08))
            
            // 3. Navigation List
            ScrollView {
                VStack(spacing: 8) {
                    ForEach(menuItems, id: \.0) { tabId, icon, label in
                        SidebarItem(label: label, iconName: icon, tabId: tabId, activeTab: $activeTab, onClose: onClose)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 16)
            }
            
            Divider().background(Color.white.opacity(0.08))
            
            // 4. Logout Action Footer
            Button(action: {
                onClose()
                onLogout()
            }) {
                HStack(spacing: 16) {
                    Image(systemName: "rectangle.portrait.and.arrow.right")
                        .font(.system(size: 20))
                        .foregroundColor(Color(red: 239/255, green: 68/255, blue: 68/255))
                    Text("Sign Out")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(Color(red: 239/255, green: 68/255, blue: 68/255))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 16)
                .padding(.vertical, 16)
            }
            .buttonStyle(PlainButtonStyle())
            .padding(.horizontal, 16)
            .padding(.bottom, 30)
        }
        .frame(width: 300)
        .background(Color(red: 15/255, green: 23/255, blue: 42/255)) // darkSlate #0F172A
        .edgesIgnoringSafeArea(.all)
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
            HStack(spacing: 16) {
                Image(systemName: iconName + (isSelected ? ".fill" : ""))
                    .font(.system(size: 18))
                    .foregroundColor(isSelected ? Color(red: 129/255, green: 140/255, blue: 248/255) : Color(red: 148/255, green: 163/255, blue: 184/255))
                    .frame(width: 24)
                Text(label)
                    .font(.system(size: 14, weight: isSelected ? .bold : .medium))
                    .foregroundColor(isSelected ? .white : Color(red: 148/255, green: 163/255, blue: 184/255))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16)
            .frame(height: 48)
            .background(isSelected ? Color(red: 99/255, green: 102/255, blue: 241/255).opacity(0.15) : Color.clear)
            .cornerRadius(12)
        }
        .buttonStyle(PlainButtonStyle())
    }
}
