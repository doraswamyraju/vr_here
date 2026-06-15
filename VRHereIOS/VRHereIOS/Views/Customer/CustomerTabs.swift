import SwiftUI

// --- Service Package & Service Detail Models ---
struct ServicePackage: Codable, Identifiable {
    let id: String
    let name: String
    let price: Double
    var isAdjustable: Bool = false
    var isPopular: Bool = false
    let description: String
    let features: [String]
    let creativeButtonText: String
}

struct ServiceDetail: Codable, Identifiable {
    let id: String
    let title: String
    let description: String
    let iconKey: String
    let packages: [ServicePackage]
}

class ServiceCatalog: ObservableObject {
    static let shared = ServiceCatalog()
    
    @Published var items: [String: ServiceDetail] = [
        "pvt-ltd-registration": ServiceDetail(
            id: "pvt-ltd-registration",
            title: "Private Limited Registration",
            description: "Launch your startup with the most credible legal structure. Get Certificate of Incorporation, MOA, AOA, PAN & TAN in 7 days.",
            iconKey: "building",
            packages: [
                ServicePackage(id: "consultation", name: "Expert Consultation", price: 499.0, isAdjustable: true, description: "Start here if you are unsure. Fee fully adjusted against registration.", features: ["30 Mins CA/CS Call", "Business Structure Advice", "Name Availability Check", "Compliance Roadmap"], creativeButtonText: "Consult CA/CS Now"),
                ServicePackage(id: "basic", name: "Basic Plan", price: 5499.0, description: "Essential registration for verified startups.", features: ["Name Approval (RUN)", "COI, PAN & TAN", "MOA & AOA", "2 DIN & 2 DSC", "PF/ESI/MSME registration"], creativeButtonText: "Launch Basic Setup"),
                ServicePackage(id: "advance", name: "Advance Plan", price: 11399.0, isPopular: true, description: "Complete compliance & web presence.", features: ["Everything in Basic", "GST Registration", "Import Export Code (IEC)", "ISO Certification", "Professional Website"], creativeButtonText: "Unlock Premium Growth")
            ]
        ),
        "gst-registration": ServiceDetail(
            id: "gst-registration",
            title: "GST Registration",
            description: "Get your GST number quickly and start filing returns. Essential for businesses with turnover above thresholds.",
            iconKey: "file",
            packages: [
                ServicePackage(id: "consultation", name: "Expert Consultation", price: 499.0, isAdjustable: true, description: "Speak with our tax expert about your GST eligibility and documents.", features: ["30 Mins Call", "Eligibility Check", "Documents List Review", "State-Specific Rules"], creativeButtonText: "Speak with Tax Expert"),
                ServicePackage(id: "basic", name: "Basic Plan", price: 2569.0, description: "Essential GST registration package.", features: ["New GST Registration", "Updating Bank Account", "1st Month GST Return"], creativeButtonText: "Get Registered Now"),
                ServicePackage(id: "expert", name: "Expert Plan", price: 9059.0, isPopular: true, description: "Complete tax compliance suite.", features: ["Everything in Basic", "LUT Filing", "IEC Code Application", "2 Months GST Returns", "Priority Support"], creativeButtonText: "Go Pro Compliance")
            ]
        ),
        "partnership-firm": ServiceDetail(
            id: "partnership-firm",
            title: "Partnership Firm Registration",
            description: "Ideal for small businesses with multiple owners. Shared responsibilities and faster decision making.",
            iconKey: "people",
            packages: [
                ServicePackage(id: "consultation", name: "Expert Consultation", price: 499.0, isAdjustable: true, description: "Discuss partnership clauses and legal requirements with our experts.", features: ["Partnership Deed Advice", "Clause Review", "Tax Implication Call"], creativeButtonText: "Draft Partners Deed"),
                ServicePackage(id: "basic", name: "Basic Plan", price: 4899.0, description: "Essential registration for partnership firms.", features: ["Deed Drafting", "PAN & TAN Applications", "Firm Registration", "Notary Assistance"], creativeButtonText: "Establish Partnership")
            ]
        ),
        "income-tax-return": ServiceDetail(
            id: "income-tax-return",
            title: "Income Tax Return (ITR)",
            description: "End-to-end ITR filing support for salaried, professionals, and businesses with compliance-first review.",
            iconKey: "calculator",
            packages: [
                ServicePackage(id: "consultation", name: "Expert Consultation", price: 499.0, isAdjustable: true, description: "Review your tax computation and self-assessment with a CA.", features: ["Tax Planning Call", "Computation Review", "Deduction Guidance"], creativeButtonText: "Solve Tax Doubts"),
                ServicePackage(id: "itr-filing", name: "ITR Filing", price: 1499.0, isPopular: true, description: "Standard filing service for individuals/professionals.", features: ["ITR 1 to 4 Support", "Computation Review", "Notice Response Guidance"], creativeButtonText: "Secure My Tax Filing")
            ]
        )
    ]
    
    private init() {}
    
    func updateFromApi(apiData: [MobileServiceDetail]) {
        for apiDetail in apiData {
            let pkgs = apiDetail.packages.map { apiPkg in
                ServicePackage(
                    id: apiPkg.id,
                    name: apiPkg.name,
                    price: apiPkg.price,
                    isAdjustable: apiPkg.isAdjustable,
                    isPopular: apiPkg.isPopular,
                    description: apiPkg.description,
                    features: apiPkg.features,
                    creativeButtonText: apiPkg.buttonText
                )
            }
            items[apiDetail.pageId] = ServiceDetail(
                id: apiDetail.pageId,
                title: apiDetail.title,
                description: apiDetail.description,
                iconKey: apiDetail.iconKey,
                packages: pkgs
            )
        }
    }
}

func getIconName(key: String) -> String {
    switch key.lowercased() {
    case "apartment", "building": return "building.2"
    case "description", "file": return "doc.text"
    case "people", "group": return "person.3"
    case "calculate", "calculator": return "calculator"
    case "star": return "star"
    case "phone": return "phone"
    default: return "briefcase"
    }
}

// ==========================================
// 1. CUSTOMER HOME TAB
// ==========================================
struct CustomerHomeTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    let userName: String
    @Binding var searchQuery: String
    let onSelectTab: (String) -> Void
    let onOpenProject: (String) -> Void
    let onOpenLiveService: (String, String) -> Void
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Welcome banner
                VStack(alignment: .leading, spacing: 4) {
                    Text("Hello, \(userName)")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.textDark)
                    Text("Welcome back to your business portal.")
                        .font(.system(size: 13))
                        .foregroundColor(.textMuted)
                }
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Search Bar
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.textMuted)
                    TextField("Search services...", text: $searchQuery)
                        .font(.system(size: 15))
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
                .background(Color.white)
                .cornerRadius(12)
                .shadow(color: Color.black.opacity(0.03), radius: 5, x: 0, y: 2)
                .padding(.horizontal, 20)
                
                // Active project progress cards
                let activeOrders = viewModel.orders.filter { $0.status != "Completed" }
                if !activeOrders.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Active Projects (\(activeOrders.count))")
                            .font(.system(size: 14, weight: .black))
                            .foregroundColor(.textDark)
                            .padding(.horizontal, 20)
                        
                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 16) {
                                ForEach(activeOrders) { order in
                                    Button(action: { onOpenProject(order.id) }) {
                                        VStack(alignment: .leading, spacing: 10) {
                                            HStack {
                                                Text(order.serviceName)
                                                    .font(.system(size: 14, weight: .black))
                                                    .foregroundColor(.textDark)
                                                Spacer()
                                                Text(order.status)
                                                    .font(.system(size: 9, weight: .bold))
                                                    .foregroundColor(.primaryRed)
                                                    .padding(.horizontal, 8)
                                                    .padding(.vertical, 4)
                                                    .background(Color.primaryRed.opacity(0.1))
                                                    .cornerRadius(6)
                                            }
                                            
                                            Text(order.packageName)
                                                .font(.system(size: 11, weight: .medium))
                                                .foregroundColor(.textMuted)
                                            
                                            // Progress Bar
                                            let completedTasks = order.tasks.filter { $0.status == "Completed" }.count
                                            let totalTasks = order.tasks.count
                                            let progress = totalTasks > 0 ? Double(completedTasks) / Double(totalTasks) : 0.0
                                            
                                            VStack(alignment: .leading, spacing: 4) {
                                                GeometryReader { geo in
                                                    ZStack(alignment: .leading) {
                                                        RoundedRectangle(cornerRadius: 3)
                                                            .fill(Color.borderLight)
                                                            .frame(height: 6)
                                                        RoundedRectangle(cornerRadius: 3)
                                                            .fill(Color.primaryRed)
                                                            .frame(width: geo.size.width * CGFloat(progress), height: 6)
                                                    }
                                                }
                                                .frame(height: 6)
                                                
                                                Text("\(Int(progress * 100))% Complete")
                                                    .font(.system(size: 9, weight: .bold))
                                                    .foregroundColor(.textMuted)
                                            }
                                        }
                                        .frame(width: 250)
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
                
                // Services grid
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
                    
                    let filteredItems = ServiceCatalog.shared.items.values.filter {
                        searchQuery.isEmpty ? true : $0.title.lowercased().contains(searchQuery.lowercased())
                    }
                    
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
                
                Spacer().frame(height: 100) // Floating bar spacing
            }
        }
    }
}

// ==========================================
// 2. CUSTOMER SERVICES TAB
// ==========================================
struct CustomerServicesTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    let onSelectTab: (String) -> Void
    let onOpenLiveService: (String, String) -> Void
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("All Compliance Services")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 12) {
                    ForEach(Array(ServiceCatalog.shared.items.values)) { item in
                        Button(action: {
                            onOpenLiveService(item.title, "https://vrhere.in/services/\(item.id)")
                        }) {
                            VStack(alignment: .leading, spacing: 12) {
                                HStack(spacing: 12) {
                                    Image(systemName: getIconName(key: item.iconKey))
                                        .font(.title3)
                                        .foregroundColor(.white)
                                        .frame(width: 38, height: 38)
                                        .background(Color.primaryRed)
                                        .cornerRadius(8)
                                    
                                    Text(item.title)
                                        .font(.system(size: 14, weight: .bold))
                                        .foregroundColor(.textDark)
                                    
                                    Spacer()
                                }
                                
                                Text(item.description)
                                    .font(.system(size: 12))
                                    .foregroundColor(.textMuted)
                                    .lineSpacing(4)
                                
                                HStack {
                                    Text("From \(Int(item.packages.map { $0.price }.min() ?? 499.0)) INR")
                                        .font(.system(size: 11, weight: .black))
                                        .foregroundColor(.primaryRed)
                                    Spacer()
                                    Text("View Details")
                                        .font(.system(size: 11, weight: .bold))
                                        .foregroundColor(.blue)
                                }
                            }
                            .padding(16)
                            .glassCard()
                        }
                        .buttonStyle(PlainButtonStyle())
                    }
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 3. SERVICE DETAIL & PREFILL/CHECKOUT OVERLAY
// ==========================================
struct CustomerServiceDetailScreen: View {
    let serviceKey: String
    let onBackClick: () -> Void
    let onNeedAdviceClick: () -> Void
    let onCheckoutClick: (String, ServicePackage, String, String, String) -> Void
    
    @State private var selectedPackage: ServicePackage? = nil
    @State private var clientName = SessionManager.shared.getUserName()
    @State private var clientEmail = SessionManager.shared.getUserEmail()
    @State private var clientPhone = SessionManager.shared.getPhone()
    @State private var termsAccepted = false
    @State private var isPrefillOpen = false
    
    var body: some View {
        if let service = ServiceCatalog.shared.items[serviceKey] {
            ZStack {
                Color.bgLight.ignoresSafeArea()
                
                VStack(spacing: 0) {
                    // Header Bar
                    HStack {
                        Button(action: onBackClick) {
                            HStack(spacing: 6) {
                                Image(systemName: "chevron.backward")
                                Text("Back")
                            }
                            .font(.system(size: 14, weight: .bold))
                            .foregroundColor(.primaryRed)
                        }
                        Spacer()
                        Text(service.title)
                            .font(.system(size: 16, weight: .black))
                            .foregroundColor(.textDark)
                        Spacer()
                        Spacer().frame(width: 60)
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
                    .background(Color.white)
                    
                    Divider()
                        .background(Color.borderLight)
                    
                    ScrollView {
                        VStack(alignment: .leading, spacing: 20) {
                            VStack(alignment: .leading, spacing: 8) {
                                Text(service.title)
                                    .font(.system(size: 24, weight: .black))
                                    .foregroundColor(.textDark)
                                Text(service.description)
                                    .font(.system(size: 13))
                                    .foregroundColor(.textMuted)
                                    .lineSpacing(4)
                            }
                            .padding(.horizontal, 20)
                            .padding(.top, 16)
                            
                            // Plans
                            VStack(spacing: 16) {
                                ForEach(service.packages) { pkg in
                                    let isSelected = selectedPackage?.id == pkg.id
                                    
                                    VStack(alignment: .leading, spacing: 12) {
                                        HStack {
                                            Text(pkg.name)
                                                .font(.system(size: 16, weight: .bold))
                                                .foregroundColor(.textDark)
                                            Spacer()
                                            if pkg.isPopular {
                                                Text("POPULAR")
                                                    .font(.system(size: 8, weight: .black))
                                                    .foregroundColor(.white)
                                                    .padding(.horizontal, 8)
                                                    .padding(.vertical, 4)
                                                    .background(Color.primaryRed)
                                                    .cornerRadius(4)
                                            }
                                        }
                                        
                                        HStack(alignment: .bottom, spacing: 4) {
                                            Text("₹\(Int(pkg.price))")
                                                .font(.system(size: 24, weight: .black))
                                                .foregroundColor(.textDark)
                                            Text(pkg.isAdjustable ? "(Consultation credit adjusted)" : "+ Taxes")
                                                .font(.system(size: 10, weight: .bold))
                                                .foregroundColor(pkg.isAdjustable ? .blue : .textMuted)
                                                .padding(.bottom, 3)
                                        }
                                        
                                        Text(pkg.description)
                                            .font(.system(size: 12))
                                            .foregroundColor(.textMuted)
                                        
                                        VStack(alignment: .leading, spacing: 6) {
                                            ForEach(pkg.features, id: \.self) { feat in
                                                HStack(spacing: 8) {
                                                    Image(systemName: "checkmark.circle.fill")
                                                        .foregroundColor(.green)
                                                        .font(.system(size: 14))
                                                    Text(feat)
                                                        .font(.system(size: 12, weight: .semibold))
                                                        .foregroundColor(.textDark)
                                                }
                                            }
                                        }
                                        .padding(.vertical, 4)
                                        
                                        Button(action: {
                                            selectedPackage = pkg
                                            isPrefillOpen = true
                                        }) {
                                            Text(pkg.creativeButtonText.uppercased())
                                                .font(.system(size: 11, weight: .black))
                                                .foregroundColor(.white)
                                                .frame(maxWidth: .infinity)
                                                .frame(height: 44)
                                                .background(isSelected ? Color.blue : Color.primaryRed)
                                                .cornerRadius(10)
                                        }
                                        .buttonStyle(ScaleOnPressButtonStyle())
                                    }
                                    .padding(16)
                                    .glassCard()
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 16)
                                            .stroke(isSelected ? Color.blue : Color.clear, lineWidth: 2)
                                    )
                                    .onTapGesture {
                                        selectedPackage = pkg
                                    }
                                }
                            }
                            .padding(.horizontal, 20)
                            
                            // Advice Section
                            VStack(alignment: .center, spacing: 8) {
                                Text("Unsure about your package requirements?")
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Button(action: onNeedAdviceClick) {
                                    Text("CONNECT WITH CA/CS PROFESSIONAL")
                                        .font(.system(size: 11, weight: .black))
                                        .foregroundColor(.blue)
                                }
                            }
                            .frame(maxWidth: .infinity)
                            .padding(20)
                            .glassCard()
                            .padding(.horizontal, 20)
                            
                            Spacer().frame(height: 50)
                        }
                    }
                }
                
                // Prefill details sheet
                if isPrefillOpen, let pkg = selectedPackage {
                    ZStack {
                        Color.black.opacity(0.4)
                            .ignoresSafeArea()
                            .onTapGesture { isPrefillOpen = false }
                        
                        VStack(alignment: .leading, spacing: 16) {
                            Text("Confirm Details")
                                .font(.system(size: 18, weight: .black))
                                .foregroundColor(.textDark)
                            
                            CustomInputField(label: "Contact Name", placeholder: "Your Name", iconName: "person", text: $clientName)
                            CustomInputField(label: "Contact Email", placeholder: "Your Email", iconName: "envelope", text: $clientEmail)
                            CustomInputField(label: "Contact Phone", placeholder: "Your Phone", iconName: "phone", text: $clientPhone)
                            
                            Toggle(isOn: $termsAccepted) {
                                Text("I accept the Terms and Conditions of service.")
                                    .font(.system(size: 12))
                                    .foregroundColor(.textMuted)
                            }
                            
                            Button(action: {
                                isPrefillOpen = false
                                onCheckoutClick(service.title, pkg, clientName, clientEmail, clientPhone)
                            }) {
                                Text("PROCEED TO PAY ₹\(Int(pkg.price))")
                                    .font(.system(size: 13, weight: .black))
                                    .foregroundColor(.white)
                                    .frame(maxWidth: .infinity)
                                    .frame(height: 50)
                                    .background(termsAccepted ? Color.primaryRed : Color.gray)
                                    .cornerRadius(12)
                            }
                            .disabled(!termsAccepted)
                            .buttonStyle(ScaleOnPressButtonStyle())
                        }
                        .padding(24)
                        .background(Color.white)
                        .cornerRadius(20)
                        .padding(20)
                        .shadow(radius: 12)
                    }
                }
            }
        } else {
            Text("Service loading...")
        }
    }
}

// ==========================================
// 4. CUSTOMER ORDERS TAB
// ==========================================
struct CustomerOrdersTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    @Binding var selectedOrderId: String
    let onSelectTab: (String) -> Void
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if selectedOrderId.isEmpty {
                    Text("Your Compliance Orders")
                        .font(.system(size: 18, weight: .black))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                        .padding(.top, 16)
                    
                    if viewModel.orders.isEmpty {
                        VStack(spacing: 8) {
                            Text("No orders registered yet.")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(.textMuted)
                            Button(action: { onSelectTab("Services") }) {
                                Text("View Service Catalog")
                                    .font(.system(size: 13, weight: .black))
                                    .foregroundColor(.primaryRed)
                            }
                        }
                        .frame(maxWidth: .infinity)
                        .padding(40)
                    } else {
                        VStack(spacing: 12) {
                            ForEach(viewModel.orders) { order in
                                Button(action: { selectedOrderId = order.id }) {
                                    VStack(alignment: .leading, spacing: 10) {
                                        HStack {
                                            Text(order.serviceName)
                                                .font(.system(size: 14, weight: .black))
                                                .foregroundColor(.textDark)
                                            Spacer()
                                            Text(order.status)
                                                .font(.system(size: 9, weight: .bold))
                                                .foregroundColor(.primaryRed)
                                                .padding(.horizontal, 8)
                                                .padding(.vertical, 4)
                                                .background(Color.primaryRed.opacity(0.1))
                                                .cornerRadius(6)
                                        }
                                        
                                        HStack {
                                            Text(order.packageName)
                                                .font(.system(size: 12))
                                                .foregroundColor(.textMuted)
                                            Spacer()
                                            Text("₹\(Int(order.price))")
                                                .font(.system(size: 12, weight: .bold))
                                                .foregroundColor(.textDark)
                                        }
                                        
                                        if let emp = order.assignedEmployee {
                                            Text("Assigned to: \(emp.name)")
                                                .font(.system(size: 10, weight: .semibold))
                                                .foregroundColor(.blue)
                                        }
                                    }
                                    .padding(16)
                                    .glassCard()
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                        .padding(.horizontal, 20)
                    }
                } else if let order = viewModel.orders.first(where: { $0.id == selectedOrderId }) {
                    // Order Drilldown View
                    VStack(alignment: .leading, spacing: 16) {
                        Button(action: { selectedOrderId = "" }) {
                            HStack(spacing: 4) {
                                Image(systemName: "chevron.backward")
                                Text("Back to Orders")
                            }
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.primaryRed)
                        }
                        .padding(.top, 16)
                        
                        Text(order.serviceName)
                            .font(.system(size: 20, weight: .black))
                            .foregroundColor(.textDark)
                        
                        // Milestones/Tasks Progress
                        VStack(alignment: .leading, spacing: 12) {
                            Text("Project Milestones")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            
                            ForEach(order.tasks) { task in
                                HStack {
                                    Image(systemName: task.status == "Completed" ? "checkmark.circle.fill" : "circle")
                                        .foregroundColor(task.status == "Completed" ? .green : .textMuted)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(task.title)
                                            .font(.system(size: 12, weight: .bold))
                                            .foregroundColor(.textDark)
                                        Text(task.description)
                                            .font(.system(size: 10))
                                            .foregroundColor(.textMuted)
                                    }
                                    Spacer()
                                    Text(task.status)
                                        .font(.system(size: 9, weight: .bold))
                                        .foregroundColor(task.status == "Completed" ? .green : .orange)
                                }
                                .padding(10)
                                .glassCard()
                            }
                        }
                        
                        // Checklists / Requirements
                        if !order.customerRequirements.isEmpty {
                            VStack(alignment: .leading, spacing: 12) {
                                Text("Action Needed: Compliance Documents")
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                
                                ForEach(order.customerRequirements) { req in
                                    HStack {
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(req.title)
                                                .font(.system(size: 12, weight: .bold))
                                                .foregroundColor(.textDark)
                                            Text(req.description)
                                                .font(.system(size: 10))
                                                .foregroundColor(.textMuted)
                                        }
                                        Spacer()
                                        Text(req.status)
                                            .font(.system(size: 9, weight: .bold))
                                            .foregroundColor(req.status == "Verified" ? .green : .red)
                                    }
                                    .padding(10)
                                    .glassCard()
                                }
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 5. CUSTOMER BILLS & INVOICES TAB
// ==========================================
struct CustomerInvoicesTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Bills & Payment Receipts")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                if viewModel.payments.isEmpty {
                    Text("No billing receipts found.")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                } else {
                    VStack(spacing: 12) {
                        ForEach(viewModel.payments) { pay in
                            VStack(alignment: .leading, spacing: 10) {
                                HStack {
                                    Text(pay.serviceName)
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    Text(pay.status)
                                        .font(.system(size: 9, weight: .bold))
                                        .foregroundColor(.white)
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .background(pay.status == "Completed" ? Color.green : Color.orange)
                                        .cornerRadius(6)
                                }
                                
                                Text(pay.packageName)
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                                
                                HStack {
                                    Text("ID: \(pay.paymentId)")
                                        .font(.system(size: 10))
                                        .foregroundColor(.textMuted)
                                    Spacer()
                                    Text("₹\(Int(pay.amount))")
                                        .font(.system(size: 14, weight: .black))
                                        .foregroundColor(.textDark)
                                }
                            }
                            .padding(14)
                            .glassCard()
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 6. CUSTOMER VAULT TAB
// ==========================================
struct CustomerVaultTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    @Environment(\.openURL) private var openURL
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Document Vault")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                let documents = viewModel.orders.flatMap { $0.clientDocuments + $0.adminDocuments }
                
                if documents.isEmpty {
                    Text("Your uploaded certificates will display here once verified.")
                        .font(.system(size: 13))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                } else {
                    VStack(spacing: 12) {
                        ForEach(documents) { doc in
                            HStack {
                                Image(systemName: "doc.fill")
                                    .foregroundColor(.primaryRed)
                                    .font(.title2)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(doc.name)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Text(doc.uploadedAt)
                                        .font(.system(size: 9))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                                Button(action: {
                                    if let url = URL(string: doc.url) {
                                        openURL(url)
                                    }
                                }) {
                                    Image(systemName: "arrow.down.circle")
                                        .font(.title3)
                                        .foregroundColor(.blue)
                                }
                            }
                            .padding(12)
                            .glassCard()
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 7. CUSTOMER SUPPORT TAB
// ==========================================
struct CustomerSupportTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Support Communication Desk")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                // Raise new ticket card
                VStack(alignment: .leading, spacing: 12) {
                    Text("Open New Query Ticket")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textDark)
                    
                    CustomInputField(label: "Subject", placeholder: "Short summary", iconName: "tag", text: $viewModel.ticketSubject)
                    CustomInputField(label: "Description", placeholder: "Detail issues", iconName: "doc.text", text: $viewModel.ticketDescription)
                    
                    Button(action: {
                        viewModel.createSupportTicket()
                    }) {
                        Text("SUBMIT TICKET QUERY")
                            .font(.system(size: 11, weight: .black))
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .frame(height: 44)
                            .background(Color.primaryRed)
                            .cornerRadius(10)
                    }
                    .buttonStyle(ScaleOnPressButtonStyle())
                }
                .padding(16)
                .glassCard()
                .padding(.horizontal, 20)
                
                // History of tickets
                if !viewModel.tickets.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Ticket Logs")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.textDark)
                            .padding(.horizontal, 20)
                        
                        ForEach(viewModel.tickets) { ticket in
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Text(ticket.subject)
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    Text(ticket.status)
                                        .font(.system(size: 9, weight: .bold))
                                        .foregroundColor(ticket.status == "Open" ? .green : .gray)
                                }
                                Text(ticket.description)
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                                
                                ForEach(ticket.messages) { msg in
                                    HStack {
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(msg.sender?.name ?? "System Executive")
                                                .font(.system(size: 9, weight: .bold))
                                                .foregroundColor(.blue)
                                            Text(msg.message)
                                                .font(.system(size: 11))
                                                .foregroundColor(.textDark)
                                        }
                                        Spacer()
                                    }
                                    .padding(8)
                                    .background(Color.bgLight)
                                    .cornerRadius(8)
                                }
                                
                                // Reply block
                                HStack {
                                    TextField("Type reply...", text: $viewModel.ticketReplyMessage)
                                        .font(.system(size: 12))
                                    Button(action: {
                                        viewModel.replyToTicket(ticketId: ticket.id)
                                    }) {
                                        Image(systemName: "paperplane.fill")
                                            .foregroundColor(.blue)
                                    }
                                }
                                .padding(8)
                                .background(Color.bgInput)
                                .cornerRadius(8)
                            }
                            .padding(14)
                            .glassCard()
                        }
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 8. CUSTOMER ACCOUNT TAB
// ==========================================
struct CustomerAccountTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    let onSelectTab: (String) -> Void
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Account Settings")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(alignment: .leading, spacing: 12) {
                    Text("User Profile Information")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(.textDark)
                    
                    HStack {
                        Text("Name:")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textMuted)
                        Spacer()
                        Text(SessionManager.shared.getUserName())
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textDark)
                    }
                    
                    HStack {
                        Text("Email:")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textMuted)
                        Spacer()
                        Text(SessionManager.shared.getUserEmail())
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textDark)
                    }
                    
                    HStack {
                        Text("Role:")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textMuted)
                        Spacer()
                        Text(SessionManager.shared.getUserRole().capitalized)
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textDark)
                    }
                }
                .padding(16)
                .glassCard()
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
}
