import SwiftUI

struct CustomerServiceDetailScreen: View {
    let serviceKey: String
    let onBackClick: () -> Void
    let onNeedAdviceClick: () -> Void
    let onCheckoutClick: (String, ServicePackage, String, String, String) -> Void
    
    @State private var dynamicPage: ServicePageResponseModel? = nil
    @State private var isLoading: Bool = true
    @State private var selectedPackage: ServicePackage? = nil
    @State private var expandedFaqId: String? = nil
    @State private var clientName = SessionManager.shared.getUserName()
    @State private var clientEmail = SessionManager.shared.getUserEmail()
    @State private var clientPhone = SessionManager.shared.getPhone()
    @State private var termsAccepted = true
    @State private var isPrefillOpen = false
    
    // Resolve fallback service from catalog if API is loading/offline
    private var fallbackService: ServiceDetail? {
        ServiceCatalog.shared.items[serviceKey]
    }
    
    private var serviceTitle: String {
        dynamicPage?.title ?? fallbackService?.title ?? "Business Registration"
    }
    
    private var serviceDescription: String {
        dynamicPage?.description ?? fallbackService?.description ?? "End-to-end legal and compliance services by verified CAs and CS professionals."
    }
    
    private var servicePackages: [ServicePackage] {
        if let dynamicPkgs = dynamicPage?.packages, !dynamicPkgs.isEmpty {
            return dynamicPkgs
        }
        return fallbackService?.packages ?? []
    }
    
    private var statsList: [ServiceStatModel] {
        if let stats = dynamicPage?.stats, !stats.isEmpty {
            return stats
        }
        return [
            ServiceStatModel(value: "7 Days", label: "Avg Turnaround"),
            ServiceStatModel(value: "5,000+", label: "Happy Clients"),
            ServiceStatModel(value: "4.9/5", label: "Client Rating"),
            ServiceStatModel(value: "100%", label: "Online & Paperless")
        ]
    }
    
    private var stepsList: [ServiceStepModel] {
        if let steps = dynamicPage?.steps, !steps.isEmpty {
            return steps
        }
        return [
            ServiceStepModel(number: "01", title: "Document Collection", desc: "Submit KYC documents online in our secure customer portal.", badge: "Step 1"),
            ServiceStepModel(number: "02", title: "Name & Legal Clearance", desc: "Expert search and formal government portal filing.", badge: "Step 2"),
            ServiceStepModel(number: "03", title: "Drafting & Verification", desc: "Deed/MOA drafting and statutory review by CA/CS.", badge: "Step 3"),
            ServiceStepModel(number: "04", title: "Final Certificate & Delivery", desc: "Official certificate, PAN, TAN and registration kit issued.", badge: "Step 4")
        ]
    }
    
    private var faqsList: [ServiceFaqModel] {
        dynamicPage?.faqs ?? [
            ServiceFaqModel(q: "How long does the entire registration process take?", a: "Standard turnaround is 5 to 7 business days subject to government department approval queues."),
            ServiceFaqModel(q: "Are government fees included in the packages?", a: "Packages clearly specify whether government fees, stamp duties, and digital signature certificates (DSC) are included or calculated per state."),
            ServiceFaqModel(q: "Can I adjust the consultation fee against the final package?", a: "Yes! If you book an expert CA/CS consultation at ₹499, the full ₹499 is credited and deducted when you upgrade to any full registration plan.")
        ]
    }
    
    var body: some View {
        ZStack {
            Color(red: 248/255, green: 250/255, blue: 252/255)
                .ignoresSafeArea()
            
            VStack(spacing: 0) {
                // Navigation Bar
                HStack {
                    Button(action: onBackClick) {
                        HStack(spacing: 6) {
                            Image(systemName: "chevron.backward")
                            Text("Catalog")
                        }
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                    }
                    
                    Spacer()
                    
                    Text(serviceTitle)
                        .font(.system(size: 15, weight: .black))
                        .foregroundColor(.textDark)
                        .lineLimit(1)
                        .truncationMode(.tail)
                        .frame(maxWidth: 200)
                    
                    Spacer()
                    
                    Button(action: onNeedAdviceClick) {
                        Image(systemName: "phone.bubble.left.fill")
                            .font(.system(size: 16))
                            .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
                .background(Color.white)
                .shadow(color: Color.black.opacity(0.03), radius: 3, y: 2)
                
                ScrollView(showsIndicators: false) {
                    VStack(alignment: .leading, spacing: 20) {
                        
                        // 1. Hero Card
                        VStack(alignment: .leading, spacing: 14) {
                            HStack {
                                HStack(spacing: 5) {
                                    Circle()
                                        .fill(Color.green)
                                        .frame(width: 7, height: 7)
                                    Text(dynamicPage?.hero?.badgeText ?? "MCA & GOVT VERIFIED")
                                        .font(.system(size: 10, weight: .black))
                                        .foregroundColor(.white)
                                }
                                .padding(.horizontal, 10)
                                .padding(.vertical, 4)
                                .background(Color.white.opacity(0.15))
                                .cornerRadius(20)
                                
                                Spacer()
                                
                                Text("100% Online")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(Color(red: 165/255, green: 180/255, blue: 252/255))
                            }
                            
                            Text(dynamicPage?.hero?.title ?? serviceTitle)
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                                .lineSpacing(2)
                            
                            Text(dynamicPage?.hero?.subtitle ?? serviceDescription)
                                .font(.system(size: 13, weight: .medium))
                                .foregroundColor(Color(red: 224/255, green: 231/255, blue: 255/255))
                                .lineSpacing(3)
                            
                            // Expert Consultation Quick Pill
                            Button(action: {
                                triggerConsultation()
                            }) {
                                HStack {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("Need Pre-Registration Advice?")
                                            .font(.system(size: 11, weight: .bold))
                                            .foregroundColor(Color(red: 224/255, green: 231/255, blue: 255/255))
                                        Text("30-Min CA/CS Call @ ₹499 (100% Adjusted)")
                                            .font(.system(size: 12, weight: .black))
                                            .foregroundColor(.white)
                                    }
                                    Spacer()
                                    Image(systemName: "arrow.right.circle.fill")
                                        .font(.system(size: 20))
                                        .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                }
                                .padding(12)
                                .background(Color.white.opacity(0.12))
                                .cornerRadius(14)
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                        .padding(20)
                        .background(
                            LinearGradient(
                                colors: [Color(red: 15/255, green: 23/255, blue: 42/255), Color(red: 49/255, green: 46/255, blue: 129/255), Color(red: 30/255, green: 27/255, blue: 75/255)],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                        .cornerRadius(24)
                        .padding(.horizontal, 16)
                        .padding(.top, 12)
                        
                        // 2. Key Metrics Bar
                        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
                            ForEach(statsList) { stat in
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(stat.value ?? "")
                                        .font(.system(size: 17, weight: .black))
                                        .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                    Text(stat.label ?? "")
                                        .font(.system(size: 11, weight: .bold))
                                        .foregroundColor(.textMuted)
                                }
                                .padding(12)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.white)
                                .cornerRadius(14)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 14)
                                        .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                                )
                            }
                        }
                        .padding(.horizontal, 16)
                        
                        // 3. Pricing Packages Header
                        VStack(alignment: .leading, spacing: 4) {
                            Text("CHOOSE YOUR PLAN")
                                .font(.system(size: 11, weight: .black))
                                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                .tracking(1.0)
                            Text("Transparent Pricing & Deliverables")
                                .font(.system(size: 18, weight: .black))
                                .foregroundColor(.textDark)
                        }
                        .padding(.horizontal, 16)
                        
                        // 4. Packages List
                        VStack(spacing: 16) {
                            ForEach(servicePackages) { pkg in
                                let isSelected = selectedPackage?.id == pkg.id
                                
                                VStack(alignment: .leading, spacing: 14) {
                                    HStack {
                                        Text(pkg.name)
                                            .font(.system(size: 17, weight: .bold))
                                            .foregroundColor(.textDark)
                                        
                                        Spacer()
                                        
                                        if pkg.isPopular {
                                            Text("MOST POPULAR")
                                                .font(.system(size: 9, weight: .black))
                                                .foregroundColor(.white)
                                                .padding(.horizontal, 8)
                                                .padding(.vertical, 4)
                                                .background(
                                                    LinearGradient(
                                                        colors: [Color(red: 244/255, green: 63/255, blue: 94/255), Color(red: 234/255, green: 88/255, blue: 12/255)],
                                                        startPoint: .leading,
                                                        endPoint: .trailing
                                                    )
                                                )
                                                .cornerRadius(6)
                                        }
                                    }
                                    
                                    HStack(alignment: .firstTextBaseline, spacing: 4) {
                                        Text("₹\(Int(pkg.price))")
                                            .font(.system(size: 26, weight: .black))
                                            .foregroundColor(.textDark)
                                        Text(pkg.isAdjustable ? "(Consultation fee credited)" : "+ Govt Fees & Taxes")
                                            .font(.system(size: 11, weight: .bold))
                                            .foregroundColor(pkg.isAdjustable ? Color.blue : .textMuted)
                                    }
                                    
                                    if !pkg.description.isEmpty {
                                        Text(pkg.description)
                                            .font(.system(size: 12, weight: .medium))
                                            .foregroundColor(.textMuted)
                                            .lineSpacing(2)
                                    }
                                    
                                    Divider()
                                        .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                                    
                                    // Features checklist
                                    VStack(alignment: .leading, spacing: 8) {
                                        ForEach(pkg.features, id: \.self) { feat in
                                            HStack(alignment: .top, spacing: 8) {
                                                Image(systemName: "checkmark.circle.fill")
                                                    .foregroundColor(Color.green)
                                                    .font(.system(size: 13))
                                                    .padding(.top, 1)
                                                Text(feat)
                                                    .font(.system(size: 12, weight: .semibold))
                                                    .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                                                    .fixedSize(horizontal: false, vertical: true)
                                            }
                                        }
                                    }
                                    
                                    // Action Button
                                    Button(action: {
                                        selectPackageAndOpenCheckout(pkg)
                                    }) {
                                        HStack {
                                            Text(pkg.creativeButtonText.isEmpty ? "SELECT & PROCEED" : pkg.creativeButtonText.uppercased())
                                                .font(.system(size: 12, weight: .black))
                                            Image(systemName: "arrow.right")
                                                .font(.system(size: 11, weight: .bold))
                                        }
                                        .foregroundColor(.white)
                                        .frame(maxWidth: .infinity)
                                        .frame(height: 46)
                                        .background(
                                            isSelected
                                                ? LinearGradient(colors: [Color(red: 99/255, green: 102/255, blue: 241/255), Color(red: 79/255, green: 70/255, blue: 229/255)], startPoint: .leading, endPoint: .trailing)
                                                : LinearGradient(colors: [Color(red: 15/255, green: 23/255, blue: 42/255), Color(red: 30/255, green: 41/255, blue: 59/255)], startPoint: .leading, endPoint: .trailing)
                                        )
                                        .cornerRadius(12)
                                        .shadow(color: Color.black.opacity(0.08), radius: 6, y: 3)
                                    }
                                    .buttonStyle(PlainButtonStyle())
                                }
                                .padding(18)
                                .background(Color.white)
                                .cornerRadius(20)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 20)
                                        .stroke(isSelected ? Color(red: 99/255, green: 102/255, blue: 241/255) : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: isSelected ? 2 : 1)
                                )
                                .onTapGesture {
                                    selectPackageAndOpenCheckout(pkg)
                                }
                            }
                        }
                        .padding(.horizontal, 16)
                        
                        // 5. How It Works Steps
                        VStack(alignment: .leading, spacing: 14) {
                            Text("STEP-BY-STEP PROCESS")
                                .font(.system(size: 11, weight: .black))
                                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                .tracking(1.0)
                            
                            VStack(spacing: 10) {
                                ForEach(stepsList) { step in
                                    HStack(alignment: .top, spacing: 12) {
                                        Text(step.number ?? "•")
                                            .font(.system(size: 14, weight: .black))
                                            .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                            .frame(width: 32, height: 32)
                                            .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                                            .cornerRadius(10)
                                        
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(step.title ?? "")
                                                .font(.system(size: 13, weight: .bold))
                                                .foregroundColor(.textDark)
                                            Text(step.desc ?? "")
                                                .font(.system(size: 11, weight: .medium))
                                                .foregroundColor(.textMuted)
                                                .lineSpacing(2)
                                        }
                                        Spacer()
                                    }
                                    .padding(12)
                                    .background(Color.white)
                                    .cornerRadius(14)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 14)
                                            .stroke(Color(red: 241/255, green: 245/255, blue: 249/255), lineWidth: 1)
                                    )
                                }
                            }
                        }
                        .padding(.horizontal, 16)
                        
                        // 6. FAQs Accordion
                        VStack(alignment: .leading, spacing: 14) {
                            Text("FREQUENTLY ASKED QUESTIONS")
                                .font(.system(size: 11, weight: .black))
                                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                .tracking(1.0)
                            
                            VStack(spacing: 10) {
                                ForEach(faqsList) { faq in
                                    let isExpanded = expandedFaqId == faq.id
                                    
                                    VStack(alignment: .leading, spacing: 8) {
                                        Button(action: {
                                            withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) {
                                                expandedFaqId = isExpanded ? nil : faq.id
                                            }
                                        }) {
                                            HStack {
                                                Text(faq.q ?? "")
                                                    .font(.system(size: 13, weight: .bold))
                                                    .foregroundColor(.textDark)
                                                    .multilineTextAlignment(.leading)
                                                Spacer()
                                                Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                                                    .font(.system(size: 12, weight: .bold))
                                                    .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                            }
                                        }
                                        .buttonStyle(PlainButtonStyle())
                                        
                                        if isExpanded {
                                            Text(faq.a ?? "")
                                                .font(.system(size: 12, weight: .medium))
                                                .foregroundColor(.textMuted)
                                                .lineSpacing(3)
                                                .padding(.top, 4)
                                        }
                                    }
                                    .padding(14)
                                    .background(Color.white)
                                    .cornerRadius(14)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 14)
                                            .stroke(Color(red: 241/255, green: 245/255, blue: 249/255), lineWidth: 1)
                                    )
                                }
                            }
                        }
                        .padding(.horizontal, 16)
                        
                        Spacer().frame(height: 60)
                    }
                }
            }
            
            // Prefill Checkout Sheet
            if isPrefillOpen, let pkg = selectedPackage {
                ZStack {
                    Color.black.opacity(0.5)
                        .ignoresSafeArea()
                        .onTapGesture { isPrefillOpen = false }
                    
                    VStack(alignment: .leading, spacing: 16) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Confirm Booking")
                                    .font(.system(size: 18, weight: .black))
                                    .foregroundColor(.textDark)
                                Text(pkg.name)
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                            }
                            Spacer()
                            Button(action: { isPrefillOpen = false }) {
                                Image(systemName: "xmark.circle.fill")
                                    .font(.system(size: 22))
                                    .foregroundColor(Color(red: 203/255, green: 213/255, blue: 225/255))
                            }
                        }
                        
                        CustomInputField(label: "Contact Name", placeholder: "Your Full Name", iconName: "person", text: $clientName)
                        CustomInputField(label: "Contact Email", placeholder: "Your Email Address", iconName: "envelope", text: $clientEmail)
                        CustomInputField(label: "Contact Phone", placeholder: "10-Digit Mobile Number", iconName: "phone", text: $clientPhone)
                        
                        Toggle(isOn: $termsAccepted) {
                            Text("I accept terms & understand advisory credits.")
                                .font(.system(size: 11, weight: .medium))
                                .foregroundColor(.textMuted)
                        }
                        
                        Button(action: {
                            isPrefillOpen = false
                            onCheckoutClick(serviceTitle, pkg, clientName, clientEmail, clientPhone)
                        }) {
                            Text("PROCEED TO PAY ₹\(Int(pkg.price))")
                                .font(.system(size: 13, weight: .black))
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity)
                                .frame(height: 50)
                                .background(
                                    termsAccepted
                                        ? LinearGradient(colors: [Color(red: 99/255, green: 102/255, blue: 241/255), Color(red: 79/255, green: 70/255, blue: 229/255)], startPoint: .leading, endPoint: .trailing)
                                        : LinearGradient(colors: [Color.gray, Color.gray], startPoint: .leading, endPoint: .trailing)
                                )
                                .cornerRadius(14)
                                .shadow(color: Color(red: 99/255, green: 102/255, blue: 241/255).opacity(0.3), radius: 8, y: 4)
                        }
                        .disabled(!termsAccepted)
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }
                    .padding(22)
                    .background(Color.white)
                    .cornerRadius(24)
                    .padding(20)
                    .shadow(radius: 20)
                }
                .transition(.opacity)
            }
        }
        .task {
            await loadServiceDataAndTrackTelemetry()
        }
    }
    
    private func loadServiceDataAndTrackTelemetry() async {
        // 1. Fetch Server-Driven config from backend
        do {
            let res = try await NetworkManager.shared.fetchServicePageConfig(pageId: serviceKey)
            await MainActor.run {
                self.dynamicPage = res
                self.isLoading = false
            }
        } catch {
            print("Could not load dynamic service config: \(error)")
            await MainActor.run {
                self.isLoading = false
            }
        }
        
        // 2. Emit Category A Telemetry Lead (PAGE_VIEW / Warm Lead)
        await NetworkManager.shared.sendLeadTelemetry(
            serviceId: serviceKey,
            serviceName: serviceTitle,
            category: "PAGE_VIEW"
        )
    }
    
    private func selectPackageAndOpenCheckout(_ pkg: ServicePackage) {
        selectedPackage = pkg
        isPrefillOpen = true
        
        // Emit Category B Telemetry Lead (PACKAGE_CLICK / High Intent Hot Lead)
        Task {
            await NetworkManager.shared.sendLeadTelemetry(
                serviceId: serviceKey,
                serviceName: serviceTitle,
                packageName: pkg.name,
                price: pkg.price,
                category: "PACKAGE_CLICK"
            )
        }
    }
    
    private func triggerConsultation() {
        let consultPkg = ServicePackage(
            id: "consultation",
            name: "Expert Advisory Consultation",
            price: 499.0,
            isAdjustable: true,
            description: "30-min CA/CS call. 100% credited against your final registration.",
            features: ["Direct CA/CS Call", "Structure Selection Advice", "Name Check Guidance"],
            creativeButtonText: "Book Consultation"
        )
        selectPackageAndOpenCheckout(consultPkg)
    }
}
