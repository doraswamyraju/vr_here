import SwiftUI

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
            .onSwipeBackGesture {
                onBackClick()
            }
        } else {
            Text("Service loading...")
        }
    }
}
