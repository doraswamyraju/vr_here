import SwiftUI
import PhotosUI

struct CustomerAccountTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    let onSelectTab: (String) -> Void
    let onDeleteAccount: () -> Void
    
    // Sub-Tab State: 'profile' | 'vault' | 'renewals' | 'billing'
    @State private var activeSubTab: String = "profile"
    
    // User Profile & Form State
    @State private var userNameInput: String = SessionManager.shared.getUserName()
    @State private var userEmailInput: String = SessionManager.shared.getUserEmail()
    @State private var userPhoneInput: String = SessionManager.shared.getPhone()
    @State private var companyNameInput: String = SessionManager.shared.getCompanyName()
    @State private var businessTypeInput: String = SessionManager.shared.getBusinessType()
    @State private var gstinInput: String = SessionManager.shared.getGstin()
    @State private var panNumberInput: String = SessionManager.shared.getPanNumber()
    @State private var addressInput: String = SessionManager.shared.getAddress()
    
    @State private var profilePhotoUrl: String = SessionManager.shared.getProfilePhoto()
    @State private var companyLogoUrl: String = SessionManager.shared.getCompanyLogo()
    
    @State private var isSavingProfile = false
    @State private var isUploadingPhoto = false
    @State private var isUploadingLogo = false
    
    @State private var showAvatarPicker = false
    @State private var showLogoPicker = false
    @State private var selectedAvatarItem: PhotosPickerItem? = nil
    @State private var selectedLogoItem: PhotosPickerItem? = nil
    
    @State private var showingDeleteAlert = false
    @State private var showingSaveSuccessAlert = false
    @State private var saveErrorMessage: String? = nil
    
    private var totalSpent: Double {
        viewModel.payments.reduce(0) { $0 + $1.amount }
    }
    
    private var activeOrdersCount: Int {
        viewModel.orders.filter { $0.status.lowercased() != "completed" }.count
    }
    
    var body: some View {
        ScrollView(showsIndicators: false) {
            VStack(spacing: 16) {
                
                // ==========================================
                // 1. HERO ACCOUNT HEADER CARD
                // ==========================================
                ZStack {
                    LinearGradient(
                        colors: [
                            Color(red: 15/255, green: 23/255, blue: 42/255),
                            Color(red: 30/255, green: 27/255, blue: 75/255),
                            Color(red: 49/255, green: 46/255, blue: 129/255)
                        ],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                    
                    VStack(spacing: 16) {
                        // User Profile Info Row
                        HStack(spacing: 14) {
                            ZStack(alignment: .bottomTrailing) {
                                VRAvatarView(
                                    photoUrl: profilePhotoUrl.isEmpty ? nil : profilePhotoUrl,
                                    name: userNameInput.isEmpty ? "Client" : userNameInput,
                                    size: 58
                                )
                                .overlay(
                                    Circle()
                                        .stroke(Color(red: 129/255, green: 140/255, blue: 248/255), lineWidth: 2)
                                )
                                
                                Button(action: {
                                    showAvatarPicker = true
                                }) {
                                    ZStack {
                                        Circle()
                                            .fill(Color(red: 220/255, green: 38/255, blue: 38/255))
                                            .frame(width: 22, height: 22)
                                        Image(systemName: "camera.fill")
                                            .font(.system(size: 10, weight: .bold))
                                            .foregroundColor(.white)
                                    }
                                }
                            }
                            
                            VStack(alignment: .leading, spacing: 3) {
                                HStack(spacing: 6) {
                                    Text(userNameInput.isEmpty ? "Enterprise Member" : userNameInput)
                                        .font(.system(size: 17, weight: .black))
                                        .foregroundColor(.white)
                                        .lineLimit(1)
                                    
                                    Text("VERIFIED")
                                        .font(.system(size: 8, weight: .black))
                                        .foregroundColor(Color(red: 52/255, green: 211/255, blue: 153/255))
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Color(red: 16/255, green: 185/255, blue: 129/255).opacity(0.2))
                                        .clipShape(Capsule())
                                    
                                    let appVer = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.2"
                                    Text("v\(appVer)")
                                        .font(.system(size: 8, weight: .black))
                                        .foregroundColor(Color(red: 165/255, green: 180/255, blue: 252/255))
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Color(red: 129/255, green: 140/255, blue: 248/255).opacity(0.25))
                                        .clipShape(Capsule())
                                }
                                
                                Text("\(userEmailInput)\(userPhoneInput.isEmpty ? "" : " • \(userPhoneInput)")")
                                    .font(.system(size: 11, weight: .medium))
                                    .foregroundColor(Color(red: 199/255, green: 210/255, blue: 254/255))
                                    .lineLimit(1)
                                
                                if !companyNameInput.isEmpty {
                                    Text(companyNameInput)
                                        .font(.system(size: 11, weight: .bold))
                                        .foregroundColor(Color(red: 244/255, green: 63/255, blue: 94/255))
                                        .lineLimit(1)
                                }
                            }
                            
                            Spacer()
                        }
                        
                        // Quick Stats Pill Row
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("TOTAL INVESTMENT")
                                    .font(.system(size: 8, weight: .black))
                                    .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                Text("₹\(Int(totalSpent).formattedWithSeparator())")
                                    .font(.system(size: 15, weight: .black))
                                    .foregroundColor(Color(red: 52/255, green: 211/255, blue: 153/255))
                            }
                            
                            Spacer()
                            
                            VStack(alignment: .trailing, spacing: 2) {
                                Text("ACTIVE ORDERS")
                                    .font(.system(size: 8, weight: .black))
                                    .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                Text("\(activeOrdersCount)")
                                    .font(.system(size: 15, weight: .black))
                                    .foregroundColor(.white)
                            }
                        }
                        .padding(12)
                        .background(Color.white.opacity(0.08))
                        .cornerRadius(14)
                    }
                    .padding(18)
                }
                .cornerRadius(22)
                .padding(.horizontal, 16)
                .padding(.top, 10)
                
                // ==========================================
                // 2. SUB-TABS NAVIGATION BAR
                // ==========================================
                HStack(spacing: 4) {
                    let subTabs = [
                        ("profile", "Profile", "person.text.rectangle"),
                        ("vault", "Vault", "folder.fill"),
                        ("renewals", "Renewals", "arrow.triangle.2.circlepath"),
                        ("billing", "Billing", "creditcard.fill")
                    ]
                    
                    ForEach(subTabs, id: \.0) { key, label, icon in
                        let isSelected = activeSubTab == key
                        Button(action: {
                            withAnimation(.spring(response: 0.3, dampingFraction: 0.75)) {
                                activeSubTab = key
                            }
                        }) {
                            HStack(spacing: 5) {
                                Image(systemName: icon)
                                    .font(.system(size: 10, weight: .bold))
                                Text(label)
                                    .font(.system(size: 11, weight: .black))
                            }
                            .foregroundColor(isSelected ? .white : Color(red: 100/255, green: 116/255, blue: 139/255))
                            .frame(maxWidth: .infinity)
                            .frame(height: 38)
                            .background(
                                isSelected ? Color(red: 220/255, green: 38/255, blue: 38/255) : Color.clear
                            )
                            .cornerRadius(10)
                        }
                    }
                }
                .padding(4)
                .background(Color.white)
                .cornerRadius(14)
                .overlay(
                    RoundedRectangle(cornerRadius: 14)
                        .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                )
                .padding(.horizontal, 16)
                
                // ==========================================
                // 3. SUB-TAB CONTENT
                // ==========================================
                switch activeSubTab {
                case "profile":
                    profileFormView
                case "vault":
                    CustomerVaultTab(viewModel: viewModel, isEmbedded: true)
                case "renewals":
                    renewalsView
                case "billing":
                    CustomerInvoicesTab(viewModel: viewModel, isEmbedded: true)
                default:
                    profileFormView
                }
                
                Spacer().frame(height: 140)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255).ignoresSafeArea())
        .onAppear {
            loadProfile()
            if let prof = viewModel.userProfile {
                populateFromProfile(prof)
            }
        }
        .onChange(of: viewModel.userProfile) { newProfile in
            if let prof = newProfile {
                populateFromProfile(prof)
            }
        }
        .photosPicker(isPresented: $showAvatarPicker, selection: $selectedAvatarItem, matching: .images)
        .photosPicker(isPresented: $showLogoPicker, selection: $selectedLogoItem, matching: .images)
        .onChange(of: selectedAvatarItem) { newItem in
            guard let item = newItem else { return }
            uploadAvatar(from: item)
        }
        .onChange(of: selectedLogoItem) { newItem in
            guard let item = newItem else { return }
            uploadLogo(from: item)
        }
        .alert("Delete Account", isPresented: $showingDeleteAlert) {
            Button("Cancel", role: .cancel) { }
            Button("Delete Forever", role: .destructive) {
                onDeleteAccount()
            }
        } message: {
            Text("Are you sure you want to permanently delete your account? All orders, uploaded KYC, and invoices will be irreversibly erased.")
        }
        .alert("Profile Updated", isPresented: $showingSaveSuccessAlert) {
            Button("OK", role: .cancel) { }
        } message: {
            Text("Your business profile and contact details have been successfully saved to VR Here cloud.")
        }
    }
    
    // ==========================================
    // PROFILE TAB SUB-VIEW
    // ==========================================
    private var profileFormView: some View {
        VStack(spacing: 16) {
            
            // --- Visual Branding Cards (Avatar + Logo) ---
            VStack(alignment: .leading, spacing: 12) {
                Text("Profile Photo & Business Logo")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                
                Text("Personalize your account and upload your official company logo for GST invoices & filings.")
                    .font(.system(size: 11))
                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                
                HStack(spacing: 12) {
                    // Personal Photo Card
                    VStack(spacing: 8) {
                        VRAvatarView(
                            photoUrl: profilePhotoUrl.isEmpty ? nil : profilePhotoUrl,
                            name: userNameInput.isEmpty ? "User" : userNameInput,
                            size: 46
                        )
                        
                        Text("Personal Photo")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        
                        if isUploadingPhoto {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: Color(red: 220/255, green: 38/255, blue: 38/255)))
                                .scaleEffect(0.8)
                                .frame(height: 28)
                        } else {
                            Button(action: {
                                showAvatarPicker = true
                            }) {
                                Text(profilePhotoUrl.isEmpty ? "Upload" : "Change")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.white)
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 5)
                                    .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                                    .cornerRadius(6)
                            }
                        }
                    }
                    .padding(12)
                    .frame(maxWidth: .infinity)
                    .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                    .cornerRadius(14)
                    .overlay(
                        RoundedRectangle(cornerRadius: 14)
                            .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                    )
                    
                    // Company Logo Card
                    VStack(spacing: 8) {
                        VRAvatarView(
                            photoUrl: companyLogoUrl.isEmpty ? nil : companyLogoUrl,
                            name: companyNameInput.isEmpty ? "Company" : companyNameInput,
                            size: 46
                        )
                        
                        Text("Company Logo")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        
                        if isUploadingLogo {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: Color(red: 220/255, green: 38/255, blue: 38/255)))
                                .scaleEffect(0.8)
                                .frame(height: 28)
                        } else {
                            Button(action: {
                                showLogoPicker = true
                            }) {
                                Text(companyLogoUrl.isEmpty ? "Upload" : "Change")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.white)
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 5)
                                    .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                                    .cornerRadius(6)
                            }
                        }
                    }
                    .padding(12)
                    .frame(maxWidth: .infinity)
                    .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                    .cornerRadius(14)
                    .overlay(
                        RoundedRectangle(cornerRadius: 14)
                            .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                    )
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .overlay(
                RoundedRectangle(cornerRadius: 18)
                    .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
            )
            .padding(.horizontal, 16)
            
            // --- Business & Contact Information Form ---
            VStack(alignment: .leading, spacing: 14) {
                Text("Business & Contact Information")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                
                // Name
                VStack(alignment: .leading, spacing: 4) {
                    Text("Full Name / Primary Contact")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                    TextField("Enter full legal name", text: $userNameInput)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .padding(10)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(10)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                }
                
                // Email
                VStack(alignment: .leading, spacing: 4) {
                    Text("Email Address")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                    TextField("Enter business email", text: $userEmailInput)
                        .keyboardType(.emailAddress)
                        .autocapitalization(.none)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .padding(10)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(10)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                }
                
                // Phone
                VStack(alignment: .leading, spacing: 4) {
                    Text("Phone Number")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                    TextField("Enter 10-digit mobile number", text: $userPhoneInput)
                        .keyboardType(.phonePad)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .padding(10)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(10)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                }
                
                // Company Name
                VStack(alignment: .leading, spacing: 4) {
                    Text("Company / Business Name")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                    TextField("Registered entity or firm name", text: $companyNameInput)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .padding(10)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(10)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                }
                
                // Business Entity Type
                VStack(alignment: .leading, spacing: 6) {
                    Text("Business Entity Type:")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                    
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 6) {
                            let types = ["Proprietorship", "Private Limited", "LLP", "Partnership Firm", "One Person Company", "Individual"]
                            ForEach(types, id: \.self) { type in
                                let isSelected = businessTypeInput == type
                                Button(action: {
                                    businessTypeInput = type
                                }) {
                                    Text(type)
                                        .font(.system(size: 10, weight: .bold))
                                        .foregroundColor(isSelected ? .white : Color(red: 71/255, green: 85/255, blue: 105/255))
                                        .padding(.horizontal, 10)
                                        .padding(.vertical, 6)
                                        .background(isSelected ? Color(red: 15/255, green: 23/255, blue: 42/255) : Color(red: 241/255, green: 245/255, blue: 249/255))
                                        .cornerRadius(8)
                                }
                            }
                        }
                    }
                }
                
                // GSTIN
                VStack(alignment: .leading, spacing: 4) {
                    Text("GSTIN (Optional)")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                    TextField("e.g. 36AAACG1234F1Z5", text: $gstinInput)
                        .autocapitalization(.allCharacters)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .padding(10)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(10)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                }
                
                // PAN Number
                VStack(alignment: .leading, spacing: 4) {
                    Text("PAN Number (Optional)")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                    TextField("e.g. ABCDE1234F", text: $panNumberInput)
                        .autocapitalization(.allCharacters)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .padding(10)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(10)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                }
                
                // Address
                VStack(alignment: .leading, spacing: 4) {
                    Text("Registered Business Address")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                    TextField("Official business address with pincode", text: $addressInput, axis: .vertical)
                        .lineLimit(2...4)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .padding(10)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(10)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                }
                
                // Save Button
                Button(action: saveProfileChanges) {
                    HStack(spacing: 6) {
                        if isSavingProfile {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: .white))
                                .scaleEffect(0.8)
                        } else {
                            Image(systemName: "checkmark.circle.fill")
                                .font(.system(size: 13, weight: .bold))
                            Text("Save Profile & Business Changes")
                                .font(.system(size: 12, weight: .black))
                        }
                    }
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 44)
                    .background(Color(red: 220/255, green: 38/255, blue: 38/255))
                    .cornerRadius(12)
                }
                .disabled(isSavingProfile)
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .overlay(
                RoundedRectangle(cornerRadius: 18)
                    .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
            )
            .padding(.horizontal, 16)
            
            // --- Support & Official Helpline Card ---
            VStack(alignment: .leading, spacing: 10) {
                Text("Support & Business Helpline")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                
                HStack(spacing: 10) {
                    Image(systemName: "phone.fill")
                        .foregroundColor(Color(red: 16/255, green: 185/255, blue: 129/255))
                    Text("Official Helpline: +91 8008530606")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    Spacer()
                }
                
                HStack(spacing: 10) {
                    Image(systemName: "envelope.fill")
                        .foregroundColor(Color(red: 59/255, green: 130/255, blue: 246/255))
                    Text("Legal & Compliance: support@vrhere.in")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    Spacer()
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .overlay(
                RoundedRectangle(cornerRadius: 18)
                    .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
            )
            .padding(.horizontal, 16)
            
            // --- Danger Zone Card ---
            VStack(alignment: .leading, spacing: 10) {
                Text("Danger Zone")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                
                Text("Once you delete your account, all profile information, historical orders, and document vault files will be permanently removed. This action is irreversible.")
                    .font(.system(size: 11))
                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                
                Button(action: {
                    showingDeleteAlert = true
                }) {
                    Text("Delete Account Permanently")
                        .font(.system(size: 12, weight: .black))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .frame(height: 42)
                        .background(Color(red: 220/255, green: 38/255, blue: 38/255))
                        .cornerRadius(10)
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .overlay(
                RoundedRectangle(cornerRadius: 18)
                    .stroke(Color(red: 254/255, green: 226/255, blue: 226/255), lineWidth: 1)
            )
            .padding(.horizontal, 16)
            
            // --- Version Footer ---
            let appVer = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.2"
            let buildVer = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "3"
            Text("VR HERE BMS iOS • Version \(appVer) (Build \(buildVer))")
                .font(.system(size: 11, weight: .bold))
                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                .padding(.top, 4)
        }
    }
    
    // ==========================================
    // RENEWALS TAB SUB-VIEW
    // ==========================================
    private var renewalsView: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Active Registrations & Renewal Cycles")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                Text("Track annual compliance due dates, licenses & renewal invoices.")
                    .font(.system(size: 11))
                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
            }
            
            if viewModel.orders.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "arrow.triangle.2.circlepath.circle")
                        .font(.system(size: 36))
                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                    Text("No active renewal cycles set up yet.")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 32)
            } else {
                ForEach(viewModel.orders) { order in
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(order.serviceName)
                                .font(.system(size: 13, weight: .black))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                            Text("Yearly Cycle • Status: \(order.status)")
                                .font(.system(size: 10, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        }
                        
                        Spacer()
                        
                        VStack(alignment: .trailing, spacing: 4) {
                            Text("₹\(Int(order.price).formattedWithSeparator())")
                                .font(.system(size: 14, weight: .black))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                            
                            Button(action: {
                                onSelectTab("invoices")
                            }) {
                                Text("Pay Renewal")
                                    .font(.system(size: 9, weight: .black))
                                    .foregroundColor(.white)
                                    .padding(.horizontal, 10)
                                    .padding(.vertical, 4)
                                    .background(Color(red: 4/255, green: 120/255, blue: 87/255))
                                    .cornerRadius(6)
                            }
                        }
                    }
                    .padding(12)
                    .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                    .cornerRadius(12)
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                    )
                }
            }
        }
        .padding(16)
        .background(Color.white)
        .cornerRadius(18)
        .overlay(
            RoundedRectangle(cornerRadius: 18)
                .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
        )
        .padding(.horizontal, 16)
    }
    
    // ==========================================
    // ACTION HANDLERS
    // ==========================================
    private func saveProfileChanges() {
        guard !userNameInput.trimmingCharacters(in: .whitespaces).isEmpty,
              !userEmailInput.trimmingCharacters(in: .whitespaces).isEmpty else {
            viewModel.toastMessage = "Name and Email are required."
            return
        }
        
        isSavingProfile = true
        Task {
            do {
                let req = UpdateProfileRequest(
                    name: userNameInput,
                    email: userEmailInput,
                    phone: userPhoneInput,
                    companyName: companyNameInput,
                    businessType: businessTypeInput,
                    gstin: gstinInput,
                    panNumber: panNumberInput,
                    address: addressInput
                )
                let res = try await NetworkManager.shared.updateProfile(request: req)
                
                SessionManager.shared.saveUserName(res.name)
                SessionManager.shared.saveUserEmail(res.email)
                if let p = res.phone { SessionManager.shared.savePhone(p) }
                if let c = res.companyName { SessionManager.shared.saveCompanyName(c) }
                if let b = res.businessType { SessionManager.shared.saveBusinessType(b) }
                if let g = res.gstin { SessionManager.shared.saveGstin(g) }
                if let pan = res.panNumber { SessionManager.shared.savePanNumber(pan) }
                if let a = res.address { SessionManager.shared.saveAddress(a) }
                
                viewModel.toastMessage = "Profile updated successfully!"
                showingSaveSuccessAlert = true
                viewModel.refreshAllData(silent: true)
            } catch {
                viewModel.toastMessage = "Failed to update profile: \(error.localizedDescription)"
            }
            isSavingProfile = false
        }
    }
    
    private func uploadAvatar(from item: PhotosPickerItem) {
        isUploadingPhoto = true
        Task {
            do {
                if let data = try? await item.loadTransferable(type: Data.self) {
                    let res = try await NetworkManager.shared.uploadAvatar(imageData: data)
                    if let url = res["url"] {
                        profilePhotoUrl = url
                        SessionManager.shared.saveProfilePhoto(url)
                        viewModel.toastMessage = "Profile photo updated!"
                        viewModel.refreshAllData(silent: true)
                    }
                }
            } catch {
                viewModel.toastMessage = "Photo upload failed: \(error.localizedDescription)"
            }
            isUploadingPhoto = false
        }
    }
    
    private func uploadLogo(from item: PhotosPickerItem) {
        isUploadingLogo = true
        Task {
            do {
                if let data = try? await item.loadTransferable(type: Data.self) {
                    let res = try await NetworkManager.shared.uploadCompanyLogo(imageData: data)
                    if let url = res["url"] {
                        companyLogoUrl = url
                        SessionManager.shared.saveCompanyLogo(url)
                        viewModel.toastMessage = "Company logo updated!"
                        viewModel.refreshAllData(silent: true)
                    }
                }
            } catch {
                viewModel.toastMessage = "Logo upload failed: \(error.localizedDescription)"
            }
            isUploadingLogo = false
        }
    }
    
    private func populateFromProfile(_ profile: UserProfile) {
        if !profile.name.isEmpty { userNameInput = profile.name }
        if !profile.email.isEmpty { userEmailInput = profile.email }
        if let p = profile.phone, !p.isEmpty { userPhoneInput = p }
        if let c = profile.companyName, !c.isEmpty { companyNameInput = c }
        if let b = profile.businessType, !b.isEmpty { businessTypeInput = b }
        if let g = profile.gstin, !g.isEmpty { gstinInput = g }
        if let pan = profile.panNumber, !pan.isEmpty { panNumberInput = pan }
        if let a = profile.address, !a.isEmpty { addressInput = a }
        if let photo = profile.profilePhoto, !photo.isEmpty { profilePhotoUrl = photo }
        if let logo = profile.companyLogo, !logo.isEmpty { companyLogoUrl = logo }
    }
    
    private func loadProfile() {
        // 1. Instantly populate from local session
        userNameInput = SessionManager.shared.getUserName()
        userEmailInput = SessionManager.shared.getUserEmail()
        userPhoneInput = SessionManager.shared.getPhone()
        companyNameInput = SessionManager.shared.getCompanyName()
        businessTypeInput = SessionManager.shared.getBusinessType()
        gstinInput = SessionManager.shared.getGstin()
        panNumberInput = SessionManager.shared.getPanNumber()
        addressInput = SessionManager.shared.getAddress()
        profilePhotoUrl = SessionManager.shared.getProfilePhoto()
        companyLogoUrl = SessionManager.shared.getCompanyLogo()
        
        // 2. If viewModel already holds live profile, populate immediately
        if let existing = viewModel.userProfile {
            populateFromProfile(existing)
        }
        
        // 3. Actively fetch latest from server
        Task {
            do {
                let profile = try await NetworkManager.shared.getProfile()
                viewModel.userProfile = profile
                populateFromProfile(profile)
                
                SessionManager.shared.saveUserName(profile.name)
                SessionManager.shared.saveUserEmail(profile.email)
                if let p = profile.phone { SessionManager.shared.savePhone(p) }
                if let c = profile.companyName { SessionManager.shared.saveCompanyName(c) }
                if let b = profile.businessType { SessionManager.shared.saveBusinessType(b) }
                if let g = profile.gstin { SessionManager.shared.saveGstin(g) }
                if let pan = profile.panNumber { SessionManager.shared.savePanNumber(pan) }
                if let a = profile.address { SessionManager.shared.saveAddress(a) }
                if let photo = profile.profilePhoto { SessionManager.shared.saveProfilePhoto(photo) }
                if let logo = profile.companyLogo { SessionManager.shared.saveCompanyLogo(logo) }
            } catch {
                print("Failed to fetch fresh user profile: \(error)")
            }
        }
    }
}
