import SwiftUI

struct AdminCreateOrderSheet: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    let onDismiss: () -> Void
    
    @State private var searchTerm = ""
    @State private var serviceSearchTerm = ""
    @State private var selectedUser: UserResponse? = nil
    @State private var isRegisteringClient = false
    
    @State private var clientName = ""
    @State private var clientEmail = ""
    @State private var clientPhone = ""
    
    @State private var serviceName = ""
    @State private var packageName = "Manual Entry"
    @State private var priceString = ""
    @State private var selectedEmployeeId = ""
    
    // Recurring Options
    @State private var isRecurring = false
    @State private var frequency = "Monthly"
    @State private var dayOfMonth = 1
    @State private var dayOfWeek = 1
    
    @State private var isSubmitting = false
    @State private var errorMessage: String? = nil
    @State private var showServiceDropdown = false
    
    private let commonServices = [
        "Income Tax Return Filing (ITR)",
        "GST Registration Online",
        "GST Return Filing (GSTR 1, 3B, 9)",
        "Private Limited Company Registration",
        "Limited Liability Partnership (LLP)",
        "One Person Company (OPC)",
        "Cloud Accounting (Tally, Zoho Books)",
        "TDS / TCS Filing (24Q, 26Q)",
        "EPF & ESI Monthly Returns",
        "Payroll Management & Payslips",
        "Trademark Registration & IP",
        "ISO 9001:2015 Certification",
        "FSSAI Food Safety License",
        "MSME / Udyam Registration",
        "Startup India DPIIT Recognition",
        "ROC Annual Compliance Filing",
        "Bookkeeping & Ledger Audit",
        "Virtual CFO Advisory"
    ]
    
    private var filteredUsers: [UserResponse] {
        guard !searchTerm.trimmingCharacters(in: .whitespaces).isEmpty else { return [] }
        let query = searchTerm.lowercased()
        return viewModel.users.filter { user in
            user.name.lowercased().contains(query) ||
            user.email.lowercased().contains(query) ||
            (user.phone?.contains(query) ?? false)
        }
    }
    
    private var filteredServices: [String] {
        if serviceSearchTerm.isEmpty {
            return commonServices
        }
        return commonServices.filter { $0.lowercased().contains(serviceSearchTerm.lowercased()) }
    }
    
    var body: some View {
        NavigationView {
            ZStack {
                Color(red: 248/255, green: 250/255, blue: 252/255).ignoresSafeArea()
                
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        
                        // Header Banner
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Image(systemName: "plus.circle.fill")
                                    .foregroundColor(.emeraldGreen)
                                Text("MANUAL ORDER CREATION")
                                    .font(.system(size: 10, weight: .black))
                                    .foregroundColor(.emeraldGreen)
                                    .tracking(1.2)
                            }
                            Text("Create Client Project")
                                .font(.system(size: 22, weight: .black))
                                .foregroundColor(.textPrimary)
                            Text("Directly place and provision an order record into the active pipeline.")
                                .font(.system(size: 12))
                                .foregroundColor(.textMuted)
                        }
                        .padding(.horizontal, 20)
                        .padding(.top, 10)
                        
                        if let err = errorMessage {
                            HStack(spacing: 8) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundColor(.red)
                                Text(err)
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundColor(.red)
                            }
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.red.opacity(0.1))
                            .cornerRadius(12)
                            .padding(.horizontal, 20)
                        }
                        
                        // SECTION 1: CUSTOMER SELECTION
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Image(systemName: "person.crop.circle.badge.plus")
                                    .foregroundColor(.indigo)
                                Text("Customer / Client Account")
                                    .font(.system(size: 14, weight: .bold))
                                    .foregroundColor(.textPrimary)
                            }
                            
                            if let user = selectedUser {
                                HStack(spacing: 12) {
                                    ZStack {
                                        Circle()
                                            .fill(Color.indigo.opacity(0.15))
                                            .frame(width: 44, height: 44)
                                        Image(systemName: "person.fill.checkmark")
                                            .foregroundColor(.indigo)
                                            .font(.system(size: 18))
                                    }
                                    
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(user.name)
                                            .font(.system(size: 14, weight: .bold))
                                            .foregroundColor(.textPrimary)
                                        Text("\(user.email) • \(user.phone ?? "")")
                                            .font(.system(size: 11))
                                            .foregroundColor(.textMuted)
                                    }
                                    
                                    Spacer()
                                    
                                    Button(action: {
                                        selectedUser = nil
                                        searchTerm = ""
                                    }) {
                                        Image(systemName: "trash.fill")
                                            .foregroundColor(.red)
                                            .padding(8)
                                            .background(Color.red.opacity(0.1))
                                            .clipShape(Circle())
                                    }
                                }
                                .padding(14)
                                .background(Color.indigo.opacity(0.06))
                                .cornerRadius(16)
                                .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.indigo.opacity(0.3), lineWidth: 1))
                            } else {
                                // Search input
                                VStack(spacing: 6) {
                                    HStack {
                                        Image(systemName: "magnifyingglass")
                                            .foregroundColor(.textMuted)
                                        TextField("Search existing user by name, email, or phone...", text: $searchTerm)
                                            .font(.system(size: 13))
                                    }
                                    .padding(12)
                                    .background(Color.white)
                                    .cornerRadius(14)
                                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                                    
                                    if !filteredUsers.isEmpty {
                                        VStack(alignment: .leading, spacing: 0) {
                                            ForEach(filteredUsers.prefix(5)) { user in
                                                Button(action: {
                                                    selectedUser = user
                                                    clientName = user.name
                                                    clientEmail = user.email
                                                    clientPhone = user.phone ?? ""
                                                    searchTerm = ""
                                                }) {
                                                    HStack {
                                                        VStack(alignment: .leading, spacing: 2) {
                                                            Text(user.name)
                                                                .font(.system(size: 13, weight: .bold))
                                                                .foregroundColor(.textPrimary)
                                                            Text("\(user.email) | \(user.phone ?? "")")
                                                                .font(.system(size: 11))
                                                                .foregroundColor(.textMuted)
                                                        }
                                                        Spacer()
                                                        Image(systemName: "plus.circle.fill")
                                                            .foregroundColor(.indigo)
                                                    }
                                                    .padding(10)
                                                }
                                                Divider()
                                            }
                                        }
                                        .background(Color.white)
                                        .cornerRadius(14)
                                        .shadow(color: Color.black.opacity(0.06), radius: 6, y: 3)
                                    }
                                }
                                
                                // Register new client toggle
                                Toggle(isOn: $isRegisteringClient) {
                                    HStack(spacing: 6) {
                                        Image(systemName: "person.badge.plus")
                                            .foregroundColor(.indigo)
                                        Text("Register as New Client")
                                            .font(.system(size: 13, weight: .semibold))
                                            .foregroundColor(.textPrimary)
                                    }
                                }
                                .padding(.top, 4)
                                
                                if isRegisteringClient || selectedUser == nil {
                                    VStack(spacing: 10) {
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text("CLIENT FULL NAME *")
                                                .font(.system(size: 10, weight: .bold))
                                                .foregroundColor(.textMuted)
                                            TextField("e.g. Rahul Sharma", text: $clientName)
                                                .font(.system(size: 13))
                                                .padding(12)
                                                .background(Color.white)
                                                .cornerRadius(12)
                                                .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                                        }
                                        
                                        HStack(spacing: 10) {
                                            VStack(alignment: .leading, spacing: 4) {
                                                Text("EMAIL ADDRESS *")
                                                    .font(.system(size: 10, weight: .bold))
                                                    .foregroundColor(.textMuted)
                                                TextField("client@example.com", text: $clientEmail)
                                                    .keyboardType(.emailAddress)
                                                    .autocapitalization(.none)
                                                    .font(.system(size: 13))
                                                    .padding(12)
                                                    .background(Color.white)
                                                    .cornerRadius(12)
                                                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                                            }
                                            
                                            VStack(alignment: .leading, spacing: 4) {
                                                Text("PHONE NUMBER")
                                                    .font(.system(size: 10, weight: .bold))
                                                    .foregroundColor(.textMuted)
                                                TextField("9876543210", text: $clientPhone)
                                                    .keyboardType(.phonePad)
                                                    .font(.system(size: 13))
                                                    .padding(12)
                                                    .background(Color.white)
                                                    .cornerRadius(12)
                                                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        .padding(16)
                        .background(Color.white)
                        .cornerRadius(20)
                        .padding(.horizontal, 20)
                        
                        // SECTION 2: SERVICE & COMMERCIALS
                        VStack(alignment: .leading, spacing: 14) {
                            HStack {
                                Image(systemName: "briefcase.fill")
                                    .foregroundColor(.emeraldGreen)
                                Text("Service & Pricing")
                                    .font(.system(size: 14, weight: .bold))
                                    .foregroundColor(.textPrimary)
                            }
                            
                            VStack(alignment: .leading, spacing: 4) {
                                Text("SERVICE NAME *")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.textMuted)
                                
                                HStack {
                                    TextField("Search or enter custom service...", text: $serviceSearchTerm)
                                        .font(.system(size: 13))
                                        .onChange(of: serviceSearchTerm) { val in
                                            serviceName = val
                                            showServiceDropdown = !val.isEmpty
                                        }
                                    
                                    Button(action: { showServiceDropdown.toggle() }) {
                                        Image(systemName: showServiceDropdown ? "chevron.up" : "chevron.down")
                                            .foregroundColor(.textMuted)
                                    }
                                }
                                .padding(12)
                                .background(Color.white)
                                .cornerRadius(12)
                                .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                                
                                if showServiceDropdown {
                                    VStack(alignment: .leading, spacing: 0) {
                                        ForEach(filteredServices.prefix(6), id: \.self) { svc in
                                            Button(action: {
                                                serviceName = svc
                                                serviceSearchTerm = svc
                                                showServiceDropdown = false
                                            }) {
                                                Text(svc)
                                                    .font(.system(size: 12))
                                                    .foregroundColor(.textPrimary)
                                                    .padding(.vertical, 8)
                                                    .padding(.horizontal, 10)
                                                    .frame(maxWidth: .infinity, alignment: .leading)
                                            }
                                            Divider()
                                        }
                                    }
                                    .background(Color.white)
                                    .cornerRadius(12)
                                    .shadow(color: Color.black.opacity(0.06), radius: 6, y: 3)
                                }
                            }
                            
                            HStack(spacing: 10) {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text("PRICE (₹ INR) *")
                                        .font(.system(size: 10, weight: .bold))
                                        .foregroundColor(.textMuted)
                                    HStack {
                                        Text("₹")
                                            .font(.system(size: 14, weight: .black))
                                            .foregroundColor(.emeraldGreen)
                                        TextField("e.g. 4999", text: $priceString)
                                            .keyboardType(.numberPad)
                                            .font(.system(size: 13, weight: .bold))
                                    }
                                    .padding(12)
                                    .background(Color.white)
                                    .cornerRadius(12)
                                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                                }
                                
                                VStack(alignment: .leading, spacing: 4) {
                                    Text("PACKAGE PLAN")
                                        .font(.system(size: 10, weight: .bold))
                                        .foregroundColor(.textMuted)
                                    TextField("Manual Entry", text: $packageName)
                                        .font(.system(size: 13))
                                        .padding(12)
                                        .background(Color.white)
                                        .cornerRadius(12)
                                        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                                }
                            }
                            
                            // Assign Specialist
                            VStack(alignment: .leading, spacing: 4) {
                                Text("ASSIGN SPECIALIST (OPTIONAL)")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.textMuted)
                                
                                Picker("Assignee", selection: $selectedEmployeeId) {
                                    Text("Unassigned (Pending Queue)").tag("")
                                    ForEach(viewModel.employees) { emp in
                                        Text("\(emp.name) (\(emp.designation ?? emp.role))").tag(emp.id)
                                    }
                                }
                                .pickerStyle(MenuPickerStyle())
                                .padding(10)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.white)
                                .cornerRadius(12)
                                .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                            }
                        }
                        .padding(16)
                        .background(Color.white)
                        .cornerRadius(20)
                        .padding(.horizontal, 20)
                        
                        // SECTION 3: RECURRING SUBSCRIPTION OPTION
                        VStack(alignment: .leading, spacing: 12) {
                            Toggle(isOn: $isRecurring) {
                                HStack(spacing: 6) {
                                    Image(systemName: "arrow.triangle.2.circlepath")
                                        .foregroundColor(.cyan)
                                    Text("Schedule as Recurring Subscription")
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.textPrimary)
                                }
                            }
                            
                            if isRecurring {
                                VStack(spacing: 10) {
                                    HStack(spacing: 10) {
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text("FREQUENCY")
                                                .font(.system(size: 10, weight: .bold))
                                                .foregroundColor(.textMuted)
                                            Picker("Frequency", selection: $frequency) {
                                                Text("Weekly").tag("Weekly")
                                                Text("Monthly").tag("Monthly")
                                                Text("Quarterly").tag("Quarterly")
                                                Text("Half-Yearly").tag("Half-Yearly")
                                                Text("Yearly").tag("Yearly")
                                            }
                                            .pickerStyle(MenuPickerStyle())
                                            .padding(10)
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                            .background(Color.white)
                                            .cornerRadius(12)
                                            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                                        }
                                        
                                        if frequency == "Weekly" {
                                            VStack(alignment: .leading, spacing: 4) {
                                                Text("DAY OF WEEK")
                                                    .font(.system(size: 10, weight: .bold))
                                                    .foregroundColor(.textMuted)
                                                Picker("Day", selection: $dayOfWeek) {
                                                    Text("Monday").tag(1)
                                                    Text("Tuesday").tag(2)
                                                    Text("Wednesday").tag(3)
                                                    Text("Thursday").tag(4)
                                                    Text("Friday").tag(5)
                                                    Text("Saturday").tag(6)
                                                    Text("Sunday").tag(0)
                                                }
                                                .pickerStyle(MenuPickerStyle())
                                                .padding(10)
                                                .frame(maxWidth: .infinity, alignment: .leading)
                                                .background(Color.white)
                                                .cornerRadius(12)
                                                .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                                            }
                                        } else {
                                            VStack(alignment: .leading, spacing: 4) {
                                                Text("DAY OF MONTH (1-31)")
                                                    .font(.system(size: 10, weight: .bold))
                                                    .foregroundColor(.textMuted)
                                                Stepper("Day \(dayOfMonth)", value: $dayOfMonth, in: 1...31)
                                                    .font(.system(size: 12, weight: .semibold))
                                                    .padding(8)
                                                    .background(Color.white)
                                                    .cornerRadius(12)
                                                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                                            }
                                        }
                                    }
                                }
                                .padding(12)
                                .background(Color.cyan.opacity(0.06))
                                .cornerRadius(14)
                            }
                        }
                        .padding(16)
                        .background(Color.white)
                        .cornerRadius(20)
                        .padding(.horizontal, 20)
                        
                        // Submit Buttons
                        HStack(spacing: 12) {
                            Button(action: onDismiss) {
                                Text("Cancel")
                                    .font(.system(size: 14, weight: .bold))
                                    .foregroundColor(.textMuted)
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 14)
                                    .background(Color.slateLight)
                                    .cornerRadius(14)
                            }
                            
                            Button(action: handleCreateOrder) {
                                HStack(spacing: 6) {
                                    if isSubmitting {
                                        ProgressView()
                                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                                    } else {
                                        Image(systemName: "bolt.fill")
                                        Text("Create Order")
                                    }
                                }
                                .font(.system(size: 14, weight: .black))
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 14)
                                .background(Color.emeraldGreen)
                                .cornerRadius(14)
                                .shadow(color: Color.emeraldGreen.opacity(0.35), radius: 8, y: 4)
                            }
                            .disabled(isSubmitting)
                        }
                        .padding(.horizontal, 20)
                        .padding(.bottom, 30)
                    }
                }
            }
            .navigationTitle("New Order")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: onDismiss) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.textMuted)
                    }
                }
            }
        }
    }
    
    private func handleCreateOrder() {
        let finalServiceName = serviceName.trimmingCharacters(in: .whitespaces).isEmpty ? serviceSearchTerm.trimmingCharacters(in: .whitespaces) : serviceName.trimmingCharacters(in: .whitespaces)
        let finalClientName = selectedUser?.name ?? clientName.trimmingCharacters(in: .whitespaces)
        let finalEmail = selectedUser?.email ?? clientEmail.trimmingCharacters(in: .whitespaces)
        let finalPhone = selectedUser?.phone ?? clientPhone.trimmingCharacters(in: .whitespaces)
        let price = Double(priceString) ?? 0.0
        
        if finalServiceName.isEmpty {
            errorMessage = "Please enter or select a service name."
            return
        }
        if price <= 0 {
            errorMessage = "Please enter a valid price amount."
            return
        }
        if finalClientName.isEmpty || finalEmail.isEmpty {
            errorMessage = "Please provide customer name and email."
            return
        }
        
        errorMessage = nil
        isSubmitting = true
        
        var payload: [String: AnyCodable] = [
            "serviceName": AnyCodable(finalServiceName),
            "packageName": AnyCodable(packageName.isEmpty ? "Manual Entry" : packageName),
            "price": AnyCodable(price),
            "clientName": AnyCodable(finalClientName),
            "email": AnyCodable(finalEmail),
            "phone": AnyCodable(finalPhone),
            "isRecurring": AnyCodable(isRecurring)
        ]
        
        if let userId = selectedUser?.idVal, !userId.isEmpty {
            payload["userId"] = AnyCodable(userId)
        }
        
        if !selectedEmployeeId.isEmpty {
            payload["employeeId"] = AnyCodable(selectedEmployeeId)
        }
        
        if isRecurring {
            payload["frequency"] = AnyCodable(frequency)
            if frequency == "Weekly" {
                payload["dayOfWeek"] = AnyCodable(dayOfWeek)
            } else {
                payload["dayOfMonth"] = AnyCodable(dayOfMonth)
            }
        }
        
        viewModel.createOrder(fields: payload) { success in
            isSubmitting = false
            if success {
                onDismiss()
            }
        }
    }
}
