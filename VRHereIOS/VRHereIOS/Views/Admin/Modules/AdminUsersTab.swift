import SwiftUI

struct AdminUsersTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var searchQuery = ""
    @State private var roleFilter = "all"
    @State private var showingAddForm = false
    @State private var selectedUserForDetail: UserResponse? = nil
    
    // Add form states
    @State private var newName = ""
    @State private var newEmail = ""
    @State private var newPhone = ""
    @State private var newRole = "employee"
    @State private var newCompany = ""
    
    // Delete prompt
    @State private var userToDelete: UserResponse? = nil
    @State private var showDeleteAlert = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // Header Banner
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("CREDENTIALS & ACCESS CONTROL")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.cyan)
                                .tracking(1.5)
                            Text("Users & Roles Matrix")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                        Button(action: { showingAddForm = true }) {
                            HStack(spacing: 4) {
                                Image(systemName: "person.badge.plus")
                                Text("New User")
                            }
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.white)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 6)
                            .background(Color.primaryRed)
                            .cornerRadius(10)
                        }
                    }
                    
                    Text("Audit system user privileges, login permissions, role switches, and individual client transaction history.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.75))
                }
                .padding(20)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 35/255, green: 20/255, blue: 45/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Search Field
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.textMuted)
                    TextField("Search by name, email, phone, or company...", text: $searchQuery)
                        .font(.system(size: 13))
                }
                .padding(12)
                .background(Color.white)
                .cornerRadius(14)
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                .padding(.horizontal, 20)
                
                // Role Filter Chips
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(roleFilterOptions, id: \.key) { opt in
                            let isSelected = roleFilter == opt.key
                            Button(action: { roleFilter = opt.key }) {
                                Text(opt.label)
                                    .font(.system(size: 11, weight: .bold))
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 6)
                                    .foregroundColor(isSelected ? .white : Color(red: 60/255, green: 75/255, blue: 95/255))
                                    .background(isSelected ? Color.indigo : Color.white)
                                    .cornerRadius(16)
                                    .overlay(RoundedRectangle(cornerRadius: 16).stroke(isSelected ? Color.indigo : Color.borderLight, lineWidth: 1))
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                // Filtered Users List
                let filtered = viewModel.users.filter { u in
                    let q = searchQuery.lowercased()
                    let matchesSearch = q.isEmpty ||
                        u.name.lowercased().contains(q) ||
                        u.email.lowercased().contains(q) ||
                        (u.phone ?? "").lowercased().contains(q) ||
                        (u.companyName ?? "").lowercased().contains(q)
                    
                    let matchesRole = roleFilter == "all" || u.role.lowercased() == roleFilter.lowercased()
                    return matchesSearch && matchesRole
                }
                
                VStack(spacing: 12) {
                    if filtered.isEmpty {
                        VStack(spacing: 8) {
                            Image(systemName: "person.crop.circle.badge.xmark")
                                .font(.system(size: 36))
                                .foregroundColor(.textMuted)
                            Text("No users found matching query")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textMuted)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 40)
                    } else {
                        ForEach(filtered) { user in
                            userCard(user: user)
                        }
                    }
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
        .sheet(isPresented: $showingAddForm) {
            addUserSheet
        }
        .sheet(item: $selectedUserForDetail) { user in
            userDetailSheet(user: user)
        }
        .alert("Delete User Account?", isPresented: $showDeleteAlert) {
            Button("Cancel", role: .cancel) { }
            Button("Delete Permanently", role: .destructive) {
                if let u = userToDelete {
                    viewModel.deleteUser(id: u.id)
                }
            }
        } message: {
            Text("Are you sure you want to delete this account? The user will lose all dashboard and portal access.")
        }
    }

    struct RoleFilterItem {
        let key: String
        let label: String
    }

    private var roleFilterOptions: [RoleFilterItem] {
        let clientCount = viewModel.users.filter { $0.role == "client" }.count
        let employeeCount = viewModel.users.filter { $0.role == "employee" }.count
        let partnerCount = viewModel.users.filter { $0.role == "partner" }.count
        let freelancerCount = viewModel.users.filter { $0.role == "freelancer" }.count
        let adminCount = viewModel.users.filter { $0.role == "admin" }.count
        
        return [
            RoleFilterItem(key: "all", label: "All (\(viewModel.users.count))"),
            RoleFilterItem(key: "client", label: "Clients (\(clientCount))"),
            RoleFilterItem(key: "employee", label: "Employees (\(employeeCount))"),
            RoleFilterItem(key: "partner", label: "Partners (\(partnerCount))"),
            RoleFilterItem(key: "freelancer", label: "Freelancers (\(freelancerCount))"),
            RoleFilterItem(key: "admin", label: "Admins (\(adminCount))")
        ]
    }

    // MARK: - User Card
    private func userCard(user: UserResponse) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                // Avatar
                Circle()
                    .fill(roleColor(user.role).opacity(0.15))
                    .frame(width: 44, height: 44)
                    .overlay(
                        Text(String(user.name.prefix(1)).uppercased())
                            .font(.system(size: 16, weight: .black))
                            .foregroundColor(roleColor(user.role))
                    )
                
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text(user.name)
                            .font(.system(size: 14, weight: .bold))
                            .foregroundColor(.textDark)
                        if !user.isActive {
                            Text("DISABLED")
                                .font(.system(size: 8, weight: .black))
                                .foregroundColor(.red)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color.red.opacity(0.12))
                                .cornerRadius(4)
                        }
                    }
                    
                    Text(user.email)
                        .font(.system(size: 11))
                        .foregroundColor(.textMuted)
                }
                
                Spacer()
                
                // Role Badge
                Text(user.role.uppercased())
                    .font(.system(size: 8, weight: .black))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .foregroundColor(roleColor(user.role))
                    .background(roleColor(user.role).opacity(0.12))
                    .cornerRadius(6)
            }
            
            Divider().background(Color.borderLight)
            
            // Card Footer & Action Buttons
            HStack {
                if let phone = user.phone, !phone.isEmpty {
                    Text(phone)
                        .font(.system(size: 11))
                        .foregroundColor(.textMuted)
                } else {
                    Text("No phone linked")
                        .font(.system(size: 11))
                        .foregroundColor(.textMuted)
                }
                
                Spacer()
                
                Button(action: { selectedUserForDetail = user }) {
                    HStack(spacing: 4) {
                        Image(systemName: "eye.fill")
                        Text("Profile")
                    }
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(.indigo)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.indigo.opacity(0.1))
                    .cornerRadius(6)
                }
                
                Button(action: { viewModel.toggleUserActive(id: user.id) }) {
                    Text(user.isActive ? "Disable" : "Enable")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(user.isActive ? .orange : .green)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background((user.isActive ? Color.orange : Color.green).opacity(0.1))
                        .cornerRadius(6)
                }
                
                Button(action: {
                    userToDelete = user
                    showDeleteAlert = true
                }) {
                    Image(systemName: "trash")
                        .font(.system(size: 10))
                        .foregroundColor(.red)
                        .padding(6)
                        .background(Color.red.opacity(0.1))
                        .cornerRadius(6)
                }
            }
        }
        .padding(14)
        .background(Color.white)
        .cornerRadius(16)
        .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
    }

    // MARK: - Modals
    private var addUserSheet: some View {
        NavigationView {
            Form {
                Section(header: Text("Account Credentials")) {
                    TextField("Full Name", text: $newName)
                    TextField("Email Address", text: $newEmail)
                        .keyboardType(.emailAddress)
                        .autocapitalization(.none)
                    TextField("Phone Number", text: $newPhone)
                        .keyboardType(.phonePad)
                    TextField("Company Name (Optional)", text: $newCompany)
                }
                
                Section(header: Text("System Role & Access")) {
                    Picker("Role", selection: $newRole) {
                        Text("Employee").tag("employee")
                        Text("Client").tag("client")
                        Text("Partner").tag("partner")
                        Text("Freelancer").tag("freelancer")
                        Text("Admin").tag("admin")
                    }
                }
            }
            .navigationTitle("Add System User")
            .navigationBarItems(
                leading: Button("Cancel") { showingAddForm = false },
                trailing: Button("Create Account") {
                    viewModel.createUser(name: newName, email: newEmail, phone: newPhone, role: newRole)
                    newName = ""
                    newEmail = ""
                    newPhone = ""
                    newCompany = ""
                    showingAddForm = false
                }
                .font(.headline)
                .disabled(newName.isEmpty || newEmail.isEmpty)
            )
        }
    }

    private func userDetailSheet(user: UserResponse) -> some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(user.name)
                            .font(.system(size: 22, weight: .black))
                            .foregroundColor(.textDark)
                        Text("Role: \(user.role.capitalized) • Email: \(user.email)")
                            .font(.system(size: 12))
                            .foregroundColor(.textMuted)
                    }
                    .padding(.top, 10)
                    
                    // User Orders Section
                    let userOrders = viewModel.orders.filter { $0.email.lowercased() == user.email.lowercased() }
                    VStack(alignment: .leading, spacing: 10) {
                        Text("USER ORDER HISTORY (\(userOrders.count))")
                            .font(.system(size: 11, weight: .black))
                            .foregroundColor(.textMuted)
                        
                        if userOrders.isEmpty {
                            Text("No orders placed by this user yet.")
                                .font(.system(size: 12))
                                .foregroundColor(.textMuted)
                                .padding(16)
                                .frame(maxWidth: .infinity, alignment: .center)
                                .background(Color.white)
                                .cornerRadius(12)
                        } else {
                            ForEach(userOrders) { ord in
                                HStack {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(ord.serviceName)
                                            .font(.system(size: 13, weight: .bold))
                                        Text("₹\(Int(ord.price)) • \(ord.status)")
                                            .font(.system(size: 11))
                                            .foregroundColor(.textMuted)
                                    }
                                    Spacer()
                                    Button("View") {
                                        selectedUserForDetail = nil
                                        viewModel.selectedOrderId = ord.id
                                    }
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(.primaryRed)
                                }
                                .padding(12)
                                .background(Color.white)
                                .cornerRadius(12)
                                .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                            }
                        }
                    }
                }
                .padding(20)
            }
            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
            .navigationTitle("User Profile")
            .navigationBarItems(trailing: Button("Done") { selectedUserForDetail = nil })
        }
    }

    private func roleColor(_ role: String) -> Color {
        switch role.lowercased() {
        case "admin": return .red
        case "employee": return .blue
        case "partner": return .purple
        case "freelancer": return .orange
        default: return .indigo
        }
    }
}
