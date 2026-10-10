import SwiftUI

struct AdminUsersTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    @State private var subTab: UsersSubTab = .appUsers
    @State private var searchQuery = ""
    @State private var roleFilter = "all"
    
    // Quick Add User Form
    @State private var showAddUserForm = false
    @State private var newName = ""
    @State private var newEmail = ""
    @State private var newPhone = ""
    @State private var newRole = "employee"
    @State private var newPartnerId = ""
    @State private var newTicketCategories: [String] = []
    @State private var isCreatingUser = false
    
    // Edit User Sheet
    @State private var userToEdit: UserResponse? = nil
    @State private var editName = ""
    @State private var editEmail = ""
    @State private var editPhone = ""
    @State private var editRole = "employee"
    @State private var editPartnerId = ""
    @State private var editTicketCategories: [String] = []
    @State private var isSavingEdit = false
    
    // Full Details Sheet
    @State private var viewingUser: UserResponse? = nil
    @State private var selectedPartnerForViewingUser = ""
    
    // Password Link Modal
    @State private var passwordLinkModalUser: UserResponse? = nil
    @State private var passwordLinkResult: PasswordLinkResponse? = nil
    @State private var isGeneratingPasswordLink = false
    @State private var copiedPasswordLink = false
    
    // Delete Alert
    @State private var userToDelete: UserResponse? = nil
    @State private var showDeleteAlert = false
    
    // Attendance & Workload Preview
    @State private var attendanceItems: [AttendanceSummaryItem] = []
    @State private var selectedEmployeeIdForPreview = ""
    @State private var isLoadingAttendance = false
    
    enum UsersSubTab: String, CaseIterable {
        case appUsers = "App Users"
        case webmail = "Webmail Accounts"
    }
    
    var partnerUsers: [UserResponse] {
        viewModel.users.filter { $0.role.lowercased() == "partner" }
    }
    
    var employeeUsers: [UserResponse] {
        viewModel.users.filter { $0.role.lowercased() == "employee" || $0.role.lowercased() == "admin" }
    }
    
    var filteredUsers: [UserResponse] {
        viewModel.users.filter { u in
            let q = searchQuery.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
            let matchesRole = roleFilter == "all" || u.role.lowercased() == roleFilter.lowercased()
            if !matchesRole { return false }
            if q.isEmpty { return true }
            
            let haystack = "\(u.name) \(u.email) \(u.phone ?? "") \(u.role) \(u.companyName ?? "") \(u.gstin ?? "") \(u.panNumber ?? "") \(u.referredByPartner?.name ?? "") \(u.referredByPartner?.phone ?? "")".lowercased()
            return haystack.contains(q)
        }
    }
    
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
                            Text("Users")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                        
                        Button(action: { showAddUserForm.toggle() }) {
                            HStack(spacing: 6) {
                                Image(systemName: showAddUserForm ? "chevron.up" : "person.badge.plus")
                                Text(showAddUserForm ? "Hide Form" : "Add User")
                            }
                            .font(.system(size: 11, weight: .black))
                            .foregroundColor(.white)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 8)
                            .background(Color.primaryRed)
                            .cornerRadius(12)
                        }
                    }
                    
                    Text("Manage system user privileges, login permissions, role switches, password setup links, and referral linkages.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.75))
                }
                .padding(20)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 25/255, green: 30/255, blue: 50/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Sub-Tabs Navigation Bar
                HStack(spacing: 0) {
                    Button(action: { subTab = .appUsers }) {
                        HStack(spacing: 6) {
                            Image(systemName: "person.2.fill")
                            Text("App Users (\(viewModel.users.count))")
                        }
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(subTab == .appUsers ? .primaryRed : .textMuted)
                        .padding(.vertical, 12)
                        .frame(maxWidth: .infinity)
                        .overlay(
                            Rectangle()
                                .fill(subTab == .appUsers ? Color.primaryRed : Color.clear)
                                .frame(height: 2),
                            alignment: .bottom
                        )
                    }
                    
                    Button(action: { subTab = .webmail }) {
                        HStack(spacing: 6) {
                            Image(systemName: "envelope.fill")
                            Text("Webmail Accounts")
                        }
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(subTab == .webmail ? .primaryRed : .textMuted)
                        .padding(.vertical, 12)
                        .frame(maxWidth: .infinity)
                        .overlay(
                            Rectangle()
                                .fill(subTab == .webmail ? Color.primaryRed : Color.clear)
                                .frame(height: 2),
                            alignment: .bottom
                        )
                    }
                }
                .background(Color.white)
                .cornerRadius(14)
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                .padding(.horizontal, 20)
                
                if subTab == .appUsers {
                    appUsersContent
                } else {
                    webmailContent
                }
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
        .onAppear {
            loadAttendance()
        }
        .sheet(item: $viewingUser) { user in
            userFullDetailsSheet(user: user)
        }
        .sheet(item: $userToEdit) { user in
            editUserSheet(user: user)
        }
        .sheet(item: $passwordLinkModalUser) { user in
            passwordLinkSheet(user: user)
        }
        .alert("Delete User Account?", isPresented: $showDeleteAlert) {
            Button("Cancel", role: .cancel) { }
            Button("Delete Permanently", role: .destructive) {
                if let u = userToDelete {
                    viewModel.deleteUser(id: u.id)
                }
            }
        } message: {
            Text("Are you sure you want to permanently delete user \(userToDelete?.name ?? "")? This cannot be undone.")
        }
    }
    
    // MARK: - App Users Sub-Tab Content
    private var appUsersContent: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Expandable Add User Form
            if showAddUserForm {
                addUserCard
            }
            
            // Search & Filter Controls
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.textMuted)
                    TextField("Search by name, email, phone, company, GSTIN...", text: $searchQuery)
                        .font(.system(size: 13))
                    if !searchQuery.isEmpty {
                        Button(action: { searchQuery = "" }) {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundColor(.textMuted)
                        }
                    }
                }
                .padding(12)
                .background(Color.white)
                .cornerRadius(14)
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                
                // Role Filter Chips
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        let roles = [
                            ("all", "All (\(viewModel.users.count))"),
                            ("admin", "Admins"),
                            ("employee", "Employees"),
                            ("client", "Clients"),
                            ("partner", "Partners")
                        ]
                        ForEach(roles, id: \.0) { roleKey, label in
                            let isSelected = roleFilter == roleKey
                            Button(action: { roleFilter = roleKey }) {
                                Text(label)
                                    .font(.system(size: 11, weight: .bold))
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 6)
                                    .foregroundColor(isSelected ? .white : Color.textDark)
                                    .background(isSelected ? Color.darkSlate : Color.white)
                                    .cornerRadius(14)
                                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(isSelected ? Color.darkSlate : Color.borderLight, lineWidth: 1))
                            }
                        }
                    }
                }
            }
            .padding(.horizontal, 20)
            
            // Users Count Summary
            HStack {
                Text("SHOWING \(filteredUsers.count) OF \(viewModel.users.count) USERS")
                    .font(.system(size: 10, weight: .black))
                    .foregroundColor(.textMuted)
                    .tracking(1)
                Spacer()
            }
            .padding(.horizontal, 20)
            
            // Users Cards List
            VStack(spacing: 12) {
                if filteredUsers.isEmpty {
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
                    ForEach(filteredUsers) { user in
                        userRowCard(user: user)
                    }
                }
            }
            .padding(.horizontal, 20)
            
            // Workload & Attendance Preview Panel
            workloadAndAttendancePanel
                .padding(.horizontal, 20)
        }
    }
    
    // MARK: - Add User Card
    private var addUserCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Create New System User")
                .font(.system(size: 14, weight: .black))
                .foregroundColor(.textDark)
            
            VStack(spacing: 10) {
                TextField("Full Name *", text: $newName)
                    .font(.system(size: 13))
                    .padding(10)
                    .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                    .cornerRadius(10)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.borderLight, lineWidth: 1))
                
                TextField("Email Address *", text: $newEmail)
                    .font(.system(size: 13))
                    .keyboardType(.emailAddress)
                    .autocapitalization(.none)
                    .padding(10)
                    .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                    .cornerRadius(10)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.borderLight, lineWidth: 1))
                
                TextField("Phone (+91...)", text: $newPhone)
                    .font(.system(size: 13))
                    .keyboardType(.phonePad)
                    .padding(10)
                    .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                    .cornerRadius(10)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.borderLight, lineWidth: 1))
                
                HStack {
                    Text("Role:")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textDark)
                    Picker("Role", selection: $newRole) {
                        Text("Employee").tag("employee")
                        Text("Client").tag("client")
                        Text("Admin").tag("admin")
                        Text("Partner").tag("partner")
                    }
                    .pickerStyle(SegmentedPickerStyle())
                }
                
                if newRole == "client" {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Assigned Referral Partner")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(.textMuted)
                        Picker("Referral Partner", selection: $newPartnerId) {
                            Text("-- Direct Client (No Partner) --").tag("")
                            ForEach(partnerUsers) { p in
                                Text("\(p.name) (\(p.phone ?? p.email))").tag(p.id)
                            }
                        }
                        .pickerStyle(MenuPickerStyle())
                        .padding(8)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(10)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.borderLight, lineWidth: 1))
                    }
                }
                
                if newRole == "employee" || newRole == "admin" {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Assigned Ticket Queues")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(.textMuted)
                        HStack(spacing: 12) {
                            ForEach(["Technical", "Service", "Support"], id: \.self) { cat in
                                let isSelected = newTicketCategories.contains(cat)
                                Button(action: {
                                    if isSelected {
                                        newTicketCategories.removeAll { $0 == cat }
                                    } else {
                                        newTicketCategories.append(cat)
                                    }
                                }) {
                                    HStack(spacing: 4) {
                                        Image(systemName: isSelected ? "checkmark.square.fill" : "square")
                                            .foregroundColor(isSelected ? .primaryRed : .textMuted)
                                        Text(cat)
                                            .font(.system(size: 11, weight: .bold))
                                            .foregroundColor(.textDark)
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            Button(action: handleCreateUser) {
                HStack(spacing: 6) {
                    if isCreatingUser {
                        ProgressView().progressViewStyle(CircularProgressViewStyle(tint: .white))
                    } else {
                        Image(systemName: "paperplane.fill")
                        Text("Create User & Dispatch Invite")
                    }
                }
                .font(.system(size: 12, weight: .black))
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .background(Color.primaryRed)
                .cornerRadius(12)
            }
            .disabled(isCreatingUser || newName.isEmpty || newEmail.isEmpty)
        }
        .padding(16)
        .background(Color.white)
        .cornerRadius(18)
        .shadow(color: Color.black.opacity(0.04), radius: 8, x: 0, y: 3)
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
        .padding(.horizontal, 20)
    }
    
    // MARK: - User Row Card
    private func userRowCard(user: UserResponse) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            // User Top Identity Header
            HStack(alignment: .top, spacing: 12) {
                // Avatar Initials
                Circle()
                    .fill(roleColor(user.role).opacity(0.15))
                    .frame(width: 42, height: 42)
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
                        if let comp = user.companyName, !comp.isEmpty {
                            Text(comp)
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.indigo)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color.indigo.opacity(0.1))
                                .cornerRadius(6)
                        }
                    }
                    
                    HStack(spacing: 4) {
                        Text(user.email)
                            .font(.system(size: 11))
                            .foregroundColor(.textMuted)
                        if user.authProvider?.lowercased() == "google" {
                            Text("Google")
                                .font(.system(size: 8, weight: .black))
                                .foregroundColor(.red)
                                .padding(.horizontal, 4)
                                .padding(.vertical, 1)
                                .background(Color.red.opacity(0.1))
                                .cornerRadius(4)
                        }
                    }
                    
                    if let p = user.phone, !p.isEmpty {
                        Text(p)
                            .font(.system(size: 10, weight: .medium))
                            .foregroundColor(.textMuted)
                    }
                }
                
                Spacer()
                
                // Status Badge & Active Switch
                VStack(alignment: .trailing, spacing: 4) {
                    Text(user.isActive ? "ACTIVE" : "INACTIVE")
                        .font(.system(size: 8, weight: .black))
                        .foregroundColor(user.isActive ? .green : .red)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background((user.isActive ? Color.green : Color.red).opacity(0.1))
                        .cornerRadius(6)
                    
                    Text(user.role.uppercased())
                        .font(.system(size: 9, weight: .black))
                        .foregroundColor(roleColor(user.role))
                }
            }
            
            // Meta Badges (Compliance & Referral Partner & Ticket Queues)
            HStack(spacing: 6) {
                if user.canManageCompliance == true {
                    HStack(spacing: 2) {
                        Image(systemName: "checkmark.seal.fill")
                        Text("Compliance Authorized")
                    }
                    .font(.system(size: 9, weight: .bold))
                    .foregroundColor(.purple)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.purple.opacity(0.1))
                    .cornerRadius(6)
                }
                
                if user.role.lowercased() == "client" {
                    if let partner = user.referredByPartner {
                        HStack(spacing: 2) {
                            Text("🤝 \(partner.name ?? "Partner")")
                        }
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.orange)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.orange.opacity(0.1))
                        .cornerRadius(6)
                    } else {
                        Text("Direct Client")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundColor(.textMuted)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.borderLight)
                            .cornerRadius(6)
                    }
                }
                
                if let cats = user.assignedTicketCategories, !cats.isEmpty {
                    ForEach(cats, id: \.self) { cat in
                        Text(cat)
                            .font(.system(size: 8, weight: .black))
                            .foregroundColor(.cyan)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1.5)
                            .background(Color.cyan.opacity(0.12))
                            .cornerRadius(4)
                    }
                }
                
                Spacer()
            }
            
            Divider().background(Color.borderLight)
            
            // Action Buttons Bar (View, Edit, Compliance, Password Link, Delete)
            HStack(spacing: 6) {
                Button(action: {
                    viewingUser = user
                    selectedPartnerForViewingUser = user.referredByPartner?.id ?? ""
                }) {
                    Text("View")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                        .cornerRadius(8)
                }
                
                Button(action: {
                    userToEdit = user
                    editName = user.name
                    editEmail = user.email
                    editPhone = user.phone ?? ""
                    editRole = user.role
                    editPartnerId = user.referredByPartner?.id ?? ""
                    editTicketCategories = user.assignedTicketCategories ?? []
                }) {
                    HStack(spacing: 3) {
                        Image(systemName: "pencil")
                        Text("Edit")
                    }
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.indigo)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(Color.indigo.opacity(0.1))
                    .cornerRadius(8)
                }
                
                Button(action: {
                    handleSendPasswordLink(user: user)
                }) {
                    HStack(spacing: 3) {
                        Image(systemName: "link")
                        Text("Password Link")
                    }
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.teal)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(Color.teal.opacity(0.1))
                    .cornerRadius(8)
                }
                
                Spacer()
                
                Menu {
                    Button(action: { handleToggleActive(user: user) }) {
                        Label(user.isActive ? "Deactivate User" : "Activate User", systemImage: "power")
                    }
                    
                    if user.role.lowercased() == "employee" {
                        Button(action: { handleToggleCompliance(user: user) }) {
                            Label(user.canManageCompliance == true ? "Revoke Compliance Manager" : "Grant Compliance Manager", systemImage: "checkmark.seal")
                        }
                    }
                    
                    Button(role: .destructive, action: {
                        userToDelete = user
                        showDeleteAlert = true
                    }) {
                        Label("Delete User", systemImage: "trash")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle.fill")
                        .font(.system(size: 18))
                        .foregroundColor(.textMuted)
                        .padding(4)
                }
            }
        }
        .padding(16)
        .background(Color.white)
        .cornerRadius(18)
        .shadow(color: Color.black.opacity(0.03), radius: 8, x: 0, y: 3)
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
    }
    
    // MARK: - Workload & Attendance Panel
    private var workloadAndAttendancePanel: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Employee Workload & Live Status")
                .font(.system(size: 14, weight: .black))
                .foregroundColor(.textDark)
            
            if attendanceItems.isEmpty {
                Text("No attendance summary recorded today.")
                    .font(.system(size: 11))
                    .foregroundColor(.textMuted)
            } else {
                VStack(spacing: 8) {
                    ForEach(attendanceItems) { att in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(att.name)
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text(att.role ?? "Staff")
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            
                            HStack(spacing: 6) {
                                Circle()
                                    .fill(att.isClockedIn ? Color.green : Color.textMuted)
                                    .frame(width: 8, height: 8)
                                Text(att.isClockedIn ? "Live Clocked In" : "Offline")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(att.isClockedIn ? .green : .textMuted)
                            }
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background((att.isClockedIn ? Color.green : Color.textMuted).opacity(0.1))
                            .cornerRadius(8)
                        }
                        .padding(10)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(10)
                    }
                }
            }
        }
        .padding(16)
        .background(Color.white)
        .cornerRadius(18)
        .shadow(color: Color.black.opacity(0.03), radius: 8, x: 0, y: 3)
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
    }
    
    // MARK: - Webmail Content
    private var webmailContent: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 8) {
                Text("Corporate Webmail Management")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(.textDark)
                Text("Manage @vrhere.in enterprise mailboxes, aliases, and reset employee mail passwords.")
                    .font(.system(size: 12))
                    .foregroundColor(.textMuted)
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.white)
            .cornerRadius(18)
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
            
            // List of Employee Emails
            VStack(spacing: 10) {
                ForEach(employeeUsers) { emp in
                    HStack {
                        Image(systemName: "envelope.badge.shield.half.filled")
                            .foregroundColor(.indigo)
                            .font(.system(size: 18))
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text(emp.email)
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.textDark)
                            Text("Assigned to: \(emp.name) • \(emp.role)")
                                .font(.system(size: 10))
                                .foregroundColor(.textMuted)
                        }
                        Spacer()
                        
                        Button(action: {
                            handleSendPasswordLink(user: emp)
                        }) {
                            Text("Reset Creds")
                                .font(.system(size: 10, weight: .bold))
                                .foregroundColor(.indigo)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 5)
                                .background(Color.indigo.opacity(0.1))
                                .cornerRadius(8)
                        }
                    }
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(14)
                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
        .padding(.horizontal, 20)
    }
    
    // MARK: - User Full Details Sheet
    private func userFullDetailsSheet(user: UserResponse) -> some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    // Gradient Profile Card
                    VStack(alignment: .leading, spacing: 12) {
                        HStack(spacing: 14) {
                            Circle()
                                .fill(Color.primaryRed)
                                .frame(width: 56, height: 56)
                                .overlay(
                                    Text(String(user.name.prefix(1)).uppercased())
                                        .font(.system(size: 22, weight: .black))
                                        .foregroundColor(.white)
                                )
                            
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(user.name)
                                        .font(.system(size: 18, weight: .black))
                                        .foregroundColor(.white)
                                    Text(user.isActive ? "ACTIVE" : "INACTIVE")
                                        .font(.system(size: 9, weight: .black))
                                        .foregroundColor(user.isActive ? .green : .red)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Color.white.opacity(0.15))
                                        .cornerRadius(6)
                                }
                                Text("\(user.email) • \(user.phone ?? "No phone")")
                                    .font(.system(size: 11))
                                    .foregroundColor(.white.opacity(0.8))
                                Text("Role: \(user.role.uppercased())")
                                    .font(.system(size: 10, weight: .black))
                                    .foregroundColor(.cyan)
                            }
                            Spacer()
                        }
                    }
                    .padding(20)
                    .background(LinearGradient(colors: [Color.darkSlate, Color(red: 30/255, green: 40/255, blue: 70/255)], startPoint: .topLeading, endPoint: .bottomTrailing))
                    .cornerRadius(20)
                    
                    // Referral Partner Assignment Card (For Clients)
                    if user.role.lowercased() == "client" {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("🤝 ASSIGNED REFERRAL PARTNER")
                                .font(.system(size: 10, weight: .black))
                                .foregroundColor(.orange)
                            
                            Picker("Referral Partner", selection: $selectedPartnerForViewingUser) {
                                Text("-- Direct Customer (No Partner Linked) --").tag("")
                                ForEach(partnerUsers) { p in
                                    Text("\(p.name) (\(p.phone ?? p.email))").tag(p.id)
                                }
                            }
                            .pickerStyle(MenuPickerStyle())
                            .padding(8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.white)
                            .cornerRadius(10)
                            .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.orange.opacity(0.4), lineWidth: 1))
                            .onChange(of: selectedPartnerForViewingUser) { newPartnerId in
                                handleUpdatePartner(userId: user.id, partnerId: newPartnerId)
                            }
                        }
                        .padding(14)
                        .background(Color.orange.opacity(0.08))
                        .cornerRadius(16)
                        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.orange.opacity(0.2), lineWidth: 1))
                    }
                    
                    // Business & Account Details
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Business & Account Information")
                            .font(.system(size: 13, weight: .black))
                            .foregroundColor(.textDark)
                        
                        detailRow(label: "Company / Business Name", value: user.companyName ?? "Not specified")
                        detailRow(label: "Entity Type", value: user.businessType ?? "Not specified")
                        detailRow(label: "GSTIN", value: user.gstin ?? "Not provided")
                        detailRow(label: "PAN Card / Number", value: user.panNumber ?? user.panCard ?? "Not provided")
                        detailRow(label: "Registered Address", value: user.address ?? "No address provided")
                        detailRow(label: "Auth Provider", value: user.authProvider == "google" ? "Google OAuth" : "Email & Password")
                    }
                    .padding(16)
                    .background(Color.white)
                    .cornerRadius(18)
                    .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
                }
                .padding(20)
            }
            .navigationTitle("User Profile Details")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Close") { viewingUser = nil }
                }
            }
        }
    }
    
    // MARK: - Edit User Sheet
    private func editUserSheet(user: UserResponse) -> some View {
        NavigationView {
            Form {
                Section(header: Text("Basic Credentials")) {
                    TextField("Name", text: $editName)
                    TextField("Email", text: $editEmail)
                        .keyboardType(.emailAddress)
                        .autocapitalization(.none)
                    TextField("Phone", text: $editPhone)
                        .keyboardType(.phonePad)
                }
                
                Section(header: Text("Role Switch")) {
                    Picker("Role", selection: $editRole) {
                        Text("Employee").tag("employee")
                        Text("Client").tag("client")
                        Text("Admin").tag("admin")
                        Text("Partner").tag("partner")
                    }
                    .pickerStyle(SegmentedPickerStyle())
                }
                
                if editRole == "client" {
                    Section(header: Text("Assigned Referral Partner")) {
                        Picker("Partner", selection: $editPartnerId) {
                            Text("-- Direct Client (No Partner) --").tag("")
                            ForEach(partnerUsers) { p in
                                Text("\(p.name) (\(p.phone ?? p.email))").tag(p.id)
                            }
                        }
                    }
                }
                
                if editRole == "employee" || editRole == "admin" {
                    Section(header: Text("Assigned Ticket Queues")) {
                        ForEach(["Technical", "Service", "Support"], id: \.self) { cat in
                            let isChecked = editTicketCategories.contains(cat)
                            Button(action: {
                                if isChecked {
                                    editTicketCategories.removeAll { $0 == cat }
                                } else {
                                    editTicketCategories.append(cat)
                                }
                            }) {
                                HStack {
                                    Text(cat)
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    if isChecked {
                                        Image(systemName: "checkmark")
                                            .foregroundColor(.primaryRed)
                                    }
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle("Edit User")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") { userToEdit = nil }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Save") { handleSaveEdit(userId: user.id) }
                        .disabled(isSavingEdit || editName.isEmpty || editEmail.isEmpty)
                }
            }
        }
    }
    
    // MARK: - Password Link Sheet
    private func passwordLinkSheet(user: UserResponse) -> some View {
        NavigationView {
            VStack(spacing: 20) {
                if let result = passwordLinkResult {
                    VStack(alignment: .leading, spacing: 14) {
                        if result.success == true {
                            HStack(spacing: 10) {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(.green)
                                    .font(.system(size: 20))
                                Text("Email dispatched successfully to \(user.email).")
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.green)
                            }
                            .padding(12)
                            .background(Color.green.opacity(0.1))
                            .cornerRadius(12)
                        } else {
                            VStack(alignment: .leading, spacing: 6) {
                                HStack(spacing: 8) {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundColor(.orange)
                                    Text("Email not sent via SMTP")
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(.orange)
                                }
                                Text(result.emailError ?? "SMTP credentials or transport failed. You can copy the 24h reset URL directly below.")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            .padding(12)
                            .background(Color.orange.opacity(0.1))
                            .cornerRadius(12)
                        }
                        
                        // Copyable Reset URL Field
                        if let url = result.resetUrl, !url.isEmpty {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("DIRECT 24-HOUR SETUP URL:")
                                    .font(.system(size: 10, weight: .black))
                                    .foregroundColor(.textMuted)
                                
                                HStack {
                                    Text(url)
                                        .font(.system(size: 11, design: .monospaced))
                                        .lineLimit(2)
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    Button(action: {
                                        UIPasteboard.general.string = url
                                        copiedPasswordLink = true
                                        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) {
                                            copiedPasswordLink = false
                                        }
                                    }) {
                                        HStack(spacing: 4) {
                                            Image(systemName: copiedPasswordLink ? "checkmark" : "doc.on.doc")
                                            Text(copiedPasswordLink ? "Copied!" : "Copy")
                                        }
                                        .font(.system(size: 11, weight: .black))
                                        .foregroundColor(.white)
                                        .padding(.horizontal, 10)
                                        .padding(.vertical, 6)
                                        .background(copiedPasswordLink ? Color.green : Color.primaryRed)
                                        .cornerRadius(8)
                                    }
                                }
                                .padding(10)
                                .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                                .cornerRadius(10)
                            }
                        }
                    }
                    .padding(20)
                } else if isGeneratingPasswordLink {
                    VStack(spacing: 12) {
                        ProgressView()
                        Text("Generating secure password setup link...")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textMuted)
                    }
                    .padding(40)
                }
                
                Spacer()
            }
            .navigationTitle("Password Setup Link")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { passwordLinkModalUser = nil }
                }
            }
        }
    }
    
    // MARK: - Actions
    private func handleCreateUser() {
        guard !newName.isEmpty, !newEmail.isEmpty else { return }
        isCreatingUser = true
        Task {
            do {
                _ = try await NetworkManager.shared.createUser(
                    name: newName,
                    email: newEmail,
                    phone: newPhone,
                    role: newRole
                )
                newName = ""
                newEmail = ""
                newPhone = ""
                newRole = "employee"
                newPartnerId = ""
                newTicketCategories = []
                showAddUserForm = false
                viewModel.toastMessage = "User account created and password link dispatched."
                viewModel.syncDashboardData(silent: true)
            } catch {
                viewModel.toastMessage = "Failed to create user: \(error.localizedDescription)"
            }
            isCreatingUser = false
        }
    }
    
    private func handleSaveEdit(userId: String) {
        isSavingEdit = true
        Task {
            do {
                var payload: [String: Any] = [
                    "name": editName,
                    "email": editEmail,
                    "phone": editPhone,
                    "role": editRole,
                    "assignedTicketCategories": editTicketCategories
                ]
                if editRole == "client" {
                    payload["referredByPartner"] = editPartnerId.isEmpty ? NSNull() : editPartnerId
                }
                let body = try JSONSerialization.data(withJSONObject: payload)
                let _: UserResponse = try await NetworkManager.shared.performRequest(path: "api/auth/users/\(userId)", method: "PUT", body: body)
                userToEdit = nil
                viewModel.toastMessage = "User updated successfully."
                viewModel.syncDashboardData(silent: true)
            } catch {
                viewModel.toastMessage = "Update failed: \(error.localizedDescription)"
            }
            isSavingEdit = false
        }
    }
    
    private func handleToggleActive(user: UserResponse) {
        Task {
            do {
                let _: GeneralResponse = try await NetworkManager.shared.performRequest(path: "api/auth/users/\(user.id)/toggle-active", method: "PATCH")
                viewModel.toastMessage = "User status toggled."
                viewModel.syncDashboardData(silent: true)
            } catch {
                viewModel.toastMessage = "Failed to toggle status."
            }
        }
    }
    
    private func handleToggleCompliance(user: UserResponse) {
        Task {
            do {
                let current = user.canManageCompliance == true
                _ = try await NetworkManager.shared.toggleUserComplianceAccess(userId: user.id, canManage: !current)
                viewModel.toastMessage = "Compliance permissions updated."
                viewModel.syncDashboardData(silent: true)
            } catch {
                viewModel.toastMessage = "Failed to update compliance permissions."
            }
        }
    }
    
    private func handleSendPasswordLink(user: UserResponse) {
        passwordLinkModalUser = user
        passwordLinkResult = nil
        isGeneratingPasswordLink = true
        Task {
            do {
                let res = try await NetworkManager.shared.sendUserPasswordLink(userId: user.id)
                passwordLinkResult = res
            } catch {
                viewModel.toastMessage = "Failed to generate link: \(error.localizedDescription)"
                passwordLinkModalUser = nil
            }
            isGeneratingPasswordLink = false
        }
    }
    
    private func handleUpdatePartner(userId: String, partnerId: String) {
        Task {
            do {
                _ = try await NetworkManager.shared.updateUserAssignedPartner(userId: userId, partnerId: partnerId)
                viewModel.toastMessage = "Referral partner updated."
                viewModel.syncDashboardData(silent: true)
            } catch {
                viewModel.toastMessage = "Failed to update partner."
            }
        }
    }
    
    private func loadAttendance() {
        Task {
            do {
                let res = try await NetworkManager.shared.getAttendanceSummary()
                attendanceItems = res.items ?? []
            } catch {
                print("Attendance summary failed: \(error)")
            }
        }
    }
    
    private func roleColor(_ role: String) -> Color {
        switch role.lowercased() {
        case "admin": return .red
        case "employee": return .indigo
        case "partner": return .orange
        default: return .green
        }
    }
    
    private func detailRow(label: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label.uppercased())
                .font(.system(size: 9, weight: .black))
                .foregroundColor(.textMuted)
            Text(value)
                .font(.system(size: 12, weight: .bold))
                .foregroundColor(.textDark)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
