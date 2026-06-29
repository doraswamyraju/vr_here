import SwiftUI

struct AdminUsersTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var searchQuery = ""
    @State private var showingAddForm = false
    
    // Add form states
    @State private var newName = ""
    @State private var newEmail = ""
    @State private var newPhone = ""
    @State private var newRole = "employee"
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 8) {
                    Text("USER CREDENTIALS & ACCESS CONTROL")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.cyan)
                        .tracking(1)
                    Text("Users Matrix")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.white)
                    Text("Audit system user privileges, login permissions, and roles.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.7))
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 45/255, green: 20/255, blue: 45/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(20)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Add User Form Card
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("ADD SYSTEM USER")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(.textMuted)
                        Spacer()
                        Button(action: { withAnimation { showingAddForm.toggle() } }) {
                            Image(systemName: showingAddForm ? "chevron.up" : "plus.circle.fill")
                                .font(.system(size: 16))
                                .foregroundColor(.primaryRed)
                        }
                    }
                    
                    if showingAddForm {
                        VStack(spacing: 10) {
                            TextField("Full Name...", text: $newName)
                                .font(.system(size: 13))
                                .padding(10)
                                .background(Color.bgInput)
                                .cornerRadius(8)
                            
                            TextField("Email Address...", text: $newEmail)
                                .font(.system(size: 13))
                                .keyboardType(.emailAddress)
                                .autocapitalization(.none)
                                .padding(10)
                                .background(Color.bgInput)
                                .cornerRadius(8)
                            
                            TextField("Phone Number...", text: $newPhone)
                                .font(.system(size: 13))
                                .keyboardType(.phonePad)
                                .padding(10)
                                .background(Color.bgInput)
                                .cornerRadius(8)
                            
                            HStack {
                                Text("Assign Role:")
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.textDark)
                                Spacer()
                                Picker("Role", selection: $newRole) {
                                    Text("Employee").tag("employee")
                                    Text("Client").tag("client")
                                    Text("Partner").tag("partner")
                                    Text("Admin").tag("admin")
                                }
                                .pickerStyle(MenuPickerStyle())
                            }
                            
                            Button(action: {
                                guard !newName.isEmpty && !newEmail.isEmpty else { return }
                                viewModel.createUser(name: newName, email: newEmail, phone: newPhone, role: newRole)
                                newName = ""
                                newEmail = ""
                                newPhone = ""
                                newRole = "employee"
                                withAnimation { showingAddForm = false }
                            }) {
                                Text("CREATE USER ACCOUNT")
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(.white)
                                    .frame(maxWidth: .infinity)
                                    .frame(height: 36)
                                    .background(Color.primaryRed)
                                    .cornerRadius(8)
                            }
                            .buttonStyle(ScaleOnPressButtonStyle())
                        }
                        .padding(.top, 6)
                    }
                }
                .padding(16)
                .background(Color.white)
                .cornerRadius(18)
                .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                .overlay(
                    RoundedRectangle(cornerRadius: 18)
                        .stroke(Color.borderLight, lineWidth: 1)
                )
                .padding(.horizontal, 20)
                
                // Search bar
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.textMuted)
                    TextField("Search users by name, email, or role...", text: $searchQuery)
                        .font(.system(size: 13))
                }
                .padding(12)
                .background(Color.white)
                .cornerRadius(12)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color.borderLight, lineWidth: 1)
                )
                .padding(.horizontal, 20)
                
                // Users list
                VStack(spacing: 12) {
                    let filtered = viewModel.users.filter {
                        searchQuery.isEmpty ||
                        $0.name.localizedCaseInsensitiveContains(searchQuery) ||
                        $0.email.localizedCaseInsensitiveContains(searchQuery) ||
                        $0.role.localizedCaseInsensitiveContains(searchQuery)
                    }
                    
                    if filtered.isEmpty {
                        Text("No matching user profile found")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.textMuted)
                            .padding(.vertical, 30)
                            .frame(maxWidth: .infinity, alignment: .center)
                    } else {
                        ForEach(filtered) { user in
                            HStack(spacing: 14) {
                                Circle()
                                    .fill(user.isActive ? Color.green : Color.gray)
                                    .frame(width: 8, height: 8)
                                
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(user.name)
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Text(user.email)
                                        .font(.system(size: 11))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                                
                                Text(user.role.uppercased())
                                    .font(.system(size: 8, weight: .bold))
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .foregroundColor(.blue)
                                    .background(Color.blue.opacity(0.12))
                                    .cornerRadius(6)
                                    .padding(.trailing, 6)
                                
                                Menu {
                                    Button(action: {
                                        viewModel.toggleUserActive(id: user.idVal)
                                    }) {
                                        Label(user.isActive ? "Deactivate" : "Activate", systemImage: user.isActive ? "power.circle" : "power.circle.fill")
                                    }
                                    
                                    Button(role: .destructive, action: {
                                        viewModel.deleteUser(id: user.idVal)
                                    }) {
                                        Label("Delete User", systemImage: "trash")
                                    }
                                } label: {
                                    Image(systemName: "ellipsis.circle")
                                        .font(.system(size: 16))
                                        .foregroundColor(.textMuted)
                                }
                            }
                            .padding(14)
                            .background(Color.white)
                            .cornerRadius(16)
                            .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                            .overlay(
                                RoundedRectangle(cornerRadius: 16)
                                    .stroke(Color.borderLight, lineWidth: 1)
                            )
                        }
                    }
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
}
