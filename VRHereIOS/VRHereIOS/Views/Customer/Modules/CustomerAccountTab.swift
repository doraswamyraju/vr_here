import SwiftUI

struct CustomerAccountTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    let onSelectTab: (String) -> Void
    let onDeleteAccount: () -> Void
    
    @State private var showingDeleteAlert = false
    
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
                
                // Danger Zone
                VStack(alignment: .leading, spacing: 12) {
                    Text("Danger Zone")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(.primaryRed)
                    
                    Text("Once you delete your account, all of your profile information, historical orders, and document vault files will be permanently removed. This action is irreversible.")
                        .font(.system(size: 11))
                        .foregroundColor(.textMuted)
                        .lineLimit(nil)
                    
                    Button(action: {
                        showingDeleteAlert = true
                    }) {
                        Text("Delete Account")
                            .font(.system(size: 12, weight: .black))
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
                
                Spacer().frame(height: 100)
            }
        }
        .alert(isPresented: $showingDeleteAlert) {
            Alert(
                title: Text("Delete Account?"),
                message: Text("Are you sure you want to permanently delete your account? All your data will be destroyed immediately. This cannot be undone."),
                primaryButton: .destructive(Text("Delete Permanently")) {
                    onDeleteAccount()
                },
                secondaryButton: .cancel()
            )
        }
    }
}
