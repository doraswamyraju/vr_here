import SwiftUI

struct AppleAccountLinkSheet: View {
    @ObservedObject var viewModel: AuthViewModel
    @State private var showPasswordFields = false
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    // Header Illustration
                    HStack(spacing: 16) {
                        ZStack {
                            Circle()
                                .fill(Color.black)
                                .frame(width: 52, height: 52)
                            Image(systemName: "applelogo")
                                .font(.system(size: 24, weight: .bold))
                                .foregroundColor(.white)
                        }
                        
                        Image(systemName: "arrow.left.arrow.right")
                            .font(.system(size: 18, weight: .bold))
                            .foregroundColor(.textMuted)
                        
                        ZStack {
                            RoundedRectangle(cornerRadius: 14)
                                .fill(Color.primaryRed)
                                .frame(width: 52, height: 52)
                            Text("VR")
                                .font(.system(size: 20, weight: .black))
                                .foregroundColor(.white)
                        }
                    }
                    .padding(.top, 16)
                    
                    VStack(spacing: 6) {
                        Text("Connect Your VR Here Account")
                            .font(.system(size: 20, weight: .bold))
                            .foregroundColor(.textDark)
                            .multilineTextAlignment(.center)
                        
                        Text("This Apple ID isn't linked to a VR Here profile yet. If you already have an account (e.g. Gmail or work email), link it now so your orders, invoices, and data stay connected!")
                            .font(.system(size: 13))
                            .foregroundColor(.textMuted)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 12)
                    }
                    
                    Divider().padding(.vertical, 4)
                    
                    // Option 1: Quick Link with Google
                    Button(action: {
                        viewModel.linkAppleWithGoogle()
                    }) {
                        HStack(spacing: 12) {
                            Text("G")
                                .font(.system(size: 22, weight: .black))
                                .foregroundColor(Color(red: 0.918, green: 0.263, blue: 0.208))
                            Text("Link via Google Account")
                                .font(.system(size: 15, weight: .bold))
                                .foregroundColor(.textDark)
                            Spacer()
                            Image(systemName: "chevron.right")
                                .font(.system(size: 13, weight: .semibold))
                                .foregroundColor(.textMuted)
                        }
                        .padding(.horizontal, 16)
                        .frame(height: 54)
                        .background(Color.white)
                        .cornerRadius(12)
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .stroke(Color.borderLight, lineWidth: 1)
                        )
                    }
                    .buttonStyle(ScaleOnPressButtonStyle())
                    
                    // Option 2: Link with Email & Password
                    VStack(spacing: 12) {
                        Button(action: {
                            withAnimation(.easeInOut) {
                                showPasswordFields.toggle()
                            }
                        }) {
                            HStack(spacing: 12) {
                                Image(systemName: "envelope.badge.shield.half.filled")
                                    .font(.system(size: 18, weight: .semibold))
                                    .foregroundColor(.primaryRed)
                                Text("Link via Email & Password")
                                    .font(.system(size: 15, weight: .bold))
                                    .foregroundColor(.textDark)
                                Spacer()
                                Image(systemName: showPasswordFields ? "chevron.up" : "chevron.down")
                                    .font(.system(size: 13, weight: .semibold))
                                    .foregroundColor(.textMuted)
                            }
                            .padding(.horizontal, 16)
                            .frame(height: 54)
                            .background(Color.white)
                            .cornerRadius(12)
                            .overlay(
                                RoundedRectangle(cornerRadius: 12)
                                    .stroke(Color.borderLight, lineWidth: 1)
                            )
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                        
                        if showPasswordFields {
                            VStack(spacing: 12) {
                                TextField("Your existing account email", text: $viewModel.linkEmailInput)
                                    .font(.system(size: 14))
                                    .keyboardType(.emailAddress)
                                    .autocapitalization(.none)
                                    .padding(.horizontal, 14)
                                    .frame(height: 48)
                                    .background(Color.white)
                                    .cornerRadius(10)
                                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.borderLight, lineWidth: 1))
                                
                                SecureField("Your account password", text: $viewModel.linkPasswordInput)
                                    .font(.system(size: 14))
                                    .padding(.horizontal, 14)
                                    .frame(height: 48)
                                    .background(Color.white)
                                    .cornerRadius(10)
                                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.borderLight, lineWidth: 1))
                                
                                Button(action: {
                                    viewModel.linkAppleWithExistingPassword()
                                }) {
                                    HStack {
                                        Text("Verify & Link Account")
                                            .font(.system(size: 14, weight: .bold))
                                            .foregroundColor(.white)
                                    }
                                    .frame(maxWidth: .infinity)
                                    .frame(height: 46)
                                    .background(Color.primaryRed)
                                    .cornerRadius(10)
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                            }
                            .padding(14)
                            .background(Color.bgLight)
                            .cornerRadius(12)
                        }
                    }
                    
                    Spacer().frame(height: 10)
                    
                    // Option 3: Create New Account
                    Button(action: {
                        viewModel.confirmCreateNewAppleAccount()
                    }) {
                        Text("No, I'm new. Create a new account")
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundColor(.primaryRed)
                            .padding(.vertical, 8)
                    }
                }
                .padding(20)
            }
            .navigationBarTitle("Apple ID Linking", displayMode: .inline)
            .navigationBarItems(trailing: Button("Cancel") {
                viewModel.showAppleLinkPrompt = false
                viewModel.pendingAppleResult = nil
            })
        }
    }
}
