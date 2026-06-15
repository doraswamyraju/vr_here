import SwiftUI

struct RegisterView: View {
    @ObservedObject var viewModel: AuthViewModel
    let onNavigateToLogin: () -> Void
    let onRegistrationSuccess: () -> Void
    
    @State private var showingToast = false
    @State private var toastMsg = ""
    
    var body: some View {
        ZStack {
            Color.white
                .ignoresSafeArea()
            
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    Spacer().frame(height: 24)
                    
                    // 1. Header
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 4) {
                            Text("VR")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.primaryRed)
                            Text("HERE")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.textDark)
                        }
                        Text("Business Management Solutions")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.textMuted)
                    }
                    .padding(.vertical, 12)
                    
                    Spacer().frame(height: 24)
                    
                    Text("Create Account")
                        .font(.system(size: 30, weight: .bold))
                        .foregroundColor(.textDark)
                    
                    Spacer().frame(height: 16)
                    
                    // 2. Role Selector Tab
                    HStack(spacing: 0) {
                        Button(action: { viewModel.roleInput = "client" }) {
                            Text("Customer")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(viewModel.roleInput == "client" ? .white : .textMuted)
                                .frame(maxWidth: .infinity)
                                .frame(height: 40)
                                .background(viewModel.roleInput == "client" ? Color.primaryRed : Color.clear)
                                .cornerRadius(8)
                        }
                        .buttonStyle(PlainButtonStyle())
                        
                        Button(action: { viewModel.roleInput = "partner" }) {
                            Text("Partner/Freelancer")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(viewModel.roleInput == "partner" ? .white : .textMuted)
                                .frame(maxWidth: .infinity)
                                .frame(height: 40)
                                .background(viewModel.roleInput == "partner" ? Color.primaryRed : Color.clear)
                                .cornerRadius(8)
                        }
                        .buttonStyle(PlainButtonStyle())
                    }
                    .padding(4)
                    .background(Color.bgInput)
                    .cornerRadius(10)
                    
                    Spacer().frame(height: 24)
                    
                    // 3. Inputs
                    VStack(spacing: 16) {
                        CustomInputField(
                            label: "Full Name",
                            placeholder: "Enter full name",
                            iconName: "person",
                            text: $viewModel.nameInput
                        )
                        
                        CustomInputField(
                            label: "Email Address",
                            placeholder: "Enter email",
                            iconName: "envelope",
                            text: $viewModel.emailInput
                        )
                        
                        CustomInputField(
                            label: "Phone Number",
                            placeholder: "Enter phone number",
                            iconName: "phone",
                            text: $viewModel.phoneInput
                        )
                        
                        CustomInputField(
                            label: "Password",
                            placeholder: "Create password",
                            iconName: "lock",
                            text: $viewModel.passwordInput,
                            isSecure: true
                        )
                        
                        if viewModel.roleInput == "partner" {
                            CustomInputField(
                                label: "PAN Card Number",
                                placeholder: "Enter PAN Card",
                                iconName: "creditcard",
                                text: $viewModel.panCardInput
                            )
                        }
                    }
                    
                    Spacer().frame(height: 32)
                    
                    // 4. Sign Up Button
                    Button(action: {
                        viewModel.register()
                    }) {
                        HStack(spacing: 8) {
                            if case .loading = viewModel.authState {
                                ProgressView()
                                    .progressViewStyle(CircularProgressViewStyle(tint: .white))
                            } else {
                                Text("Register Now")
                                    .font(.system(size: 16, weight: .bold))
                                    .foregroundColor(.white)
                                Image(systemName: "checkmark.circle")
                                    .font(.system(size: 14, weight: .bold))
                                    .foregroundColor(.white)
                            }
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: 54)
                        .background(Color.primaryRed)
                        .cornerRadius(12)
                    }
                    .buttonStyle(ScaleOnPressButtonStyle())
                    .disabled({
                        if case .loading = viewModel.authState { return true }
                        return false
                    }())
                    
                    Spacer().frame(height: 24)
                    
                    // 5. Back to Login switcher
                    HStack(spacing: 4) {
                        Spacer()
                        Text("Already have an account?")
                            .font(.system(size: 14))
                            .foregroundColor(.textMuted)
                        Button(action: onNavigateToLogin) {
                            Text("Sign In")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(.primaryRed)
                        }
                        Spacer()
                    }
                    .padding(.bottom, 24)
                }
                .padding(.horizontal, 24)
            }
            
            // Toast Overlay
            if showingToast {
                VStack {
                    Spacer()
                    ToastView(message: toastMsg)
                }
                .onAppear {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                        showingToast = false
                    }
                }
            }
        }
        .onChange(of: viewModel.toastMessage) { val in
            if let msg = val {
                toastMsg = msg
                showingToast = true
                viewModel.toastMessage = nil
            }
        }
        .onChange(of: viewModel.authState) { state in
            if case .success = state {
                onRegistrationSuccess()
            }
        }
    }
}
