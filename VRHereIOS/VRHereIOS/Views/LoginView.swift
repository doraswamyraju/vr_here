import SwiftUI

struct LoginView: View {
    @ObservedObject var viewModel: AuthViewModel
    let onNavigateToRegister: () -> Void
    let onLoginSuccess: (String) -> Void
    
    @State private var showingToast = false
    @State private var toastMsg = ""
    
    var body: some View {
        ZStack {
            Color.white
                .ignoresSafeArea()
            
            VStack(alignment: .leading, spacing: 0) {
                Spacer().frame(height: 40)
                
                // 1. VR HERE Branding Header
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
                
                Spacer().frame(height: 44)
                
                // 2. Sign In Headers
                Text("Sign In")
                    .font(.system(size: 36, weight: .bold))
                    .foregroundColor(.textDark)
                
                Spacer().frame(height: 8)
                
                Text("Please enter your details to continue.")
                    .font(.system(size: 15))
                    .foregroundColor(.textMuted)
                
                Spacer().frame(height: 40)
                
                // 3. Email Input
                CustomInputField(
                    label: "Email Address",
                    placeholder: "Email Address",
                    iconName: "envelope",
                    text: $viewModel.emailInput
                )
                
                Spacer().frame(height: 20)
                
                // 4. Password Input
                CustomInputField(
                    label: "Password",
                    placeholder: "Password",
                    iconName: "lock",
                    text: $viewModel.passwordInput,
                    isSecure: true
                )
                
                Spacer().frame(height: 16)
                
                // 5. Forgot Password Trigger
                HStack {
                    Spacer()
                    Button(action: {
                        toastMsg = "Password reset link sent to your registered email."
                        showingToast = true
                    }) {
                        Text("Forgot Password?")
                            .font(.system(size: 14, weight: .bold))
                            .foregroundColor(.primaryRed)
                    }
                    .buttonStyle(PlainButtonStyle())
                }
                
                Spacer().frame(height: 32)
                
                // 6. Sign In Button
                Button(action: {
                    viewModel.login()
                }) {
                    HStack(spacing: 8) {
                        if case .loading = viewModel.authState {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: .white))
                        } else {
                            Text("Sign In")
                                .font(.system(size: 16, weight: .bold))
                                .foregroundColor(.white)
                            Image(systemName: "arrow.right")
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
                
                Spacer().frame(height: 20)
                
                // OR Divider
                HStack {
                    VStack { Divider() }
                    Text("OR")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 8)
                    VStack { Divider() }
                }
                
                Spacer().frame(height: 16)
                
                // Google Sign In Button
                Button(action: {
                    viewModel.signInWithGoogle()
                }) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 16)
                            .fill(
                                LinearGradient(
                                    gradient: Gradient(colors: [
                                        Color(red: 0.918, green: 0.263, blue: 0.208),
                                        Color(red: 0.984, green: 0.737, blue: 0.02),
                                        Color(red: 0.204, green: 0.659, blue: 0.325),
                                        Color(red: 0.259, green: 0.522, blue: 0.957)
                                    ]),
                                    startPoint: .leading,
                                    endPoint: .trailing
                                )
                            )
                        
                        HStack(spacing: 8) {
                            Text("G")
                                .font(.system(size: 22, weight: .black))
                                .foregroundColor(Color(red: 0.918, green: 0.263, blue: 0.208))
                            Text("Continue with Google")
                                .font(.system(size: 15, weight: .bold))
                                .foregroundColor(.textDark)
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .background(Color.white)
                        .cornerRadius(14)
                        .padding(2)
                    }
                    .frame(maxWidth: .infinity)
                    .frame(height: 54)
                    .shadow(color: Color(red: 0.918, green: 0.263, blue: 0.208).opacity(0.35), radius: 8, x: 0, y: 4)
                }
                .buttonStyle(ScaleOnPressButtonStyle())
                
                Spacer()
                
                // 7. Sign Up Switcher
                HStack(spacing: 4) {
                    Spacer()
                    Text("Don't have an account?")
                        .font(.system(size: 14))
                        .foregroundColor(.textMuted)
                    Button(action: onNavigateToRegister) {
                        Text("Sign Up")
                            .font(.system(size: 14, weight: .bold))
                            .foregroundColor(.primaryRed)
                    }
                    Spacer()
                }
                .padding(.bottom, 24)
            }
            .padding(.horizontal, 24)
            
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
            if case .success(let role) = state {
                onLoginSuccess(role)
            }
        }
    }
}

// SwiftUI 5 Preview structures can be added or ignored.
struct LoginView_Previews: PreviewProvider {
    static var previews: some View {
        LoginView(viewModel: AuthViewModel(), onNavigateToRegister: {}, onLoginSuccess: {_ in})
    }
}
