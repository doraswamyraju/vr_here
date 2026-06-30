import Foundation
import Combine

enum AuthState: Equatable {
    case idle
    case loading
    case success(role: String)
    case error(message: String)
}

@MainActor
class AuthViewModel: ObservableObject {
    @Published var authState: AuthState = .idle
    
    @Published var nameInput = ""
    @Published var emailInput = ""
    @Published var phoneInput = ""
    @Published var passwordInput = ""
    @Published var panCardInput = ""
    @Published var roleInput = "client"
    
    @Published var toastMessage: String? = nil
    
    init() {
        if SessionManager.shared.isLoggedIn() {
            let role = SessionManager.shared.getUserRole()
            authState = .success(role: role.isEmpty ? "client" : role)
        }
    }
    
    func login() {
        guard !emailInput.isEmpty && !passwordInput.isEmpty else {
            toastMessage = "Please enter email and password"
            return
        }
        
        authState = .loading
        Task {
            do {
                let request = LoginRequest(email: emailInput, password: passwordInput)
                let authData = try await NetworkManager.shared.login(request: request)
                SessionManager.shared.saveSession(
                    token: authData.token,
                    userId: authData.id,
                    name: authData.name,
                    email: authData.email,
                    role: authData.role,
                    isActive: authData.isActive
                )
                SessionManager.shared.savePhone(authData.phone ?? "")
                SessionManager.shared.saveFirebaseCustomToken(authData.firebaseCustomToken)
                
                FirebaseNotificationHelper.shared.startListening { _ in }
                
                // Sync FCM Token here if we have it
                if let token = SessionManager.shared.getFcmToken() {
                    _ = try? await NetworkManager.shared.updateFcmToken(token: token)
                }
                
                authState = .success(role: authData.role)
                toastMessage = "Welcome back, \(authData.name)!"
            } catch {
                let errorMsg = error.localizedDescription
                authState = .error(message: errorMsg)
                toastMessage = errorMsg
            }
        }
    }
    
    func register() {
        guard !nameInput.isEmpty && !emailInput.isEmpty && !phoneInput.isEmpty && !passwordInput.isEmpty else {
            toastMessage = "Please fill in all details"
            return
        }
        
        if roleInput == "partner" && panCardInput.isEmpty {
            toastMessage = "PAN card is strictly required for partners"
            return
        }
        
        authState = .loading
        Task {
            do {
                let authData: AuthResponse
                if roleInput == "partner" {
                    let reqObj = RegisterPartnerRequest(
                        name: nameInput,
                        email: emailInput,
                        phone: phoneInput,
                        password: passwordInput,
                        panCard: panCardInput
                    )
                    authData = try await NetworkManager.shared.registerPartner(request: reqObj)
                } else {
                    let reqObj = RegisterRequest(
                        name: nameInput,
                        email: emailInput,
                        phone: phoneInput,
                        password: passwordInput
                    )
                    authData = try await NetworkManager.shared.register(request: reqObj)
                }
                
                SessionManager.shared.saveSession(
                    token: authData.token,
                    userId: authData.id,
                    name: authData.name,
                    email: authData.email,
                    role: authData.role,
                    isActive: authData.isActive
                )
                SessionManager.shared.savePhone(authData.phone ?? "")
                SessionManager.shared.saveFirebaseCustomToken(authData.firebaseCustomToken)
                
                FirebaseNotificationHelper.shared.startListening { _ in }
                
                if authData.isActive {
                    authState = .success(role: authData.role)
                    toastMessage = "Registration successful!"
                } else {
                    authState = .idle
                    toastMessage = "Partner registered successfully! Account is pending admin validation."
                }
            } catch {
                let errorMsg = error.localizedDescription
                authState = .error(message: errorMsg)
                toastMessage = errorMsg
            }
        }
    }
    
    func logout() {
        SessionManager.shared.clearSession()
        authState = .idle
        emailInput = ""
        passwordInput = ""
        nameInput = ""
        phoneInput = ""
        panCardInput = ""
        roleInput = "client"
    }
    
    func isUserLoggedIn() -> Bool {
        return SessionManager.shared.isLoggedIn()
    }
    
    func getUserRole() -> String {
        let role = SessionManager.shared.getUserRole()
        return role.isEmpty ? "client" : role
    }
    
    func getUserName() -> String {
        return SessionManager.shared.getUserName()
    }
}
