import Foundation
import Combine
import AuthenticationServices

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
    
    // Apple Account Linking State
    @Published var showAppleLinkPrompt = false
    @Published var pendingAppleResult: AppleSignInResult? = nil
    @Published var linkEmailInput = ""
    @Published var linkPasswordInput = ""
    @Published var isLinkingWithPassword = false
    
    init() {
        if SessionManager.shared.isLoggedIn() {
            let role = SessionManager.shared.getUserRole()
            authState = .success(role: role.isEmpty ? "client" : role)
            
            if let token = SessionManager.shared.getFcmToken() {
                Task {
                    _ = try? await NetworkManager.shared.updateFcmToken(token: token)
                }
            }
        }
        
        NotificationCenter.default.addObserver(
            forName: NSNotification.Name("SessionExpiredNotification"),
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.logout()
                self?.toastMessage = "Session expired. Please sign in again."
            }
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
    
    func signInWithGoogle() {
        GoogleOAuthManager.shared.startGoogleSignIn { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .success(let res):
                self.googleLogin(idToken: res.idToken, accessToken: res.accessToken)
            case .failure(let error):
                // User cancelled or network error
                if (error as NSError).code != ASWebAuthenticationSessionError.canceledLogin.rawValue {
                    let errorMsg = error.localizedDescription
                    self.authState = .error(message: errorMsg)
                    self.toastMessage = errorMsg
                }
            }
        }
    }
    
    func googleLogin(idToken: String? = nil, accessToken: String? = nil) {
        authState = .loading
        Task {
            do {
                let authData = try await NetworkManager.shared.googleLogin(idToken: idToken, accessToken: accessToken)
                SessionManager.shared.saveSession(
                    token: authData.token,
                    userId: authData.id,
                    name: authData.name,
                    email: authData.email,
                    role: authData.role,
                    isActive: authData.isActive
                )
                SessionManager.shared.savePhone(authData.phone ?? "")
                
                if let token = SessionManager.shared.getFcmToken() {
                    _ = try? await NetworkManager.shared.updateFcmToken(token: token)
                }
                
                authState = .success(role: authData.role)
                toastMessage = "Welcome, \(authData.name)!"
            } catch {
                let errorMsg = error.localizedDescription
                authState = .error(message: errorMsg)
                toastMessage = errorMsg
            }
        }
    }
    
    func signInWithApple() {
        AppleSignInManager.shared.startAppleSignIn { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .success(let res):
                self.appleLogin(result: res)
            case .failure(let error):
                // If user cancelled, don't show error toast
                if (error as NSError).code != ASAuthorizationError.canceled.rawValue {
                    let errorMsg = error.localizedDescription
                    self.authState = .error(message: errorMsg)
                    self.toastMessage = errorMsg
                }
            }
        }
    }
    
    func appleLogin(result: AppleSignInResult, confirmNewAccount: Bool = false) {
        authState = .loading
        Task {
            do {
                let res = try await NetworkManager.shared.appleLogin(
                    identityToken: result.identityToken,
                    userIdentifier: result.userIdentifier,
                    email: result.email,
                    fullName: result,
                    confirmNewAccount: confirmNewAccount
                )
                
                // If it's a first-time user with an unlinked Apple ID, prompt them to link or create new
                if res.isNewUser == true {
                    self.pendingAppleResult = result
                    self.showAppleLinkPrompt = true
                    self.authState = .idle
                    return
                }
                
                guard let token = res.token, let id = res.id, let name = res.name, let email = res.email, let role = res.role else {
                    throw NetworkError.serverError("Incomplete user credentials from Apple Sign In")
                }
                
                SessionManager.shared.saveSession(
                    token: token,
                    userId: id,
                    name: name,
                    email: email,
                    role: role,
                    isActive: res.isActive ?? true
                )
                SessionManager.shared.savePhone(res.phone ?? "")
                
                if let fcmToken = SessionManager.shared.getFcmToken() {
                    _ = try? await NetworkManager.shared.updateFcmToken(token: fcmToken)
                }
                
                self.showAppleLinkPrompt = false
                self.pendingAppleResult = nil
                self.authState = .success(role: role)
                self.toastMessage = "Welcome, \(name)!"
            } catch {
                let errorMsg = error.localizedDescription
                self.authState = .error(message: errorMsg)
                self.toastMessage = errorMsg
            }
        }
    }
    
    func confirmCreateNewAppleAccount() {
        guard let result = pendingAppleResult else { return }
        showAppleLinkPrompt = false
        appleLogin(result: result, confirmNewAccount: true)
    }
    
    func linkAppleWithExistingPassword() {
        guard let appleResult = pendingAppleResult else { return }
        guard !linkEmailInput.isEmpty && !linkPasswordInput.isEmpty else {
            toastMessage = "Please enter your existing email and password"
            return
        }
        
        authState = .loading
        Task {
            do {
                let authData = try await NetworkManager.shared.linkAppleToExistingAccount(
                    identityToken: appleResult.identityToken,
                    userIdentifier: appleResult.userIdentifier,
                    email: linkEmailInput,
                    password: linkPasswordInput
                )
                
                SessionManager.shared.saveSession(
                    token: authData.token,
                    userId: authData.id,
                    name: authData.name,
                    email: authData.email,
                    role: authData.role,
                    isActive: authData.isActive
                )
                SessionManager.shared.savePhone(authData.phone ?? "")
                
                if let token = SessionManager.shared.getFcmToken() {
                    _ = try? await NetworkManager.shared.updateFcmToken(token: token)
                }
                
                self.showAppleLinkPrompt = false
                self.pendingAppleResult = nil
                self.authState = .success(role: authData.role)
                self.toastMessage = "Apple ID successfully linked to \(authData.email)!"
            } catch {
                let errorMsg = error.localizedDescription
                self.authState = .error(message: errorMsg)
                self.toastMessage = errorMsg
            }
        }
    }
    
    func linkAppleWithGoogle() {
        guard let appleResult = pendingAppleResult else { return }
        
        GoogleOAuthManager.shared.startGoogleSignIn { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .success(let res):
                guard let googleIdToken = res.idToken else {
                    self.toastMessage = "Google verification failed"
                    return
                }
                self.authState = .loading
                Task {
                    do {
                        let authData = try await NetworkManager.shared.linkAppleToExistingAccount(
                            identityToken: appleResult.identityToken,
                            userIdentifier: appleResult.userIdentifier,
                            googleIdToken: googleIdToken
                        )
                        
                        SessionManager.shared.saveSession(
                            token: authData.token,
                            userId: authData.id,
                            name: authData.name,
                            email: authData.email,
                            role: authData.role,
                            isActive: authData.isActive
                        )
                        SessionManager.shared.savePhone(authData.phone ?? "")
                        
                        if let token = SessionManager.shared.getFcmToken() {
                            _ = try? await NetworkManager.shared.updateFcmToken(token: token)
                        }
                        
                        self.showAppleLinkPrompt = false
                        self.pendingAppleResult = nil
                        self.authState = .success(role: authData.role)
                        self.toastMessage = "Apple ID linked to your Google account (\(authData.email))!"
                    } catch {
                        let errorMsg = error.localizedDescription
                        self.authState = .error(message: errorMsg)
                        self.toastMessage = errorMsg
                    }
                }
            case .failure(let error):
                if (error as NSError).code != ASWebAuthenticationSessionError.canceledLogin.rawValue {
                    let errorMsg = error.localizedDescription
                    self.toastMessage = errorMsg
                }
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
    
    func deleteAccount() {
        authState = .loading
        Task {
            do {
                let res = try await NetworkManager.shared.deleteAccount()
                if res.success {
                    logout()
                } else {
                    toastMessage = res.message ?? "Could not delete account."
                    authState = .idle
                }
            } catch {
                toastMessage = error.localizedDescription
                authState = .idle
            }
        }
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
