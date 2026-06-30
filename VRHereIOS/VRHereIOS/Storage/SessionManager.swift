import Foundation

class SessionManager {
    static let shared = SessionManager()
    
    private let prefs = UserDefaults.standard
    private let prefName = "vrhere_session_prefs"
    
    private let keyAuthToken = "auth_token"
    private let keyUserId = "user_id"
    private let keyUserName = "user_name"
    private let keyUserEmail = "user_email"
    private let keyUserRole = "user_role"
    private let keyUserActive = "user_active"
    private let keyUserPhone = "user_phone"
    private let keyFcmToken = "fcm_token"
    
    func saveSession(
        token: String,
        userId: String,
        name: String,
        email: String,
        role: String,
        isActive: Bool
    ) {
        prefs.set(token, forKey: keyAuthToken)
        prefs.set(userId, forKey: keyUserId)
        prefs.set(name, forKey: keyUserName)
        prefs.set(email, forKey: keyUserEmail)
        prefs.set(role, forKey: keyUserRole)
        prefs.set(isActive, forKey: keyUserActive)
    }
    
    func getAuthToken() -> String? {
        return prefs.string(forKey: keyAuthToken)
    }
    
    func getUserId() -> String? {
        return prefs.string(forKey: keyUserId)
    }
    
    func getUserName() -> String {
        return prefs.string(forKey: keyUserName) ?? ""
    }
    
    func getUserEmail() -> String {
        return prefs.string(forKey: keyUserEmail) ?? ""
    }
    
    func getUserRole() -> String {
        return prefs.string(forKey: keyUserRole) ?? ""
    }
    
    func isUserActive() -> Bool {
        return prefs.bool(forKey: keyUserActive)
    }
    
    func savePhone(_ phone: String) {
        prefs.set(phone, forKey: keyUserPhone)
    }
    
    func getPhone() -> String {
        return prefs.string(forKey: keyUserPhone) ?? ""
    }
    
    func saveFcmToken(_ token: String) {
        prefs.set(token, forKey: keyFcmToken)
    }
    
    func getFcmToken() -> String? {
        return prefs.string(forKey: keyFcmToken)
    }
    
    func clearSession() {
        prefs.removeObject(forKey: keyAuthToken)
        prefs.removeObject(forKey: keyUserId)
        prefs.removeObject(forKey: keyUserName)
        prefs.removeObject(forKey: keyUserEmail)
        prefs.removeObject(forKey: keyUserRole)
        prefs.removeObject(forKey: keyUserActive)
        prefs.removeObject(forKey: keyUserPhone)
    }
    
    func isLoggedIn() -> Bool {
        return getAuthToken() != nil
    }
}
