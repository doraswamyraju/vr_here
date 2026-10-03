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
    
    private let keyProfilePhoto = "profile_photo"
    private let keyCompanyLogo = "company_logo"
    private let keyCompanyName = "company_name"
    private let keyBusinessType = "business_type"
    private let keyGstin = "gstin"
    private let keyPanNumber = "pan_number"
    private let keyAddress = "address"
    
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
    
    func getToken() -> String? {
        return getAuthToken()
    }
    
    func getUserId() -> String? {
        return prefs.string(forKey: keyUserId)
    }
    
    func saveUserName(_ name: String) {
        prefs.set(name, forKey: keyUserName)
    }
    
    func getUserName() -> String {
        return prefs.string(forKey: keyUserName) ?? ""
    }
    
    func saveUserEmail(_ email: String) {
        prefs.set(email, forKey: keyUserEmail)
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
    
    func saveProfilePhoto(_ url: String) {
        prefs.set(url, forKey: keyProfilePhoto)
    }
    
    func getProfilePhoto() -> String {
        return prefs.string(forKey: keyProfilePhoto) ?? ""
    }
    
    func saveCompanyLogo(_ url: String) {
        prefs.set(url, forKey: keyCompanyLogo)
    }
    
    func getCompanyLogo() -> String {
        return prefs.string(forKey: keyCompanyLogo) ?? ""
    }
    
    func saveCompanyName(_ name: String) {
        prefs.set(name, forKey: keyCompanyName)
    }
    
    func getCompanyName() -> String {
        return prefs.string(forKey: keyCompanyName) ?? ""
    }
    
    func saveBusinessType(_ type: String) {
        prefs.set(type, forKey: keyBusinessType)
    }
    
    func getBusinessType() -> String {
        return prefs.string(forKey: keyBusinessType) ?? "Private Limited"
    }
    
    func saveGstin(_ gstin: String) {
        prefs.set(gstin, forKey: keyGstin)
    }
    
    func getGstin() -> String {
        return prefs.string(forKey: keyGstin) ?? ""
    }
    
    func savePanNumber(_ pan: String) {
        prefs.set(pan, forKey: keyPanNumber)
    }
    
    func getPanNumber() -> String {
        return prefs.string(forKey: keyPanNumber) ?? ""
    }
    
    func saveAddress(_ addr: String) {
        prefs.set(addr, forKey: keyAddress)
    }
    
    func getAddress() -> String {
        return prefs.string(forKey: keyAddress) ?? ""
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
        prefs.removeObject(forKey: keyProfilePhoto)
        prefs.removeObject(forKey: keyCompanyLogo)
        prefs.removeObject(forKey: keyCompanyName)
        prefs.removeObject(forKey: keyBusinessType)
        prefs.removeObject(forKey: keyGstin)
        prefs.removeObject(forKey: keyPanNumber)
        prefs.removeObject(forKey: keyAddress)
    }
    
    func isLoggedIn() -> Bool {
        return getAuthToken() != nil
    }
}
