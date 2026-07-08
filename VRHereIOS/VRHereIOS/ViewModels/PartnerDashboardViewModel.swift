import Foundation
import Combine

enum PartnerDashboardState {
    case idle
    case loading
    case success
    case error(String)
}

@MainActor
class PartnerDashboardViewModel: ObservableObject {
    @Published var dashboardState: PartnerDashboardState = .idle
    
    @Published var orders: [PartnerOrderResponse] = []
    @Published var profile: PartnerProfileResponse? = nil
    @Published var notifications: [NotificationResponse] = []
    
    // Settings inputs
    @Published var nameInput = ""
    @Published var panCardInput = ""
    @Published var bankAccountNameInput = ""
    @Published var bankAccountNumberInput = ""
    @Published var bankIfscCodeInput = ""
    @Published var bankNameInput = ""
    
    @Published var isSavingProfile = false
    @Published var toastMessage: String? = nil
    @Published var profileUpdatedEvent = false
    
    func refreshAllData() {
        Task {
            await refreshAllDataAsync()
        }
    }
    
    func refreshAllDataAsync() async {
        dashboardState = .loading
        do {
            async let profileCall = NetworkManager.shared.getPartnerProfile()
            async let ordersCall = NetworkManager.shared.getPartnerOrders()
            async let notificationsCall = NetworkManager.shared.getNotifications()
            
            let (p, ords, notifs) = try await (profileCall, ordersCall, notificationsCall)
            self.profile = p
            self.orders = ords
            self.notifications = notifs
            
            self.nameInput = p.name
            self.panCardInput = p.panCard ?? ""
            if let bank = p.bankDetails {
                self.bankAccountNameInput = bank.accountName
                self.bankAccountNumberInput = bank.accountNumber
                self.bankIfscCodeInput = bank.ifscCode
                self.bankNameInput = bank.bankName
            }
            
            dashboardState = .success
        } catch {
            if !error.isCancellationError {
                dashboardState = .error(error.localizedDescription)
                toastMessage = "Sync error: \(error.localizedDescription)"
            }
        }
    }
    
    func markNotificationAsRead(id: String) {
        Task {
            do {
                _ = try await NetworkManager.shared.markNotificationAsRead(id: id)
                if let index = notifications.firstIndex(where: { $0.id == id }) {
                    let n = notifications[index]
                    notifications[index] = NotificationResponse(
                        idVal: n.idVal,
                        title: n.title,
                        message: n.message,
                        type: n.type,
                        isRead: true,
                        createdAt: n.createdAt
                    )
                }
            } catch {
                print("Failed to mark notification \(id) as read: \(error)")
            }
        }
    }
    
    func updateProfile() {
        guard !nameInput.isEmpty else {
            toastMessage = "Name cannot be empty"
            return
        }
        guard !panCardInput.isEmpty else {
            toastMessage = "PAN Card cannot be empty"
            return
        }
        
        isSavingProfile = true
        Task {
            do {
                let bank = BankDetails(
                    accountName: bankAccountNameInput,
                    accountNumber: bankAccountNumberInput,
                    ifscCode: bankIfscCodeInput,
                    bankName: bankNameInput
                )
                let dto = PartnerProfileUpdateDto(
                    name: nameInput,
                    panCard: panCardInput,
                    bankDetails: bank
                )
                let updated = try await NetworkManager.shared.updatePartnerProfile(profile: dto)
                profile = updated
                toastMessage = "Profile updated successfully!"
                profileUpdatedEvent = true
            } catch {
                toastMessage = "Failed to update profile: \(error.localizedDescription)"
            }
            isSavingProfile = false
        }
    }
}
