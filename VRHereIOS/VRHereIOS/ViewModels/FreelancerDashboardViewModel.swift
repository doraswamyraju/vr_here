import Foundation
import Combine

@MainActor
class FreelancerDashboardViewModel: ObservableObject {
    @Published var orders: [OrderResponse] = []
    @Published var broadcasts: [OrderResponse] = []
    @Published var ledger: [PayoutResponse] = []
    @Published var supportTickets: [TicketResponse] = []
    @Published var notifications: [NotificationResponse] = []
    
    // Inputs for profile setting update
    @Published var nameInput = ""
    @Published var phoneInput = ""
    @Published var skillsInput = ""
    @Published var experienceInput = ""
    @Published var resumeUrlInput = ""
    @Published var panCardInput = ""
    
    // Bank details inputs
    @Published var bankAccountNameInput = ""
    @Published var bankAccountNumberInput = ""
    @Published var bankIfscCodeInput = ""
    @Published var bankNameInput = ""
    
    @Published var isLoading = false
    @Published var isSavingProfile = false
    @Published var toastMessage: String? = nil
    
    func syncFreelancerData() {
        Task {
            await syncFreelancerDataAsync()
        }
    }
    
    func syncFreelancerDataAsync() async {
        isLoading = true
        do {
            async let ordersCall = NetworkManager.shared.getFreelancerOrders()
            async let broadcastsCall = NetworkManager.shared.getFreelancerBroadcasts()
            async let ledgerCall = NetworkManager.shared.getFreelancerLedger()
            async let ticketsCall = NetworkManager.shared.getTickets()
            async let notificationsCall = NetworkManager.shared.getNotifications()
            
            let (o, b, l, t, n) = try await (ordersCall, broadcastsCall, ledgerCall, ticketsCall, notificationsCall)
            
            self.orders = o
            self.broadcasts = b
            self.ledger = l
            self.supportTickets = t
            self.notifications = n
            
            isLoading = false
        } catch {
            if !error.isCancellationError {
                isLoading = false
                toastMessage = "Sync error: \(error.localizedDescription)"
            }
        }
    }
    
    func claimJob(orderId: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.claimBroadcast(orderId: orderId)
                toastMessage = "Job claimed successfully!"
                await syncFreelancerDataAsync()
            } catch {
                isLoading = false
                toastMessage = "Claim failed: \(error.localizedDescription)"
            }
        }
    }
    
    func clockIn(orderId: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.clockInFreelancer(orderId: orderId)
                toastMessage = "Clocked in successfully!"
                await syncFreelancerDataAsync()
            } catch {
                isLoading = false
                toastMessage = "Clock-in failed: \(error.localizedDescription)"
            }
        }
    }
    
    func clockOut(orderId: String, notes: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.clockOutFreelancer(orderId: orderId, notes: notes)
                toastMessage = "Clocked out successfully!"
                await syncFreelancerDataAsync()
            } catch {
                isLoading = false
                toastMessage = "Clock-out failed: \(error.localizedDescription)"
            }
        }
    }
    
    func replyToTicket(ticketId: String, message: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.addTicketMessage(ticketId: ticketId, message: message)
                toastMessage = "Reply posted successfully!"
                await syncFreelancerDataAsync()
            } catch {
                isLoading = false
                toastMessage = "Reply failed: \(error.localizedDescription)"
            }
        }
    }
    
    func updateProfile() {
        guard !nameInput.isEmpty else {
            toastMessage = "Name cannot be empty"
            return
        }
        guard !phoneInput.isEmpty else {
            toastMessage = "Phone cannot be empty"
            return
        }
        
        isSavingProfile = true
        Task {
            do {
                let bankDict: [String: AnyCodable] = [
                    "accountName": AnyCodable(bankAccountNameInput),
                    "accountNumber": AnyCodable(bankAccountNumberInput),
                    "ifscCode": AnyCodable(bankIfscCodeInput),
                    "bankName": AnyCodable(bankNameInput)
                ]
                
                let payload: [String: AnyCodable] = [
                    "name": AnyCodable(nameInput),
                    "phone": AnyCodable(phoneInput),
                    "skills": AnyCodable(skillsInput),
                    "yearsOfExperience": AnyCodable(Int(experienceInput) ?? 0),
                    "resumeUrl": AnyCodable(resumeUrlInput),
                    "panCard": AnyCodable(panCardInput),
                    "bankDetails": AnyCodable(bankDict)
                ]
                
                _ = try await NetworkManager.shared.updateFreelancerProfile(payload: payload)
                toastMessage = "Profile update submitted for admin approval!"
                isSavingProfile = false
            } catch {
                isSavingProfile = false
                toastMessage = "Profile update failed: \(error.localizedDescription)"
            }
        }
    }
    
    func markNotificationAsRead(id: String) {
        Task {
            do {
                _ = try await NetworkManager.shared.markNotificationAsRead(id: id)
                if let index = notifications.firstIndex(where: { $0.id == id }) {
                    var n = notifications[index]
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
}
