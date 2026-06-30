import Foundation
import Combine

enum DashboardState {
    case idle
    case loading
    case success
    case error(String)
}

@MainActor
class CustomerDashboardViewModel: ObservableObject {
    @Published var dashboardState: DashboardState = .idle
    
    @Published var orders: [OrderResponse] = []
    @Published var payments: [PaymentResponse] = []
    @Published var tickets: [TicketResponse] = []
    @Published var notifications: [NotificationResponse] = []
    
    @Published var activeBannerNotification: NotificationResponse? = nil
    
    @Published var ticketSubject = ""
    @Published var ticketDescription = ""
    @Published var ticketPriority = "Low"
    @Published var ticketReplyMessage = ""
    
    @Published var toastMessage: String? = nil
    @Published var ticketCreatedEvent = false
    
    init() {
        refreshAllData()
        startFirestoreListener()
    }
    
    private func startFirestoreListener() {
        FirebaseNotificationHelper.shared.startListening { [weak self] list in
            guard let self = self else { return }
            DispatchQueue.main.async {
                let oldList = self.notifications
                if !oldList.isEmpty && !list.isEmpty {
                    let newUnreads = list.filter { item in
                        !item.isRead && !oldList.contains(where: { $0.id == item.id })
                    }
                    if let latest = newUnreads.first {
                        self.activeBannerNotification = latest
                    }
                }
                self.notifications = list
            }
        }
    }
    
    deinit {
        FirebaseNotificationHelper.shared.stopListening()
    }
    
    func dismissBanner() {
        activeBannerNotification = nil
    }
    
    func refreshAllData(silent: Bool = false) {
        Task {
            await refreshAllDataAsync(silent: silent)
        }
    }
    
    func refreshAllDataAsync(silent: Bool = false) async {
        if !silent {
            dashboardState = .loading
        }
        
        var hasErrors = false
        var lastErrorMessage = ""
        
        // 1. Fetch Orders
        do {
            orders = try await NetworkManager.shared.getOrders()
        } catch {
            if !error.isCancellationError {
                hasErrors = true
                lastErrorMessage = "Orders: \(error.localizedDescription)"
                print("Orders sync failed: \(error)")
            }
        }
        
        // 2. Fetch Payments
        do {
            payments = try await NetworkManager.shared.getPayments()
        } catch {
            if !error.isCancellationError {
                hasErrors = true
                lastErrorMessage = "Payments: \(error.localizedDescription)"
                print("Payments sync failed: \(error)")
            }
        }
        
        // 3. Fetch Tickets
        do {
            tickets = try await NetworkManager.shared.getTickets()
        } catch {
            if !error.isCancellationError {
                hasErrors = true
                lastErrorMessage = "Tickets: \(error.localizedDescription)"
                print("Tickets sync failed: \(error)")
            }
        }
        
        // 4. Fetch Notifications
        do {
            let newNotifications = try await NetworkManager.shared.getNotifications()
            if !notifications.isEmpty && !newNotifications.isEmpty {
                let newUnreads = newNotifications.filter { item in
                    !item.isRead && !notifications.contains(where: { $0.id == item.id })
                }
                if let latest = newUnreads.first {
                    activeBannerNotification = latest
                }
            }
            notifications = newNotifications
        } catch {
            print("Notifications sync failed: \(error)")
        }
        
        if hasErrors {
            if !silent {
                dashboardState = .error(lastErrorMessage)
                toastMessage = lastErrorMessage
            }
        } else {
            dashboardState = .success
        }
    }
    
    func createSupportTicket() {
        guard !ticketSubject.isEmpty && !ticketDescription.isEmpty else {
            toastMessage = "Please enter subject and description"
            return
        }
        
        Task {
            do {
                let newTicket = try await NetworkManager.shared.createTicket(
                    subject: ticketSubject,
                    description: ticketDescription,
                    priority: ticketPriority
                )
                tickets.insert(newTicket, at: 0)
                ticketSubject = ""
                ticketDescription = ""
                ticketPriority = "Low"
                toastMessage = "Support ticket raised successfully!"
                ticketCreatedEvent = true
            } catch {
                toastMessage = "Failed to create ticket: \(error.localizedDescription)"
            }
        }
    }
    
    func replyToTicket(ticketId: String) {
        guard !ticketReplyMessage.isEmpty else { return }
        
        Task {
            do {
                let updatedTicket = try await NetworkManager.shared.addTicketMessage(ticketId: ticketId, message: ticketReplyMessage)
                if let index = tickets.firstIndex(where: { $0.id == ticketId }) {
                    tickets[index] = updatedTicket
                }
                ticketReplyMessage = ""
                toastMessage = "Reply sent!"
            } catch {
                toastMessage = "Failed to reply: \(error.localizedDescription)"
            }
        }
    }
    
    func markNotificationAsRead(id: String) {
        FirebaseNotificationHelper.shared.markAsRead(notificationId: id)
        Task {
            do {
                _ = try await NetworkManager.shared.markNotificationAsRead(id: id)
            } catch {
                print("Failed to mark notification \(id) as read: \(error)")
            }
        }
    }
}
