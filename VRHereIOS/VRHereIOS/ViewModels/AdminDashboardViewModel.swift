import Foundation
import Combine

@MainActor
class AdminDashboardViewModel: ObservableObject {
    @Published var orders: [OrderResponse] = []
    @Published var todos: [TodoResponse] = []
    @Published var employees: [EmployeeResponse] = []
    @Published var notifications: [NotificationResponse] = []
    @Published var payments: [PaymentResponse] = []
    @Published var activeBannerNotification: NotificationResponse? = nil
    @Published var freelancers: [FreelancerResponse] = []
    @Published var assessments: [ITAssessmentResponse] = []
    @Published var complianceRecords: [ComplianceResponse] = []
    @Published var financeRecords: [FinanceRecordResponse] = []
    @Published var users: [UserResponse] = []
    @Published var tickets: [TicketResponse] = []
    @Published var recurring: [RecurringResponse] = []
    @Published var isLoading = false
    @Published var toastMessage: String? = nil
    
    init() {
        syncDashboardData()
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
    
    // Dynamic Calculations
    var activePipelineCount: Int {
        return orders.filter { $0.status != "Completed" }.count
    }
    
    var totalPipelineValue: Double {
        return orders.reduce(0.0) { $0 + $1.price }
    }
    
    var statTotalOrders: Int {
        return orders.count
    }
    
    var statPending: Int {
        return orders.filter { $0.status != "Completed" }.count
    }
    
    var statCompleted: Int {
        return orders.filter { $0.status == "Completed" }.count
    }
    
    func dismissBanner() {
        activeBannerNotification = nil
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
    
    func syncDashboardData(silent: Bool = false) {
        Task {
            await syncDashboardDataAsync(silent: silent)
        }
    }
    
    func syncDashboardDataAsync(silent: Bool = false) async {
        if !silent {
            isLoading = true
        }
        do {
            // 1. Fetch Orders
            do {
                orders = try await NetworkManager.shared.getOrders()
            } catch {
                if !error.isCancellationError {
                    print("ORDER DECODING ERROR: \(error)")
                    toastMessage = "Order parse failed: \(String(describing: error))"
                }
            }
            
            // 2. Fetch Todos
            do {
                todos = try await NetworkManager.shared.getTodos()
            } catch {
                print("TODO DECODING ERROR: \(error)")
            }
            
            // 3. Fetch Employees
            do {
                employees = try await NetworkManager.shared.getEmployees()
            } catch {
                print("EMPLOYEE DECODING ERROR: \(error)")
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
                print("Admin notification fetch failed: \(error)")
            }
            
            // 5. Fetch Payments
            do {
                payments = try await NetworkManager.shared.getPayments()
            } catch {
                print("PAYMENT DECODING ERROR: \(error)")
            }
            
            // 6. Fetch Freelancers
            do {
                freelancers = try await NetworkManager.shared.getAdminFreelancers()
            } catch {
                print("FREELANCER DECODING ERROR: \(error)")
            }
            
            // 7. Fetch Assessments
            do {
                assessments = try await NetworkManager.shared.getIncomeTaxAssessments()
            } catch {
                print("ASSESSMENT DECODING ERROR: \(error)")
            }
            
            // 8. Fetch Compliance
            do {
                complianceRecords = try await NetworkManager.shared.getComplianceRecords()
            } catch {
                print("COMPLIANCE DECODING ERROR: \(error)")
            }
            
            // 9. Fetch Finance
            do {
                financeRecords = try await NetworkManager.shared.getFinanceRecords(type: "Invoice")
            } catch {
                print("FINANCE DECODING ERROR: \(error)")
            }
            
            // 10. Fetch Users
            do {
                users = try await NetworkManager.shared.getUsers()
            } catch {
                print("USERS DECODING ERROR: \(error)")
            }
            
            // 11. Fetch Tickets
            do {
                tickets = try await NetworkManager.shared.getTickets()
            } catch {
                print("TICKETS DECODING ERROR: \(error)")
            }
            
            // 12. Fetch Recurring
            do {
                recurring = try await NetworkManager.shared.getRecurring()
            } catch {
                print("RECURRING DECODING ERROR: \(error)")
            }
            
            isLoading = false
        } catch {
            if !silent && !error.isCancellationError {
                isLoading = false
                toastMessage = "Sync error: \(error.localizedDescription)"
            }
        }
    }
    
    func updateAssessmentStatus(id: String, status: String, notes: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.updateIncomeTaxAssessmentStatus(id: id, status: status, notes: notes)
                toastMessage = "Assessment status updated successfully!"
                syncDashboardData()
            } catch {
                toastMessage = "Status update failed: \(error.localizedDescription)"
            }
            isLoading = false
        }
    }
    
    func updateComplianceStatus(id: String, status: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.updateComplianceStatus(id: id, status: status)
                toastMessage = "Compliance status updated!"
                syncDashboardData()
            } catch {
                toastMessage = "Failed: \(error.localizedDescription)"
            }
            isLoading = false
        }
    }
    
    func fetchFinanceRecords(type: String) {
        isLoading = true
        Task {
            do {
                financeRecords = try await NetworkManager.shared.getFinanceRecords(type: type)
            } catch {
                toastMessage = "Failed to load \(type) records: \(error.localizedDescription)"
            }
            isLoading = false
        }
    }
    
    func createOrder(fields: [String: AnyCodable], completion: @escaping (Bool) -> Void) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.createOrder(fields: fields)
                toastMessage = "New order created successfully!"
                syncDashboardData()
                completion(true)
            } catch {
                toastMessage = "Order creation failed: \(error.localizedDescription)"
                completion(false)
            }
            isLoading = false
        }
    }
    
    func createTodo(request: CreateTodoRequest, completion: @escaping (Bool) -> Void) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.createTodo(request: request)
                toastMessage = "Task added successfully!"
                syncDashboardData()
                completion(true)
            } catch {
                toastMessage = "Failed to create task: \(error.localizedDescription)"
                completion(false)
            }
            isLoading = false
        }
    }
    
    // --- USER MANAGEMENT ACTIONS ---
    func createUser(name: String, email: String, phone: String, role: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.createUser(name: name, email: email, phone: phone, role: role)
                toastMessage = "User created successfully!"
                syncDashboardData()
            } catch {
                toastMessage = "Failed to create user: \(error.localizedDescription)"
            }
            isLoading = false
        }
    }
    
    func toggleUserActive(id: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.toggleUserActive(id: id)
                toastMessage = "User status toggled!"
                syncDashboardData()
            } catch {
                toastMessage = "Failed: \(error.localizedDescription)"
            }
            isLoading = false
        }
    }
    
    func deleteUser(id: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.deleteUser(id: id)
                toastMessage = "User deleted successfully"
                syncDashboardData()
            } catch {
                toastMessage = "Failed to delete user: \(error.localizedDescription)"
            }
            isLoading = false
        }
    }
    
    // --- RECURRING HUB ACTIONS ---
    func toggleRecurringStatus(id: String, isActive: Bool) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.updateRecurringStatus(id: id, isActive: isActive)
                toastMessage = "Subscription status updated!"
                syncDashboardData()
            } catch {
                toastMessage = "Failed: \(error.localizedDescription)"
            }
            isLoading = false
        }
    }
    
    func deleteRecurring(id: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.deleteRecurring(id: id)
                toastMessage = "Subscription removed"
                syncDashboardData()
            } catch {
                toastMessage = "Failed: \(error.localizedDescription)"
            }
            isLoading = false
        }
    }
    
    // --- TO-DO TOGGLE STATUS ACTION ---
    func toggleTodoStatus(todo: TodoResponse) {
        let newStatus = todo.completed ? "Pending" : "Completed"
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.updateTodoStatus(id: todo.idVal, status: newStatus)
                toastMessage = "Task updated successfully!"
                syncDashboardData()
            } catch {
                toastMessage = "Failed to update task: \(error.localizedDescription)"
            }
            isLoading = false
        }
    }
}
