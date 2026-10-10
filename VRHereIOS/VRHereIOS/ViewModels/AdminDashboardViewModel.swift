import Foundation
import Combine
import UIKit
import UserNotifications

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
    @Published var selectedOrderFilter: String = "All"
    @Published var selectedOrderId: String = ""
    @Published var isLoading = false
    @Published var toastMessage: String? = nil
    
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
    
    func updateAppBadge() {
        let unread = notifications.filter { !$0.isRead }.count
        if #available(iOS 16.0, *) {
            UNUserNotificationCenter.current().setBadgeCount(unread) { _ in }
        } else {
            UIApplication.shared.applicationIconBadgeNumber = unread
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
                updateAppBadge()
            } catch {
                print("Failed notification read update")
            }
        }
    }
    
    func markAllNotificationsAsRead() {
        Task {
            for n in notifications where !n.isRead {
                _ = try? await NetworkManager.shared.markNotificationAsRead(id: n.id)
            }
            notifications = notifications.map { n in
                NotificationResponse(
                    idVal: n.idVal,
                    title: n.title,
                    message: n.message,
                    type: n.type,
                    isRead: true,
                    createdAt: n.createdAt
                )
            }
            updateAppBadge()
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
                updateAppBadge()
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
    
    // --- COMPREHENSIVE ORDER MANAGEMENT ACTIONS ---
    
    func updateOrderStatus(orderId: String, status: String, completion: ((Bool) -> Void)? = nil) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.updateOrderStatus(id: orderId, status: status)
                toastMessage = "Order status updated to \(status)"
                syncDashboardData()
                completion?(true)
            } catch {
                toastMessage = "Failed to update status: \(error.localizedDescription)"
                completion?(false)
            }
            isLoading = false
        }
    }
    
    func updateOrderAssignments(orderId: String, employeeId: String? = nil, makerId: String? = nil, checkerId: String? = nil, projectManagerId: String? = nil, completion: ((Bool) -> Void)? = nil) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.assignOrder(id: orderId, employeeId: employeeId, makerId: makerId, checkerId: checkerId, projectManagerId: projectManagerId)
                toastMessage = "Assignments updated successfully!"
                syncDashboardData()
                completion?(true)
            } catch {
                toastMessage = "Failed to update assignments: \(error.localizedDescription)"
                completion?(false)
            }
            isLoading = false
        }
    }
    
    func updateOrderCommercials(orderId: String, packageName: String, price: Double, serviceName: String, completion: ((Bool) -> Void)? = nil) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.updateOrderCommercials(id: orderId, packageName: packageName, price: price, serviceName: serviceName)
                toastMessage = "Commercials saved successfully!"
                syncDashboardData()
                completion?(true)
            } catch {
                toastMessage = "Failed to save commercials: \(error.localizedDescription)"
                completion?(false)
            }
            isLoading = false
        }
    }
    
    func deleteOrder(orderId: String, completion: ((Bool) -> Void)? = nil) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.deleteOrder(id: orderId)
                toastMessage = "Project deleted successfully"
                if selectedOrderId == orderId {
                    selectedOrderId = ""
                }
                syncDashboardData()
                completion?(true)
            } catch {
                toastMessage = "Failed to delete project: \(error.localizedDescription)"
                completion?(false)
            }
            isLoading = false
        }
    }
    
    func updateTaskStatus(orderId: String, taskId: String, status: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.updateTaskStatus(orderId: orderId, taskId: taskId, status: status)
                toastMessage = "Task status updated"
                syncDashboardData()
            } catch {
                toastMessage = "Failed to update task: \(error.localizedDescription)"
            }
            isLoading = false
        }
    }
    
    func assignTask(orderId: String, taskId: String, employeeId: String? = nil, freelancerId: String? = nil) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.assignTask(orderId: orderId, taskId: taskId, employeeId: employeeId, freelancerId: freelancerId)
                toastMessage = "Task assigned successfully"
                syncDashboardData()
            } catch {
                toastMessage = "Failed to assign task: \(error.localizedDescription)"
            }
            isLoading = false
        }
    }
    
    func updateSubtask(orderId: String, taskId: String, subtaskId: String, isCompleted: Bool, status: String) {
        let payload: [String: AnyCodable] = [
            "isCompleted": AnyCodable(isCompleted),
            "status": AnyCodable(status)
        ]
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.updateSubtask(orderId: orderId, taskId: taskId, subtaskId: subtaskId, fields: payload)
                toastMessage = "Subtask updated"
                syncDashboardData()
            } catch {
                toastMessage = "Failed to update subtask: \(error.localizedDescription)"
            }
            isLoading = false
        }
    }
    
    func addOrderTask(orderId: String, title: String, taskCode: String, description: String, ownerRole: String, completion: ((Bool) -> Void)? = nil) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.addOrderTask(orderId: orderId, title: title, taskCode: taskCode, description: description, ownerRole: ownerRole)
                toastMessage = "Task added to project"
                syncDashboardData()
                completion?(true)
            } catch {
                toastMessage = "Failed to add task: \(error.localizedDescription)"
                completion?(false)
            }
            isLoading = false
        }
    }
    
    func updateRequirementStatus(orderId: String, requirementId: String, status: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.updateRequirementStatus(orderId: orderId, requirementId: requirementId, status: status)
                toastMessage = "Document status updated to \(status)"
                syncDashboardData()
            } catch {
                toastMessage = "Failed: \(error.localizedDescription)"
            }
            isLoading = false
        }
    }
    
    func raiseRequirement(orderId: String, title: String, description: String, completion: ((Bool) -> Void)? = nil) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.raiseRequirement(orderId: orderId, title: title, description: description)
                toastMessage = "Requirement raised"
                syncDashboardData()
                completion?(true)
            } catch {
                toastMessage = "Failed: \(error.localizedDescription)"
                completion?(false)
            }
            isLoading = false
        }
    }
    
    func deleteRequirement(orderId: String, requirementId: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.deleteRequirement(orderId: orderId, requirementId: requirementId)
                toastMessage = "Requirement deleted"
                syncDashboardData()
            } catch {
                toastMessage = "Failed: \(error.localizedDescription)"
            }
            isLoading = false
        }
    }
    
    func addOrderInvoice(orderId: String, invoiceNumber: String, amount: Double, status: String, dueDate: String? = nil, notes: String? = nil, completion: ((Bool) -> Void)? = nil) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.addOrderInvoice(orderId: orderId, invoiceNumber: invoiceNumber, amount: amount, status: status, dueDate: dueDate, notes: notes)
                toastMessage = "Invoice generated successfully"
                syncDashboardData()
                completion?(true)
            } catch {
                toastMessage = "Failed: \(error.localizedDescription)"
                completion?(false)
            }
            isLoading = false
        }
    }
    
    func updateInvoiceStatus(orderId: String, invoiceId: String, status: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.updateInvoiceStatus(orderId: orderId, invoiceId: invoiceId, status: status)
                toastMessage = "Invoice marked as \(status)"
                syncDashboardData()
            } catch {
                toastMessage = "Failed: \(error.localizedDescription)"
            }
            isLoading = false
        }
    }
}
