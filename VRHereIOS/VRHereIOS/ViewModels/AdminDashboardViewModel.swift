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
                print("Failed notification read update")
            }
        }
    }
    
    func syncDashboardData(silent: Bool = false) {
        if !silent {
            isLoading = true
        }
        Task {
            do {
                // 1. Fetch Orders
                if let ords = try? await NetworkManager.shared.getOrders() {
                    orders = ords
                }
                
                // 2. Fetch Todos
                if let tds = try? await NetworkManager.shared.getTodos() {
                    todos = tds
                }
                
                // 3. Fetch Employees
                if let emps = try? await NetworkManager.shared.getEmployees() {
                    employees = emps
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
                    print("Admin notification fetch failed")
                }
                
                // 5. Fetch Payments
                if let pays = try? await NetworkManager.shared.getPayments() {
                    payments = pays
                }
                
                isLoading = false
            } catch {
                if !silent {
                    isLoading = false
                    toastMessage = "Sync error: \(error.localizedDescription)"
                }
            }
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
}
