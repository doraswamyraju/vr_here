import Foundation
import Combine

@MainActor
class EmployeeDashboardViewModel: ObservableObject {
    @Published var attendanceLogs: [AttendanceResponse] = []
    @Published var assignedOrders: [OrderResponse] = []
    @Published var assignedTodos: [TodoResponse] = []
    @Published var supportTickets: [TicketResponse] = []
    @Published var notifications: [NotificationResponse] = []
    
    @Published var isClockedIn = false
    @Published var currentAttendanceRecord: AttendanceResponse? = nil
    @Published var clockInNote = ""
    
    @Published var isLoading = false
    @Published var toastMessage: String? = nil
    
    func syncDashboardData() {
        Task {
            await syncDashboardDataAsync()
        }
    }
    
    func syncDashboardDataAsync() async {
        isLoading = true
        do {
            // Fetch attendance logs
            let logs = try await NetworkManager.shared.getAttendance()
            attendanceLogs = logs
            let activeRecord = logs.first { $0.clockOutAt == nil }
            isClockedIn = activeRecord != nil
            currentAttendanceRecord = activeRecord
            
            // Fetch assigned orders/tasks
            let orders = try await NetworkManager.shared.getOrders()
            assignedOrders = orders
            
            // Fetch todos
            let todos = try await NetworkManager.shared.getTodos()
            assignedTodos = todos
            
            // Fetch tickets
            let tickets = try await NetworkManager.shared.getTickets()
            supportTickets = tickets
            
            // Fetch notifications
            let notifs = try await NetworkManager.shared.getNotifications()
            notifications = notifs
            
            isLoading = false
        } catch {
            if !error.isCancellationError {
                isLoading = false
                toastMessage = "Sync error: \(error.localizedDescription)"
            }
        }
    }
    
    func updateTodoStatus(todoId: String, status: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.updateTodoStatus(id: todoId, status: status)
                toastMessage = "Todo status updated!"
                syncDashboardData()
            } catch {
                isLoading = false
                toastMessage = "Failed: \(error.localizedDescription)"
            }
        }
    }
    
    func updateOrderStatus(orderId: String, status: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.updateOrderStatus(id: orderId, status: status)
                toastMessage = "Order status updated!"
                syncDashboardData()
            } catch {
                isLoading = false
                toastMessage = "Failed: \(error.localizedDescription)"
            }
        }
    }
    
    func updateTaskStatus(orderId: String, taskId: String, status: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.updateTaskStatus(orderId: orderId, taskId: taskId, status: status)
                toastMessage = "Task status updated!"
                syncDashboardData()
            } catch {
                isLoading = false
                toastMessage = "Failed: \(error.localizedDescription)"
            }
        }
    }
    
    func updateSubtaskStatus(orderId: String, taskId: String, subtaskId: String, isCompleted: Bool, status: String) {
        isLoading = true
        Task {
            do {
                let fields: [String: AnyCodable] = [
                    "isCompleted": AnyCodable(isCompleted),
                    "status": AnyCodable(status)
                ]
                _ = try await NetworkManager.shared.updateSubtask(orderId: orderId, taskId: taskId, subtaskId: subtaskId, fields: fields)
                toastMessage = "Subtask updated!"
                syncDashboardData()
            } catch {
                isLoading = false
                toastMessage = "Failed: \(error.localizedDescription)"
            }
        }
    }
    
    func logTaskTime(orderId: String, taskId: String, minutes: Int, notes: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.logTaskTime(orderId: orderId, taskId: taskId, minutes: minutes, note: notes)
                toastMessage = "Logged \(minutes) minutes successfully!"
                syncDashboardData()
            } catch {
                isLoading = false
                toastMessage = "Failed to log time: \(error.localizedDescription)"
            }
        }
    }
    
    func updateRequirementStatus(orderId: String, requirementId: String, status: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.updateRequirementStatus(orderId: orderId, requirementId: requirementId, status: status)
                toastMessage = "Requirement status updated!"
                syncDashboardData()
            } catch {
                isLoading = false
                toastMessage = "Failed: \(error.localizedDescription)"
            }
        }
    }
    
    func raiseRequirement(orderId: String, title: String, type: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.raiseRequirement(orderId: orderId, title: title, description: type)
                toastMessage = "New query raised!"
                syncDashboardData()
            } catch {
                isLoading = false
                toastMessage = "Failed: \(error.localizedDescription)"
            }
        }
    }
    
    func uploadFinalCertificate(orderId: String, fileData: Data, fileName: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.uploadFinalCertificate(orderId: orderId, fileData: fileData, fileName: fileName)
                toastMessage = "Final certificate uploaded successfully!"
                syncDashboardData()
            } catch {
                isLoading = false
                toastMessage = "Upload error: \(error.localizedDescription)"
            }
        }
    }
    
    func markNotificationAsRead(notificationId: String) {
        Task {
            do {
                _ = try await NetworkManager.shared.markNotificationAsRead(id: notificationId)
                syncDashboardData()
            } catch {
                print("Failed read status sync")
            }
        }
    }
    
    func toggleClockStatus() {
        isLoading = true
        Task {
            do {
                if isClockedIn {
                    _ = try await NetworkManager.shared.clockOut()
                    isClockedIn = false
                    currentAttendanceRecord = nil
                    toastMessage = "Successfully Clocked Out!"
                    syncDashboardData()
                } else {
                    let record = try await NetworkManager.shared.clockIn(notes: clockInNote)
                    isClockedIn = true
                    currentAttendanceRecord = record
                    clockInNote = ""
                    toastMessage = "Successfully Clocked In!"
                    syncDashboardData()
                }
                isLoading = false
            } catch {
                isLoading = false
                toastMessage = "Network error: \(error.localizedDescription)"
            }
        }
    }
}
