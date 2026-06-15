import Foundation
import Combine

@MainActor
class HrmsViewModel: ObservableObject {
    @Published var isLoading = false
    @Published var errorMessage: String? = nil
    
    @Published var leaves: [LeaveResponse] = []
    @Published var adminLeaves: [LeaveResponse] = []
    @Published var holidays: [HolidayResponse] = []
    @Published var notices: [NoticeResponse] = []
    @Published var liveStatus: LiveStatusResponse? = nil
    
    @Published var toastMessage: String? = nil
    @Published var leaveSubmitted = false
    @Published var leaveProcessed = false
    @Published var bulletinCreated = false
    
    func clearError() {
        errorMessage = nil
    }
    
    // --- EMPLOYEE OPERATIONS ---
    
    func fetchMyLeaves() {
        isLoading = true
        errorMessage = nil
        Task {
            do {
                leaves = try await NetworkManager.shared.getMyLeaves()
                isLoading = false
            } catch {
                isLoading = false
                errorMessage = "Failed to load leave history: \(error.localizedDescription)"
            }
        }
    }
    
    func applyLeave(startDate: String, endDate: String, type: String, reason: String) {
        isLoading = true
        errorMessage = nil
        Task {
            do {
                _ = try await NetworkManager.shared.applyLeave(startDate: startDate, endDate: endDate, type: type, reason: reason)
                toastMessage = "Leave request submitted! Admins alerted."
                leaveSubmitted = true
                fetchMyLeaves()
            } catch {
                isLoading = false
                toastMessage = "Apply leave failed: \(error.localizedDescription)"
            }
        }
    }
    
    // --- ADMIN OPERATIONS ---
    
    func fetchAdminLeaves() {
        isLoading = true
        errorMessage = nil
        Task {
            do {
                adminLeaves = try await NetworkManager.shared.getAdminLeaves()
                isLoading = false
            } catch {
                isLoading = false
                errorMessage = "Failed to load admin leaves: \(error.localizedDescription)"
            }
        }
    }
    
    func approveLeave(leaveId: String, status: String, adminNotes: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.approveLeave(id: leaveId, status: status, adminNotes: adminNotes)
                toastMessage = "Leave request updated successfully!"
                leaveProcessed = true
                fetchAdminLeaves()
            } catch {
                isLoading = false
                toastMessage = "Failed to process: \(error.localizedDescription)"
            }
        }
    }
    
    func fetchLiveStatus() {
        isLoading = true
        errorMessage = nil
        Task {
            do {
                liveStatus = try await NetworkManager.shared.getLiveStatus()
                isLoading = false
            } catch {
                isLoading = false
                errorMessage = "Failed to load live tracking: \(error.localizedDescription)"
            }
        }
    }
    
    // --- ANNOUNCEMENTS & HOLIDAYS ---
    
    func fetchBulletins() {
        isLoading = true
        errorMessage = nil
        Task {
            do {
                async let holidaysCall = NetworkManager.shared.getHolidays()
                async let noticesCall = NetworkManager.shared.getNotices()
                
                let (hRes, nRes) = try await (holidaysCall, noticesCall)
                holidays = hRes
                notices = nRes
                isLoading = false
            } catch {
                isLoading = false
                errorMessage = "Failed to load announcement feeds: \(error.localizedDescription)"
            }
        }
    }
    
    func createHoliday(title: String, date: String, description: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.createHoliday(title: title, date: date, description: description)
                toastMessage = "Company holiday declared!"
                bulletinCreated = true
                fetchBulletins()
            } catch {
                isLoading = false
                toastMessage = "Failed to create holiday: \(error.localizedDescription)"
            }
        }
    }
    
    func deleteHoliday(id: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.deleteHoliday(id: id)
                toastMessage = "Holiday removed successfully"
                fetchBulletins()
            } catch {
                isLoading = false
                toastMessage = "Network error: \(error.localizedDescription)"
            }
        }
    }
    
    func createNotice(title: String, message: String, priority: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.createNotice(title: title, message: message, priority: priority)
                toastMessage = "Notice published! Staff notified."
                bulletinCreated = true
                fetchBulletins()
            } catch {
                isLoading = false
                toastMessage = "Failed to publish: \(error.localizedDescription)"
            }
        }
    }
    
    func deleteNotice(id: String) {
        isLoading = true
        Task {
            do {
                _ = try await NetworkManager.shared.deleteNotice(id: id)
                toastMessage = "Notice deleted successfully"
                fetchBulletins()
            } catch {
                isLoading = false
                toastMessage = "Network error: \(error.localizedDescription)"
            }
        }
    }
}
