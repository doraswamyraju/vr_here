import Foundation

enum NetworkError: Error, LocalizedError {
    case invalidURL
    case noData
    case apiError(String)
    case unauthorized
    case decodingError(Error)
    
    var errorDescription: String? {
        switch self {
        case .invalidURL: return "The URL generated was invalid."
        case .noData: return "No response data was returned by the server."
        case .apiError(let message): return message
        case .unauthorized: return "Unauthorized access. Please login again."
        case .decodingError(let error): return "JSON decoding failure: \(error.localizedDescription)"
        }
    }
}

class NetworkManager {
    static let shared = NetworkManager()
    
    private let baseURL = "https://vrhere.in/"
    
    private init() {}
    
    // Core Request wrapper
    private func performRequest<T: Codable>(
        path: String,
        method: String,
        body: Data? = nil,
        headers: [String: String] = [:],
        isMultipart: Bool = false,
        boundary: String? = nil
    ) async throws -> T {
        guard let url = URL(string: baseURL + path) else {
            throw NetworkError.invalidURL
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = method
        
        // Add default headers
        if isMultipart, let boundary = boundary {
            request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        } else {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        
        // Add Authorization header
        if let token = SessionManager.shared.getAuthToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        
        // Add extra headers
        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }
        
        if let body = body {
            request.httpBody = body
        }
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw NetworkError.noData
        }
        
        if httpResponse.statusCode == 401 {
            throw NetworkError.unauthorized
        }
        
        guard (200...299).contains(httpResponse.statusCode) else {
            // Try parsing error message from JSON response
            if let errorObj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let message = errorObj["message"] as? String {
                throw NetworkError.apiError(message)
            }
            throw NetworkError.apiError("Server returned code \(httpResponse.statusCode)")
        }
        
        do {
            let decoder = JSONDecoder()
            // Some date formatting configs if needed, standard JSONDecoder handles rest
            return try decoder.decode(T.self, from: data)
        } catch {
            print("Decoding error for \(T.self): \(error)")
            throw NetworkError.decodingError(error)
        }
    }
    
    // --- AUTHENTICATION ---
    
    func login(request: LoginRequest) async throws -> AuthResponse {
        let data = try JSONEncoder().encode(request)
        return try await performRequest(path: "api/auth/login", method: "POST", body: data)
    }
    
    func register(request: RegisterRequest) async throws -> AuthResponse {
        let data = try JSONEncoder().encode(request)
        return try await performRequest(path: "api/auth/register", method: "POST", body: data)
    }
    
    func registerPartner(request: RegisterPartnerRequest) async throws -> AuthResponse {
        let data = try JSONEncoder().encode(request)
        return try await performRequest(path: "api/auth/register-partner", method: "POST", body: data)
    }
    
    func getProfile() async throws -> UserProfile {
        return try await performRequest(path: "api/auth/profile", method: "GET")
    }
    
    // --- ORDERS ---
    
    func getOrders() async throws -> [OrderResponse] {
        return try await performRequest(path: "api/orders", method: "GET")
    }
    
    func getOrderById(id: String) async throws -> OrderResponse {
        return try await performRequest(path: "api/orders/\(id)", method: "GET")
    }
    
    func updateOrderStatus(id: String, status: String) async throws -> OrderResponse {
        let payload = ["status": status]
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/orders/\(id)/status", method: "PUT", body: data)
    }
    
    // --- PAYMENTS ---
    
    func getPayments() async throws -> [PaymentResponse] {
        return try await performRequest(path: "api/payments", method: "GET")
    }
    
    func checkoutOrder(payload: CheckoutPayload) async throws -> CheckoutOrderResponse {
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/payments/checkout-order", method: "POST", body: data)
    }
    
    func verifyPayment(payload: VerifyPayload) async throws -> VerifyResponse {
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/payments/verify", method: "POST", body: data)
    }
    
    // --- TICKETS ---
    
    func getTickets() async throws -> [TicketResponse] {
        return try await performRequest(path: "api/tickets", method: "GET")
    }
    
    func createTicket(subject: String, description: String, priority: String) async throws -> TicketResponse {
        let requestObj = CreateTicketRequest(subject: subject, description: description, priority: priority)
        let data = try JSONEncoder().encode(requestObj)
        return try await performRequest(path: "api/tickets", method: "POST", body: data)
    }
    
    func addTicketMessage(ticketId: String, message: String) async throws -> TicketResponse {
        let requestObj = AddMessageRequest(message: message)
        let data = try JSONEncoder().encode(requestObj)
        return try await performRequest(path: "api/tickets/\(ticketId)/messages", method: "POST", body: data)
    }
    
    // --- NOTIFICATIONS ---
    
    func getNotifications() async throws -> [NotificationResponse] {
        return try await performRequest(path: "api/notifications", method: "GET")
    }
    
    func markNotificationAsRead(id: String) async throws -> NotificationResponse {
        return try await performRequest(path: "api/notifications/\(id)/read", method: "PUT")
    }
    
    func updateFcmToken(token: String) async throws -> [String: AnyCodable] {
        let payload = ["token": token]
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/auth/fcm-token", method: "PUT", body: data)
    }
    
    func deleteAccount() async throws -> GeneralResponse {
        return try await performRequest(path: "api/auth/delete-account", method: "DELETE")
    }
    
    // --- ATTENDANCE ---
    
    func getAttendance() async throws -> [AttendanceResponse] {
        return try await performRequest(path: "api/attendance/my-logs", method: "GET")
    }
    
    func clockIn(notes: String) async throws -> AttendanceResponse {
        let req = ClockInRequest(notes: notes)
        let data = try JSONEncoder().encode(req)
        let wrapper: AttendanceSessionWrapper = try await performRequest(path: "api/attendance/clock-in", method: "POST", body: data)
        return wrapper.session
    }
    
    func clockOut() async throws -> AttendanceResponse {
        let wrapper: AttendanceSessionWrapper = try await performRequest(path: "api/attendance/clock-out", method: "POST")
        return wrapper.session
    }
    
    // --- HRMS Endpoints ---
    
    func applyLeave(startDate: String, endDate: String, type: String, reason: String) async throws -> [String: AnyCodable] {
        let req = LeaveRequest(startDate: startDate, endDate: endDate, type: type, reason: reason)
        let data = try JSONEncoder().encode(req)
        return try await performRequest(path: "api/hrms/leaves", method: "POST", body: data)
    }
    
    func getMyLeaves() async throws -> [LeaveResponse] {
        return try await performRequest(path: "api/hrms/leaves/my", method: "GET")
    }
    
    func getAdminLeaves() async throws -> [LeaveResponse] {
        return try await performRequest(path: "api/hrms/leaves/admin", method: "GET")
    }
    
    func approveLeave(id: String, status: String, adminNotes: String) async throws -> [String: AnyCodable] {
        let req = ApproveLeaveRequest(status: status, adminNotes: adminNotes)
        let data = try JSONEncoder().encode(req)
        return try await performRequest(path: "api/hrms/leaves/\(id)/approve", method: "PUT", body: data)
    }
    
    func getHolidays() async throws -> [HolidayResponse] {
        return try await performRequest(path: "api/hrms/holidays", method: "GET")
    }
    
    func createHoliday(title: String, date: String, description: String) async throws -> [String: AnyCodable] {
        let req = HolidayRequest(title: title, date: date, description: description)
        let data = try JSONEncoder().encode(req)
        return try await performRequest(path: "api/hrms/holidays", method: "POST", body: data)
    }
    
    func deleteHoliday(id: String) async throws -> [String: AnyCodable] {
        return try await performRequest(path: "api/hrms/holidays/\(id)", method: "DELETE")
    }
    
    func getNotices() async throws -> [NoticeResponse] {
        return try await performRequest(path: "api/hrms/notices", method: "GET")
    }
    
    func createNotice(title: String, message: String, priority: String) async throws -> [String: AnyCodable] {
        let req = NoticeRequest(title: title, message: message, priority: priority)
        let data = try JSONEncoder().encode(req)
        return try await performRequest(path: "api/hrms/notices", method: "POST", body: data)
    }
    
    func deleteNotice(id: String) async throws -> [String: AnyCodable] {
        return try await performRequest(path: "api/hrms/notices/\(id)", method: "DELETE")
    }
    
    func getLiveStatus() async throws -> LiveStatusResponse {
        return try await performRequest(path: "api/hrms/admin/live-status", method: "GET")
    }
    
    // --- PARTNER ---
    
    func getPartnerOrders() async throws -> [PartnerOrderResponse] {
        return try await performRequest(path: "api/partner/orders", method: "GET")
    }
    
    func getPartnerProfile() async throws -> PartnerProfileResponse {
        return try await performRequest(path: "api/partner/profile", method: "GET")
    }
    
    func updatePartnerProfile(profile: PartnerProfileUpdateDto) async throws -> PartnerProfileResponse {
        let data = try JSONEncoder().encode(profile)
        return try await performRequest(path: "api/partner/profile", method: "PUT", body: data)
    }
    
    // --- ADMIN COMMANDS ---
    
    func createOrder(fields: [String: AnyCodable]) async throws -> OrderResponse {
        let data = try JSONEncoder().encode(fields)
        return try await performRequest(path: "api/orders", method: "POST", body: data)
    }
    
    func getTodos() async throws -> [TodoResponse] {
        return try await performRequest(path: "api/todos", method: "GET")
    }
    
    func createTodo(request: CreateTodoRequest) async throws -> TodoResponse {
        let data = try JSONEncoder().encode(request)
        return try await performRequest(path: "api/todos", method: "POST", body: data)
    }
    
    func getEmployees() async throws -> [EmployeeResponse] {
        return try await performRequest(path: "api/auth/employees", method: "GET")
    }
    
    // --- EMPLOYEE TRANSACTION Endpoints ---
    
    func updateTodoStatus(id: String, status: String) async throws -> TodoResponse {
        let payload = ["status": status]
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/todos/\(id)", method: "PUT", body: data)
    }
    
    func updateTaskStatus(orderId: String, taskId: String, status: String) async throws -> OrderResponse {
        let payload = ["status": status]
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/orders/\(orderId)/tasks/\(taskId)", method: "PUT", body: data)
    }
    
    func updateSubtask(orderId: String, taskId: String, subtaskId: String, fields: [String: AnyCodable]) async throws -> OrderResponse {
        let data = try JSONEncoder().encode(fields)
        return try await performRequest(path: "api/orders/\(orderId)/tasks/\(taskId)/subtasks/\(subtaskId)", method: "PUT", body: data)
    }
    
    func logTaskTime(orderId: String, taskId: String, minutes: Int, note: String) async throws -> OrderResponse {
        let payload: [String: AnyCodable] = [
            "minutes": AnyCodable(minutes),
            "note": AnyCodable(note)
        ]
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/orders/\(orderId)/tasks/\(taskId)/time-log", method: "POST", body: data)
    }
    
    func updateRequirementStatus(orderId: String, requirementId: String, status: String) async throws -> OrderResponse {
        let payload = ["status": status]
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/orders/\(orderId)/requirements/\(requirementId)/status", method: "PUT", body: data)
    }
    
    func raiseRequirement(orderId: String, title: String, description: String) async throws -> OrderResponse {
        let payload = ["title": title, "description": description]
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/orders/\(orderId)/requirements", method: "POST", body: data)
    }
    
    func uploadFinalCertificate(orderId: String, fileData: Data, fileName: String) async throws -> OrderResponse {
        let boundary = "Boundary-\(UUID().uuidString)"
        var body = Data()
        
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"document\"; filename=\"\(fileName)\"\r\n".data(using: .utf8)!)
        body.append("Content-Type: application/pdf\r\n\r\n".data(using: .utf8)!)
        body.append(fileData)
        body.append("\r\n".data(using: .utf8)!)
        body.append("--\(boundary)--\r\n".data(using: .utf8)!)
        
        return try await performRequest(
            path: "api/orders/\(orderId)/documents",
            method: "POST",
            body: body,
            isMultipart: true,
            boundary: boundary
        )
    }
    
    // --- DYNAMIC SERVER-DRIVEN SERVICES ---
    
    func getDynamicServices() async throws -> [MobileServiceDetail] {
        return try await performRequest(path: "api/service-pages", method: "GET")
    }
    
    func getAdminFreelancers() async throws -> [FreelancerResponse] {
        return try await performRequest(path: "api/freelancer/admin/users", method: "GET")
    }
    
    // --- FREELANCER ACTIONS ---
    
    func getFreelancerBroadcasts() async throws -> [OrderResponse] {
        return try await performRequest(path: "api/freelancer/broadcasts", method: "GET")
    }
    
    func claimBroadcast(orderId: String) async throws -> OrderResponse {
        return try await performRequest(path: "api/freelancer/claim/\(orderId)", method: "POST")
    }
    
    func getFreelancerOrders() async throws -> [OrderResponse] {
        return try await performRequest(path: "api/freelancer/orders", method: "GET")
    }
    
    func getFreelancerLedger() async throws -> [PayoutResponse] {
        return try await performRequest(path: "api/freelancer/ledger", method: "GET")
    }
    
    func clockInFreelancer(orderId: String) async throws -> FreelancerClockResponse {
        return try await performRequest(path: "api/freelancer/clock-in/\(orderId)", method: "POST")
    }
    
    func clockOutFreelancer(orderId: String, notes: String) async throws -> FreelancerClockResponse {
        let payload = ["notes": notes]
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/freelancer/clock-out/\(orderId)", method: "POST", body: data)
    }
    
    func updateFreelancerProfile(payload: [String: AnyCodable]) async throws -> UserResponse {
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/freelancer/profile-update", method: "PUT", body: data)
    }

    
    func getIncomeTaxAssessments() async throws -> [ITAssessmentResponse] {
        return try await performRequest(path: "api/income-tax-assessment", method: "GET")
    }
    
    func updateIncomeTaxAssessmentStatus(id: String, status: String, notes: String) async throws -> ITAssessmentResponse {
        let payload = ["status": status, "notes": notes]
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/income-tax-assessment/\(id)/status", method: "PUT", body: data)
    }
    
    // --- COMPLIANCE ENDPOINTS ---
    func getComplianceRecords() async throws -> [ComplianceResponse] {
        return try await performRequest(path: "api/compliance", method: "GET")
    }
    
    func updateComplianceStatus(id: String, status: String) async throws -> [String: AnyCodable] {
        let payload = ["status": status]
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/compliance/\(id)", method: "PUT", body: data)
    }
    
    // --- FINANCE ENDPOINTS ---
    func getFinanceRecords(type: String) async throws -> [FinanceRecordResponse] {
        return try await performRequest(path: "api/finance?type=\(type)", method: "GET")
    }
    
    func createFinanceRecord(payload: [String: AnyCodable]) async throws -> FinanceRecordResponse {
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/finance", method: "POST", body: data)
    }
    
    func deleteFinanceRecord(id: String) async throws -> [String: AnyCodable] {
        return try await performRequest(path: "api/finance/\(id)", method: "DELETE")
    }
    
    // --- USER MANAGEMENT ENDPOINTS ---
    func getUsers() async throws -> [UserResponse] {
        return try await performRequest(path: "api/auth/users", method: "GET")
    }
    
    func createUser(name: String, email: String, phone: String, role: String) async throws -> UserResponse {
        let payload = ["name": name, "email": email, "phone": phone, "role": role]
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/auth/users", method: "POST", body: data)
    }
    
    func updateUser(id: String, name: String, email: String, phone: String, role: String) async throws -> UserResponse {
        let payload = ["name": name, "email": email, "phone": phone, "role": role]
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/auth/users/\(id)", method: "PUT", body: data)
    }
    
    func toggleUserActive(id: String) async throws -> UserResponse {
        return try await performRequest(path: "api/auth/users/\(id)/toggle-active", method: "PATCH")
    }
    
    func deleteUser(id: String) async throws -> [String: AnyCodable] {
        return try await performRequest(path: "api/auth/users/\(id)", method: "DELETE")
    }
    
    // --- RECURRING HUB ENDPOINTS ---
    func getRecurring() async throws -> [RecurringResponse] {
        return try await performRequest(path: "api/recurring", method: "GET")
    }
    
    func updateRecurringStatus(id: String, isActive: Bool) async throws -> [String: AnyCodable] {
        let payload = ["isActive": isActive]
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/recurring/\(id)", method: "PUT", body: data)
    }
    
    func deleteRecurring(id: String) async throws -> [String: AnyCodable] {
        return try await performRequest(path: "api/recurring/\(id)", method: "DELETE")
    }
}

// AnyCodable helper struct to encode/decode dynamic types in Swift
struct AnyCodable: Codable {
    let value: Any
    
    init(_ value: Any) {
        self.value = value
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let string = try? container.decode(String.self) {
            value = string
        } else if let int = try? container.decode(Int.self) {
            value = int
        } else if let double = try? container.decode(Double.self) {
            value = double
        } else if let bool = try? container.decode(Bool.self) {
            value = bool
        } else if let array = try? container.decode([AnyCodable].self) {
            value = array.map { $0.value }
        } else if let dictionary = try? container.decode([String: AnyCodable].self) {
            value = dictionary.mapValues { $0.value }
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unable to decode AnyCodable")
        }
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        if let string = value as? String {
            try container.encode(string)
        } else if let int = value as? Int {
            try container.encode(int)
        } else if let double = value as? Double {
            try container.encode(double)
        } else if let bool = value as? Bool {
            try container.encode(bool)
        } else if let array = value as? [Any] {
            try container.encode(array.map { AnyCodable($0) })
        } else if let dictionary = value as? [String: Any] {
            try container.encode(dictionary.mapValues { AnyCodable($0) })
        } else {
            throw EncodingError.invalidValue(value, EncodingError.Context(codingPath: encoder.codingPath, debugDescription: "Unable to encode AnyCodable"))
        }
    }
}

struct FreelancerResponse: Codable, Identifiable {
    let id: String
    let name: String
    let email: String
    let role: String
    
    enum CodingKeys: String, CodingKey {
        case id = "_id"
        case name, email, role
    }
}

struct ITAssessmentResponse: Codable, Identifiable {
    let id: String
    let clientName: String
    let pan: String
    let financialYear: String
    let assessmentYear: String
    let status: String
    
    enum CodingKeys: String, CodingKey {
        case id = "_id"
        case clientName, pan, financialYear, assessmentYear, status
    }
}

extension Error {
    var isCancellationError: Bool {
        if self is CancellationError {
            return true
        }
        let nsError = self as NSError
        if nsError.domain == NSURLErrorDomain && nsError.code == -999 {
            return true
        }
        return false
    }
}
