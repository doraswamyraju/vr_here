import Foundation

enum NetworkError: Error, LocalizedError {
    case invalidURL
    case noData
    case apiError(String)
    case unauthorized
    case decodingError(Error)
    case serverError(String)
    
    var errorDescription: String? {
        switch self {
        case .invalidURL: return "The URL generated was invalid."
        case .noData: return "No response data was returned by the server."
        case .apiError(let message): return message
        case .unauthorized: return "Unauthorized access. Please login again."
        case .decodingError(let error): return "JSON decoding failure: \(error.localizedDescription)"
        case .serverError(let message): return message
        }
    }
}

class NetworkManager {
    static let shared = NetworkManager()
    
    private let baseURL = "https://vrhere.in/"
    
    private init() {}
    
    // Core Request wrapper
    func performRequest<T: Codable>(
        path: String,
        method: String = "GET",
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
    
    func googleLogin(idToken: String? = nil, accessToken: String? = nil, code: String? = nil, redirectUri: String? = nil) async throws -> AuthResponse {
        let reqObj = GoogleAuthRequest(idToken: idToken, credential: idToken, accessToken: accessToken, code: code, redirectUri: redirectUri)
        let data = try JSONEncoder().encode(reqObj)
        return try await performRequest(path: "api/auth/google", method: "POST", body: data)
    }
    
    func appleLogin(
        identityToken: String?,
        userIdentifier: String?,
        email: String?,
        fullName: AppleSignInResult? = nil,
        givenName: String? = nil,
        familyName: String? = nil,
        confirmNewAccount: Bool = false
    ) async throws -> AppleAuthResponse {
        var fullNamePayload: AppleAuthRequest.AppleFullNamePayload? = nil
        if let gn = givenName ?? fullName?.fullName?.givenName, let fn = familyName ?? fullName?.fullName?.familyName {
            fullNamePayload = AppleAuthRequest.AppleFullNamePayload(givenName: gn, familyName: fn)
        } else if let gn = givenName ?? fullName?.fullName?.givenName {
            fullNamePayload = AppleAuthRequest.AppleFullNamePayload(givenName: gn, familyName: nil)
        }
        
        let reqObj = AppleAuthRequest(
            identityToken: identityToken,
            userIdentifier: userIdentifier,
            email: email,
            fullName: fullNamePayload,
            confirmNewAccount: confirmNewAccount
        )
        let data = try JSONEncoder().encode(reqObj)
        return try await performRequest(path: "api/auth/apple", method: "POST", body: data)
    }
    
    func linkAppleAccount(identityToken: String?, userIdentifier: String?) async throws -> SimpleSuccessResponse {
        struct LinkPayload: Codable {
            let identityToken: String?
            let userIdentifier: String?
        }
        let data = try JSONEncoder().encode(LinkPayload(identityToken: identityToken, userIdentifier: userIdentifier))
        return try await performRequest(path: "api/auth/link-apple", method: "POST", body: data)
    }
    
    func linkAppleToExistingAccount(
        identityToken: String?,
        userIdentifier: String?,
        email: String? = nil,
        password: String? = nil,
        googleIdToken: String? = nil
    ) async throws -> AuthResponse {
        let reqObj = AppleLinkExistingRequest(
            identityToken: identityToken,
            userIdentifier: userIdentifier,
            email: email,
            password: password,
            googleIdToken: googleIdToken
        )
        let data = try JSONEncoder().encode(reqObj)
        return try await performRequest(path: "api/auth/apple/link-existing", method: "POST", body: data)
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
    
    func updateProfile(request: UpdateProfileRequest) async throws -> UserProfile {
        let data = try JSONEncoder().encode(request)
        return try await performRequest(path: "api/auth/profile", method: "PUT", body: data)
    }
    
    func updatePhone(phone: String) async throws -> UserProfile {
        struct UpdatePhonePayload: Codable {
            let phone: String
        }
        let data = try JSONEncoder().encode(UpdatePhonePayload(phone: phone))
        return try await performRequest(path: "api/auth/profile", method: "PUT", body: data)
    }
    
    func uploadAvatar(imageData: Data, fileName: String = "avatar.jpg", mimeType: String = "image/jpeg") async throws -> [String: Any] {
        guard let url = URL(string: "\(baseURL)api/auth/upload-avatar") else {
            throw NetworkError.invalidURL
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        if let token = SessionManager.shared.getAuthToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        
        let boundary = "Boundary-\(UUID().uuidString)"
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        
        var body = Data()
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"image\"; filename=\"\(fileName)\"\r\n".data(using: .utf8)!)
        body.append("Content-Type: \(mimeType)\r\n\r\n".data(using: .utf8)!)
        body.append(imageData)
        body.append("\r\n".data(using: .utf8)!)
        body.append("--\(boundary)--\r\n".data(using: .utf8)!)
        
        request.httpBody = body
        
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
            let errorMsg = String(data: data, encoding: .utf8) ?? "Upload failed"
            throw NetworkError.serverError(errorMsg)
        }
        return (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
    }
    
    func uploadCompanyLogo(imageData: Data, fileName: String = "logo.png", mimeType: String = "image/png") async throws -> [String: Any] {
        guard let url = URL(string: "\(baseURL)api/auth/upload-logo") else {
            throw NetworkError.invalidURL
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        if let token = SessionManager.shared.getAuthToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        
        let boundary = "Boundary-\(UUID().uuidString)"
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        
        var body = Data()
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"image\"; filename=\"\(fileName)\"\r\n".data(using: .utf8)!)
        body.append("Content-Type: \(mimeType)\r\n\r\n".data(using: .utf8)!)
        body.append(imageData)
        body.append("\r\n".data(using: .utf8)!)
        body.append("--\(boundary)--\r\n".data(using: .utf8)!)
        
        request.httpBody = body
        
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
            let errorMsg = String(data: data, encoding: .utf8) ?? "Upload failed"
            throw NetworkError.serverError(errorMsg)
        }
        return (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
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

    // --- ORDER CHAT & MESSAGES ---
    func getOrderMessages(orderId: String, messageType: String? = nil) async throws -> [OrderChatMessage] {
        var path = "api/orders/\(orderId)/messages"
        if let type = messageType {
            path += "?messageType=\(type)"
        }
        return try await performRequest(path: path, method: "GET")
    }

    func sendOrderMessage(orderId: String, message: String, messageType: String, fileData: Data? = nil, fileName: String? = nil, mimeType: String? = nil) async throws -> OrderChatMessage {
        let boundary = "Boundary-\(UUID().uuidString)"
        guard let url = URL(string: "\(baseURL)/api/orders/\(orderId)/messages") else {
            throw URLError(.badURL)
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        if let token = SessionManager.shared.getToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        var body = Data()
        // Message field
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"message\"\r\n\r\n".data(using: .utf8)!)
        body.append("\(message)\r\n".data(using: .utf8)!)

        // MessageType field
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"messageType\"\r\n\r\n".data(using: .utf8)!)
        body.append("\(messageType)\r\n".data(using: .utf8)!)

        // Optional File Part
        if let fileData = fileData, let fileName = fileName {
            let mime = mimeType ?? "application/octet-stream"
            body.append("--\(boundary)\r\n".data(using: .utf8)!)
            body.append("Content-Disposition: form-data; name=\"file\"; filename=\"\(fileName)\"\r\n".data(using: .utf8)!)
            body.append("Content-Type: \(mime)\r\n\r\n".data(using: .utf8)!)
            body.append(fileData)
            body.append("\r\n".data(using: .utf8)!)
        }

        body.append("--\(boundary)--\r\n".data(using: .utf8)!)
        request.httpBody = body

        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
            let errorMsg = String(data: data, encoding: .utf8) ?? "Failed to send message"
            throw NSError(domain: "NetworkManager", code: (response as? HTTPURLResponse)?.statusCode ?? 500, userInfo: [NSLocalizedDescriptionKey: errorMsg])
        }

        return try JSONDecoder().decode(OrderChatMessage.self, from: data)
    }

    func getOrderUnreadCount(orderId: String) async throws -> OrderUnreadCountResponse {
        return try await performRequest(path: "api/orders/\(orderId)/messages/unread-count", method: "GET")
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
    
    func createTicket(category: String = "Service", subject: String, description: String, priority: String) async throws -> TicketResponse {
        let requestObj = CreateTicketRequest(category: category, subject: subject, description: description, priority: priority)
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
    
    func markAllNotificationsAsRead() async throws -> [String: AnyCodable] {
        return try await performRequest(path: "api/notifications/readall", method: "PUT")
    }
    
    func updateFcmToken(token: String) async throws -> [String: AnyCodable] {
        let payload = ["fcmToken": token, "token": token]
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
    
    func updateTodo(id: String, fields: [String: AnyCodable]) async throws -> TodoResponse {
        let data = try JSONEncoder().encode(fields)
        return try await performRequest(path: "api/todos/\(id)", method: "PUT", body: data)
    }
    
    func deleteTodo(id: String) async throws -> SimpleSuccessResponse {
        return try await performRequest(path: "api/todos/\(id)", method: "DELETE")
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
    
    // --- ADMIN ORDER MANAGEMENT EXTENSIONS ---
    
    func deleteOrder(id: String) async throws -> SimpleSuccessResponse {
        return try await performRequest(path: "api/orders/\(id)", method: "DELETE")
    }
    
    func assignOrder(id: String, employeeId: String? = nil, makerId: String? = nil, checkerId: String? = nil, projectManagerId: String? = nil) async throws -> OrderResponse {
        var payload: [String: AnyCodable] = [:]
        if let employeeId = employeeId { payload["assignedEmployee"] = AnyCodable(employeeId) }
        if let makerId = makerId { payload["makerId"] = AnyCodable(makerId) }
        if let checkerId = checkerId { payload["checkerId"] = AnyCodable(checkerId) }
        if let projectManagerId = projectManagerId { payload["projectManagerId"] = AnyCodable(projectManagerId) }
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/orders/\(id)/assign", method: "PUT", body: data)
    }
    
    func updateOrderCommercials(id: String, packageName: String, price: Double, serviceName: String) async throws -> OrderResponse {
        let payload: [String: AnyCodable] = [
            "packageName": AnyCodable(packageName),
            "price": AnyCodable(price),
            "serviceName": AnyCodable(serviceName)
        ]
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/orders/\(id)/commercials", method: "PUT", body: data)
    }
    
    func addOrderTask(orderId: String, title: String, taskCode: String, description: String, ownerRole: String) async throws -> OrderResponse {
        let payload: [String: AnyCodable] = [
            "title": AnyCodable(title),
            "taskCode": AnyCodable(taskCode),
            "description": AnyCodable(description),
            "ownerRole": AnyCodable(ownerRole)
        ]
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/orders/\(orderId)/tasks", method: "POST", body: data)
    }
    
    func assignTask(orderId: String, taskId: String, employeeId: String? = nil, freelancerId: String? = nil) async throws -> OrderResponse {
        var payload: [String: AnyCodable] = [:]
        if let employeeId = employeeId { payload["employeeId"] = AnyCodable(employeeId) }
        if let freelancerId = freelancerId { payload["freelancerId"] = AnyCodable(freelancerId) }
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/orders/\(orderId)/tasks/\(taskId)/assign", method: "PUT", body: data)
    }
    
    func deleteRequirement(orderId: String, requirementId: String) async throws -> OrderResponse {
        return try await performRequest(path: "api/orders/\(orderId)/requirements/\(requirementId)", method: "DELETE")
    }
    
    func addOrderInvoice(orderId: String, invoiceNumber: String, amount: Double, status: String, dueDate: String? = nil, notes: String? = nil) async throws -> OrderResponse {
        var payload: [String: AnyCodable] = [
            "invoiceNumber": AnyCodable(invoiceNumber),
            "amount": AnyCodable(amount),
            "status": AnyCodable(status)
        ]
        if let dueDate = dueDate { payload["dueDate"] = AnyCodable(dueDate) }
        if let notes = notes { payload["notes"] = AnyCodable(notes) }
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/orders/\(orderId)/invoices", method: "POST", body: data)
    }
    
    func updateInvoiceStatus(orderId: String, invoiceId: String, status: String) async throws -> OrderResponse {
        let payload = ["status": status]
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/orders/\(orderId)/invoices/\(invoiceId)/status", method: "PUT", body: data)
    }
    
    // --- LEADS & TELEMETRY CRM ENDPOINTS ---
    
    func getLeads(params: [String: String] = [:]) async throws -> LeadListResponse {
        var path = "api/leads"
        if !params.isEmpty {
            let query = params.compactMap { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? $0.value)" }.joined(separator: "&")
            path += "?\(query)"
        }
        return try await performRequest(path: path, method: "GET")
    }
    
    func getLeadStats() async throws -> LeadStatsResponse {
        return try await performRequest(path: "api/leads/stats", method: "GET")
    }
    
    func updateLead(id: String, fields: [String: AnyCodable]) async throws -> LeadResponse {
        let data = try JSONEncoder().encode(fields)
        return try await performRequest(path: "api/leads/\(id)", method: "PUT", body: data)
    }
    
    func deleteLead(id: String) async throws -> SimpleSuccessResponse {
        return try await performRequest(path: "api/leads/\(id)", method: "DELETE")
    }
    
    // --- DYNAMIC SERVER-DRIVEN SERVICES ---
    
    func getDynamicServices() async throws -> [MobileServiceDetail] {
        return try await performRequest(path: "api/service-pages", method: "GET")
    }
    
    // --- BLOGS & REGULATORY INSIGHTS CMS ---
    
    func getBlogs() async throws -> [BlogResponse] {
        return try await performRequest(path: "api/blogs", method: "GET")
    }
    
    func getBlogBySlug(slug: String) async throws -> BlogResponse {
        return try await performRequest(path: "api/blogs/\(slug)", method: "GET")
    }
    
    // --- PROMOTIONAL OFFERS & SCHEMES ---
    
    func getOffers() async throws -> [OfferResponse] {
        return try await performRequest(path: "api/offers", method: "GET")
    }
    
    // --- FINANCE & BILLING RECORDS ---
    
    func getFinanceRecords() async throws -> [FinanceRecordResponse] {
        return try await performRequest(path: "api/finance", method: "GET")
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
    
    func createComplianceTask(payload: [String: AnyCodable]) async throws -> ComplianceResponse {
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/compliance", method: "POST", body: data)
    }
    
    func updateComplianceTask(id: String, payload: [String: AnyCodable]) async throws -> ComplianceResponse {
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/compliance/\(id)", method: "PUT", body: data)
    }
    
    func deleteComplianceTask(id: String) async throws -> SimpleSuccessResponse {
        return try await performRequest(path: "api/compliance/\(id)", method: "DELETE")
    }
    
    // --- ADMIN BOOKKEEPING & FILINGS MATRIX ENDPOINTS ---
    func getAdminFilingsMatrix(month: String) async throws -> FilingsMatrixResponse {
        let encoded = month.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? month
        return try await performRequest(path: "api/accounting/filings/matrix?month=\(encoded)", method: "GET")
    }
    
    func getClientAccountingTransactions(clientId: String) async throws -> [AccountingTransaction] {
        return try await performRequest(path: "api/accounting/transactions?clientId=\(clientId)", method: "GET")
    }
    
    func updateAccountingTransactionStatus(id: String, status: String) async throws -> [String: AnyCodable] {
        let payload = ["status": status]
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/accounting/transactions/\(id)", method: "PUT", body: data)
    }
    
    func getClientPayrollRecords(clientId: String) async throws -> [AccountingPayrollRecord] {
        return try await performRequest(path: "api/accounting/payroll?clientId=\(clientId)", method: "GET")
    }
    
    func createClientPayrollRecord(payload: [String: AnyCodable]) async throws -> AccountingPayrollRecord {
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/accounting/payroll", method: "POST", body: data)
    }
    
    func getGstr3bExport(clientId: String) async throws -> Gstr3bResponseData {
        return try await performRequest(path: "api/accounting/export/gstr3b?clientId=\(clientId)", method: "GET")
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
    
    // --- PARTNER ADMIN PAYOUTS ---
    func getPartnerAdminPayouts() async throws -> [PartnerAdminPayoutItem] {
        return try await performRequest(path: "api/partner/admin/payouts", method: "GET")
    }
    
    func updatePartnerAdminPayout(id: String, payload: [String: AnyCodable]) async throws -> PartnerAdminPayoutItem {
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/partner/admin/payouts/\(id)", method: "PUT", body: data)
    }
    
    func updateTicketStatus(id: String, status: String) async throws -> TicketResponse {
        let payload = ["status": status]
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/tickets/\(id)/status", method: "PUT", body: data)
    }
    
    func getServicesHeaderConfig() async throws -> HeaderConfigResponse {
        return try await performRequest(path: "api/services/header-config", method: "GET")
    }
    
    func saveServicesHeaderConfig(config: HeaderConfigResponse) async throws -> HeaderConfigResponse {
        let data = try JSONEncoder().encode(config)
        return try await performRequest(path: "api/services/header-config", method: "PUT", body: data)
    }
    
    func updateServicesHeaderConfig(payload: [String: AnyCodable]) async throws -> [String: AnyCodable] {
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/services/header-config", method: "PUT", body: data)
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
    
    // --- SERVICE PAGES & LEADS TELEMETRY ---
    
    func fetchServicePageConfig(pageId: String) async throws -> ServicePageResponseModel {
        return try await performRequest(path: "api/service-pages/\(pageId)", method: "GET")
    }
    
    func sendLeadTelemetry(
        serviceId: String,
        serviceName: String,
        packageName: String? = nil,
        price: Double? = nil,
        category: String = "PAGE_VIEW"
    ) async {
        let payload = LeadTelemetryPayload(
            customerId: SessionManager.shared.getUserId(),
            customerName: SessionManager.shared.getUserName(),
            email: SessionManager.shared.getUserEmail(),
            phone: SessionManager.shared.getPhone(),
            serviceId: serviceId,
            serviceName: serviceName,
            packageName: packageName,
            price: price,
            category: category,
            source: "ios",
            deviceInfo: "iOS App"
        )
        do {
            let data = try JSONEncoder().encode(payload)
            let _: [String: AnyCodable]? = try? await performRequest(path: "api/leads/telemetry", method: "POST", body: data)
        } catch {
            print("Lead telemetry error: \(error)")
        }
    }
    
    // --- CUSTOMER REFERRAL API ---
    
    func getCustomerReferralStats() async throws -> CustomerReferralStatsResponse {
        return try await performRequest(path: "api/customer/referrals/stats")
    }
    
    func addCustomerReferralLead(name: String, phone: String, email: String?, interestedService: String?) async throws -> GeneralResponse {
        let payload = AddReferralLeadRequest(name: name, phone: phone, email: email, interestedService: interestedService)
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/customer/referrals/lead", method: "POST", body: data)
    }
    
    func requestCustomerUpiPayout(amount: Double, upiId: String) async throws -> GeneralResponse {
        let payload = UpiPayoutRequest(amount: amount, upiId: upiId)
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/customer/referrals/payout-request", method: "POST", body: data)
    }
    
    // --- ORDER REQUIREMENTS & UPLOAD API ---
    
    func updateOrderRequirement(orderId: String, requirementId: String, clientValue: String?, clientNotes: String?, isClientCompleted: Bool) async throws -> OrderResponse {
        var payload: [String: AnyCodable] = [
            "isClientCompleted": AnyCodable(isClientCompleted)
        ]
        if let val = clientValue {
            payload["clientValue"] = AnyCodable(val)
        }
        if let notes = clientNotes {
            payload["clientNotes"] = AnyCodable(notes)
        }
        let data = try JSONEncoder().encode(payload)
        return try await performRequest(path: "api/orders/\(orderId)/requirements/\(requirementId)", method: "PUT", body: data)
    }
    
    func uploadOrderRequirementDocument(orderId: String, requirementId: String, fileData: Data, fileName: String, mimeType: String = "application/pdf") async throws -> OrderResponse {
        guard let url = URL(string: "\(baseURL)api/orders/\(orderId)/documents") else {
            throw NetworkError.invalidURL
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        if let token = SessionManager.shared.getAuthToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        
        let boundary = "Boundary-\(UUID().uuidString)"
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        
        var body = Data()
        // Append requirementId field
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"requirementId\"\r\n\r\n".data(using: .utf8)!)
        body.append("\(requirementId)\r\n".data(using: .utf8)!)
        
        // Append file field
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"document\"; filename=\"\(fileName)\"\r\n".data(using: .utf8)!)
        body.append("Content-Type: \(mimeType)\r\n\r\n".data(using: .utf8)!)
        body.append(fileData)
        body.append("\r\n".data(using: .utf8)!)
        body.append("--\(boundary)--\r\n".data(using: .utf8)!)
        
        request.httpBody = body
        
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
            let errorMsg = String(data: data, encoding: .utf8) ?? "Upload failed"
            throw NetworkError.serverError(errorMsg)
        }
        return try JSONDecoder().decode(OrderResponse.self, from: data)
    }
    
    // --- USER VAULT DOCUMENT API ---
    
    func getUserVaultDocuments() async throws -> [UserVaultDocument] {
        let res: UserVaultDocumentsResponse = try await performRequest(path: "api/documents", method: "GET")
        return res.data
    }
    
    func uploadUserVaultDocument(docType: String, fileData: Data, fileName: String, mimeType: String = "application/pdf") async throws -> GeneralResponse {
        guard let url = URL(string: "\(baseURL)api/documents/upload") else {
            throw NetworkError.invalidURL
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        if let token = SessionManager.shared.getAuthToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        
        let boundary = "Boundary-\(UUID().uuidString)"
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        
        var body = Data()
        // Append docType field
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"docType\"\r\n\r\n".data(using: .utf8)!)
        body.append("\(docType)\r\n".data(using: .utf8)!)
        
        // Append file field
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"document\"; filename=\"\(fileName)\"\r\n".data(using: .utf8)!)
        body.append("Content-Type: \(mimeType)\r\n\r\n".data(using: .utf8)!)
        body.append(fileData)
        body.append("\r\n".data(using: .utf8)!)
        body.append("--\(boundary)--\r\n".data(using: .utf8)!)
        
        request.httpBody = body
        
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
            let errorMsg = String(data: data, encoding: .utf8) ?? "Upload failed"
            throw NetworkError.serverError(errorMsg)
        }
        return try JSONDecoder().decode(GeneralResponse.self, from: data)
    }
    
    func deleteUserVaultDocument(id: String) async throws -> GeneralResponse {
        return try await performRequest(path: "api/documents/\(id)", method: "DELETE")
    }

    // MARK: - Bookkeeping & AaaS (Accounting) Endpoints
    
    func getAccountingTransactions(type: String? = nil, month: String? = nil, status: String? = nil) async throws -> [TransactionDto] {
        var queryItems: [String] = []
        if let type = type, !type.isEmpty { queryItems.append("type=\(type.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? type)") }
        if let month = month, !month.isEmpty { queryItems.append("month=\(month.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? month)") }
        if let status = status, !status.isEmpty { queryItems.append("status=\(status.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? status)") }
        let queryString = queryItems.isEmpty ? "" : "?" + queryItems.joined(separator: "&")
        return try await performRequest(path: "api/accounting/transactions\(queryString)")
    }
    
    func createAccountingTransaction(transaction: TransactionDto) async throws -> TransactionDto {
        let body = try JSONEncoder().encode(transaction)
        return try await performRequest(path: "api/accounting/transactions", method: "POST", body: body)
    }
    
    func updateAccountingTransaction(id: String, transaction: TransactionDto) async throws -> TransactionDto {
        let body = try JSONEncoder().encode(transaction)
        return try await performRequest(path: "api/accounting/transactions/\(id)", method: "PUT", body: body)
    }
    
    func deleteAccountingTransaction(id: String) async throws -> GeneralResponse {
        return try await performRequest(path: "api/accounting/transactions/\(id)", method: "DELETE")
    }
    
    func recordAccountingPayment(id: String, request: RecordPaymentRequest) async throws -> TransactionDto {
        let body = try JSONEncoder().encode(request)
        return try await performRequest(path: "api/accounting/transactions/\(id)/payment", method: "POST", body: body)
    }
    
    func getCompanyDetails() async throws -> CompanyDetailsDto {
        return try await performRequest(path: "api/accounting/company")
    }
    
    func updateCompanyDetails(details: CompanyDetailsDto) async throws -> CompanyDetailsDto {
        let body = try JSONEncoder().encode(details)
        return try await performRequest(path: "api/accounting/company", method: "POST", body: body)
    }
    
    func getAccountingParties(partyType: String? = nil) async throws -> [PartyDto] {
        let query = (partyType != nil && !partyType!.isEmpty) ? "?partyType=\(partyType!.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? partyType!)" : ""
        return try await performRequest(path: "api/accounting/parties\(query)")
    }
    
    func createAccountingParty(party: PartyDto) async throws -> PartyDto {
        let body = try JSONEncoder().encode(party)
        return try await performRequest(path: "api/accounting/parties", method: "POST", body: body)
    }
    
    func updateAccountingParty(id: String, party: PartyDto) async throws -> PartyDto {
        let body = try JSONEncoder().encode(party)
        return try await performRequest(path: "api/accounting/parties/\(id)", method: "PUT", body: body)
    }
    
    func deleteAccountingParty(id: String) async throws -> GeneralResponse {
        return try await performRequest(path: "api/accounting/parties/\(id)", method: "DELETE")
    }
    
    func getBankStatements() async throws -> [BankStatementDto] {
        return try await performRequest(path: "api/accounting/bank-statements")
    }
    
    func createBankStatement(statement: BankStatementDto) async throws -> BankStatementDto {
        let body = try JSONEncoder().encode(statement)
        return try await performRequest(path: "api/accounting/bank-statements", method: "POST", body: body)
    }
    
    func deleteBankStatement(id: String) async throws -> GeneralResponse {
        return try await performRequest(path: "api/accounting/bank-statements/\(id)", method: "DELETE")
    }
    
    func tagBankTransaction(statementId: String, request: TagBankTransactionRequest) async throws -> GeneralResponse {
        let body = try JSONEncoder().encode(request)
        return try await performRequest(path: "api/accounting/bank-statements/\(statementId)/tag", method: "POST", body: body)
    }

    // MARK: - Admin Users Extended API
    func sendUserPasswordLink(userId: String) async throws -> PasswordLinkResponse {
        return try await performRequest(path: "api/auth/users/\(userId)/send-password-link", method: "POST")
    }

    func toggleUserComplianceAccess(userId: String, canManage: Bool) async throws -> UserResponse {
        let payload = ["canManageCompliance": canManage]
        let body = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/auth/users/\(userId)", method: "PUT", body: body)
    }

    func updateUserAssignedPartner(userId: String, partnerId: String?) async throws -> UserResponse {
        var payload: [String: Any] = [:]
        if let pid = partnerId, !pid.isEmpty {
            payload["referredByPartner"] = pid
        } else {
            payload["referredByPartner"] = NSNull()
        }
        let body = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/auth/users/\(userId)", method: "PUT", body: body)
    }

    func getAttendanceSummary() async throws -> AttendanceSummaryResponse {
        return try await performRequest(path: "api/attendance/admin/summary")
    }

    // MARK: - Order Details Extended API
    func updateOrderServiceName(orderId: String, serviceName: String) async throws -> OrderResponse {
        let payload = ["serviceName": serviceName]
        let body = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/orders/\(orderId)/commercials", method: "PUT", body: body)
    }

    func getOrderPayments(orderId: String) async throws -> [PaymentResponse] {
        return try await performRequest(path: "api/payments?orderId=\(orderId)")
    }

    func getOrderMilestones(orderId: String) async throws -> [MilestoneHistoryResponse] {
        return try await performRequest(path: "api/orders/\(orderId)/history")
    }

    func getOrderTodos(orderId: String) async throws -> [TodoResponse] {
        return try await performRequest(path: "api/todos?orderId=\(orderId)")
    }

    func createOrderTodo(orderId: String, title: String) async throws -> TodoResponse {
        let payload = ["orderId": orderId, "title": title, "priority": "Medium"]
        let body = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/todos", method: "POST", body: body)
    }

    func toggleOrderTodo(todoId: String, newStatus: String) async throws -> TodoResponse {
        let payload = ["status": newStatus]
        let body = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/todos/\(todoId)", method: "PUT", body: body)
    }

    func broadcastFreelancerOrder(orderId: String, payout: Double) async throws -> GeneralResponse {
        let payload = ["payoutAmount": payout]
        let body = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/freelancer/admin/broadcast/\(orderId)", method: "PUT", body: body)
    }

    func assignFreelancerOrder(orderId: String, freelancerId: String?, payout: Double? = nil) async throws -> GeneralResponse {
        if let p = payout, p > 0 {
            let bPayload = ["payoutAmount": p]
            let bBody = try JSONSerialization.data(withJSONObject: bPayload)
            let _: GeneralResponse? = try? await performRequest(path: "api/freelancer/admin/broadcast/\(orderId)", method: "PUT", body: bBody)
        }
        var payload: [String: Any] = [:]
        if let fid = freelancerId, !fid.isEmpty {
            payload["freelancerId"] = fid
        } else {
            payload["freelancerId"] = NSNull()
        }
        let body = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/freelancer/admin/reassign/\(orderId)", method: "POST", body: body)
    }

    func approveFreelancerPayout(orderId: String) async throws -> GeneralResponse {
        return try await performRequest(path: "api/freelancer/admin/approve-payout/\(orderId)", method: "POST")
    }

    func getFreelancerApplicants() async throws -> [FreelancerApplicant] {
        return try await performRequest(path: "api/freelancer/admin/users", method: "GET")
    }

    func updateFreelancerApplicantStatus(id: String, status: String) async throws -> GeneralResponse {
        let payload = ["verificationStatus": status]
        let body = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/freelancer/admin/users/\(id)/status", method: "PUT", body: body)
    }

    func getAdminFreelancerPayouts() async throws -> [FreelancerPayoutItem] {
        return try await performRequest(path: "api/freelancer/admin/payouts", method: "GET")
    }

    func settleFreelancerPayout(id: String, method: String, transactionRef: String, notes: String) async throws -> GeneralResponse {
        let payload = [
            "method": method,
            "transactionRef": transactionRef,
            "notes": notes
        ]
        let body = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/freelancer/admin/payouts/\(id)/settle", method: "PUT", body: body)
    }

    func raiseAdjustedInvoice(orderId: String, payload: [String: Any]) async throws -> GeneralResponse {
        let body = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/orders/\(orderId)/invoices/adjusted", method: "POST", body: body)
    }

    func getWorkflowTickets(orderId: String) async throws -> [WorkflowTicketResponse] {
        return try await performRequest(path: "api/workflow-tickets?orderId=\(orderId)")
    }

    func createWorkflowTicket(orderId: String, title: String, description: String, category: String, priority: String, assignedTo: String?) async throws -> WorkflowTicketResponse {
        var payload: [String: Any] = [
            "orderId": orderId,
            "title": title,
            "description": description,
            "category": category,
            "priority": priority
        ]
        if let a = assignedTo, !a.isEmpty {
            payload["assignedTo"] = a
        }
        let body = try JSONSerialization.data(withJSONObject: payload)
        return try await performRequest(path: "api/workflow-tickets", method: "POST", body: body)
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
        if container.decodeNil() {
            value = NSNull()
        } else if let string = try? container.decode(String.self) {
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
            value = NSNull()
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
    var idVal: String { id }
    let name: String
    let email: String
    let role: String
    
    enum CodingKeys: String, CodingKey {
        case id = "_id"
        case name, email, role
    }
}

struct ITAssessmentResponseItem: Codable, Identifiable {
    var id: String { "\(itemId)" }
    let itemId: AnyCodable
    let section: String
    let description: String
    let remarks: String?
    let value: String
    let documentUrl: String?
}

struct ITAssessmentResponse: Codable, Identifiable {
    let id: String
    let clientName: String
    let pan: String
    let financialYear: String
    let assessmentYear: String
    let status: String
    let notes: String?
    let createdAt: String?
    let responses: [ITAssessmentResponseItem]?
    
    enum CodingKeys: String, CodingKey {
        case id = "_id"
        case clientName, pan, financialYear, assessmentYear, status, notes, createdAt, responses
    }
}

// MARK: - Server-Driven Service Page & Lead Models

struct ServiceHeroModel: Codable {
    let title: String?
    let subtitle: String?
    let badgeText: String?
    let consultationPrice: Double?
}

struct ServiceStatModel: Codable, Identifiable {
    var id: String { (label ?? "") + (value ?? "") }
    let value: String?
    let label: String?
}

struct ServiceStepModel: Codable, Identifiable {
    var id: String { (number ?? "") + (title ?? "") }
    let number: String?
    let title: String?
    let desc: String?
    let badge: String?
}

struct ServiceFaqModel: Codable, Identifiable {
    var id: String { q ?? UUID().uuidString }
    let q: String?
    let a: String?
}

struct ServiceGuideSection: Codable, Identifiable {
    var id: String { heading ?? UUID().uuidString }
    let heading: String?
    let content: String?
    let bullets: [String]?
}

struct ServiceGuideModel: Codable {
    let title: String?
    let overview: String?
    let checklistTitle: String?
    let checklist: [String]?
    let sections: [ServiceGuideSection]?
}

struct ServicePageResponseModel: Codable {
    let pageId: String?
    let title: String?
    let description: String?
    let iconKey: String?
    let hero: ServiceHeroModel?
    let stats: [ServiceStatModel]?
    let packages: [ServicePackage]?
    let steps: [ServiceStepModel]?
    let faqs: [ServiceFaqModel]?
    let guide: ServiceGuideModel?
    let popularSearches: [String]?
}

struct LeadTelemetryPayload: Codable {
    let customerId: String?
    let customerName: String?
    let email: String?
    let phone: String?
    let serviceId: String
    let serviceName: String
    let packageName: String?
    let price: Double?
    let category: String
    let source: String
    let deviceInfo: String?
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
