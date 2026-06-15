import Foundation

// --- AUTH DATA CLASSES ---

struct LoginRequest: Codable {
    let email: String
    let password: String
}

struct RegisterRequest: Codable {
    let name: String
    let email: String
    let phone: String
    let password: String
    let role: String = "client"
}

struct RegisterPartnerRequest: Codable {
    let name: String
    let email: String
    let phone: String
    let password: String
    let panCard: String
}

struct AuthResponse: Codable {
    let id: String
    let name: String
    let email: String
    let phone: String?
    let role: String
    let isActive: Bool
    let token: String

    enum CodingKeys: String, CodingKey {
        case id = "_id"
        case name, email, phone, role, isActive, token
    }
}

struct UserProfile: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let name: String
    let email: String
    let role: String
    let isActive: Bool

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case name, email, role, isActive
    }
}

// --- ORDER DATA CLASSES ---

struct EmployeeResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let name: String
    let email: String
    let role: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case name, email, role
    }
    
    init(idVal: String = "", name: String = "", email: String = "", role: String = "") {
        self.idVal = idVal
        self.name = name
        self.email = email
        self.role = role
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        idVal = try container.decodeIfPresent(String.self, forKey: .idVal) ?? ""
        name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        email = try container.decodeIfPresent(String.self, forKey: .email) ?? ""
        role = try container.decodeIfPresent(String.self, forKey: .role) ?? ""
    }
}

struct OrderResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let clientName: String
    let email: String
    let phone: String
    let serviceName: String
    let packageName: String
    let price: Double
    let paymentId: String
    let razorpayOrderId: String
    let paymentStatus: String
    let status: String
    let assignedEmployee: EmployeeResponse?
    let clientDocuments: [OrderDocument]
    let adminDocuments: [OrderDocument]
    let finalCertificateUrl: String?
    let tasks: [OrderTask]
    let invoices: [OrderInvoice]
    let customerRequirements: [CustomerRequirement]
    let checklists: [ChecklistItem]
    let consultationAdjusted: Bool
    let linkedTodos: [TodoResponse]
    let activityHistory: [OrderHistoryResponse]
    let attendance: [OrderAttendanceResponse]
    let createdAt: String
    let updatedAt: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case clientName, email, phone, serviceName, packageName, price, paymentId
        case razorpayOrderId, paymentStatus, status, assignedEmployee, clientDocuments
        case adminDocuments, finalCertificateUrl, tasks, invoices, customerRequirements
        case checklists, consultationAdjusted, linkedTodos, activityHistory, attendance, createdAt, updatedAt
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        idVal = try container.decodeIfPresent(String.self, forKey: .idVal) ?? ""
        clientName = try container.decodeIfPresent(String.self, forKey: .clientName) ?? ""
        email = try container.decodeIfPresent(String.self, forKey: .email) ?? ""
        phone = try container.decodeIfPresent(String.self, forKey: .phone) ?? ""
        serviceName = try container.decodeIfPresent(String.self, forKey: .serviceName) ?? ""
        packageName = try container.decodeIfPresent(String.self, forKey: .packageName) ?? ""
        price = try container.decodeIfPresent(Double.self, forKey: .price) ?? 0.0
        paymentId = try container.decodeIfPresent(String.self, forKey: .paymentId) ?? ""
        razorpayOrderId = try container.decodeIfPresent(String.self, forKey: .razorpayOrderId) ?? ""
        paymentStatus = try container.decodeIfPresent(String.self, forKey: .paymentStatus) ?? ""
        status = try container.decodeIfPresent(String.self, forKey: .status) ?? ""
        assignedEmployee = try container.decodeIfPresent(EmployeeResponse.self, forKey: .assignedEmployee)
        clientDocuments = try container.decodeIfPresent([OrderDocument].self, forKey: .clientDocuments) ?? []
        adminDocuments = try container.decodeIfPresent([OrderDocument].self, forKey: .adminDocuments) ?? []
        finalCertificateUrl = try container.decodeIfPresent(String.self, forKey: .finalCertificateUrl)
        tasks = try container.decodeIfPresent([OrderTask].self, forKey: .tasks) ?? []
        invoices = try container.decodeIfPresent([OrderInvoice].self, forKey: .invoices) ?? []
        customerRequirements = try container.decodeIfPresent([CustomerRequirement].self, forKey: .customerRequirements) ?? []
        checklists = try container.decodeIfPresent([ChecklistItem].self, forKey: .checklists) ?? []
        consultationAdjusted = try container.decodeIfPresent(Bool.self, forKey: .consultationAdjusted) ?? false
        linkedTodos = try container.decodeIfPresent([TodoResponse].self, forKey: .linkedTodos) ?? []
        activityHistory = try container.decodeIfPresent([OrderHistoryResponse].self, forKey: .activityHistory) ?? []
        attendance = try container.decodeIfPresent([OrderAttendanceResponse].self, forKey: .attendance) ?? []
        createdAt = try container.decodeIfPresent(String.self, forKey: .createdAt) ?? ""
        updatedAt = try container.decodeIfPresent(String.self, forKey: .updatedAt) ?? ""
    }
}

struct OrderDocument: Codable, Identifiable {
    var id: String { idVal ?? UUID().uuidString }
    let idVal: String?
    let name: String
    let url: String
    let uploadedAt: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case name, url, uploadedAt
    }
}

struct OrderTask: Codable, Identifiable {
    var id: String { idVal ?? UUID().uuidString }
    let idVal: String?
    let taskCode: String
    let title: String
    var status: String // 'Pending', 'In Progress', 'Completed'
    let ownerRole: String
    let description: String
    let subtasks: [OrderSubtask]
    let totalMinutes: Int

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case taskCode, title, status, ownerRole, description, subtasks, totalMinutes
    }
}

struct OrderSubtask: Codable, Identifiable {
    var id: String { idVal ?? UUID().uuidString }
    let idVal: String?
    let subTaskCode: String
    let title: String
    var isCompleted: Bool
    var status: String
    let makerRole: String
    let checkerRole: String
    let duration: String
    let dependency: String
    let output: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case subTaskCode, title, isCompleted, status, makerRole, checkerRole, duration, dependency, output
    }
}

struct OrderInvoice: Codable, Identifiable {
    var id: String { idVal ?? UUID().uuidString }
    let idVal: String?
    let invoiceNumber: String
    let amount: Double
    let status: String
    let url: String?
    let dueDate: String?
    let notes: String?
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case invoiceNumber, amount, status, url, dueDate, notes, createdAt
    }
}

struct CustomerRequirement: Codable, Identifiable {
    var id: String { idVal ?? UUID().uuidString }
    let idVal: String?
    let title: String
    let sheetName: String
    let category: String
    let type: String
    let itemCode: String
    let inputType: String
    let placeholder: String
    let required: Bool
    var status: String
    let description: String
    var value: String
    var clientValue: String
    var clientNotes: String
    let documentUrl: String
    var uploadedDocumentUrl: String
    var uploadedDocumentName: String
    var isClientCompleted: Bool

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case title, sheetName, category, type, itemCode, inputType, placeholder, required
        case status, description, value, clientValue, clientNotes, documentUrl, uploadedDocumentUrl
        case uploadedDocumentName, isClientCompleted
    }
}

struct ChecklistItem: Codable, Identifiable {
    var id: String { idVal ?? UUID().uuidString }
    let idVal: String?
    let title: String
    var isCompleted: Bool
    let required: Bool
    let documentUrl: String?

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case title, isCompleted, required, documentUrl
    }
}

// --- PAYMENT DATA CLASSES ---

struct PaymentResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let amount: Double
    let currency: String
    let paymentId: String
    let razorpayOrderId: String
    let status: String
    let method: String
    let customerName: String
    let email: String
    let phone: String
    let serviceName: String
    let packageName: String
    let invoiceUrl: String?
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case amount, currency, paymentId, razorpayOrderId, status, method, customerName, email, phone, serviceName, packageName, invoiceUrl, createdAt
    }
}

// --- TICKET DATA CLASSES ---

struct TicketResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let subject: String
    let description: String
    let status: String
    let priority: String
    let messages: [TicketMessage]
    let createdAt: String
    let updatedAt: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case subject, description, status, priority, messages, createdAt, updatedAt
    }
}

struct TicketMessage: Codable, Identifiable {
    var id: String { idVal ?? UUID().uuidString }
    let idVal: String?
    let sender: UserProfile?
    let message: String
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case sender, message, createdAt
    }
}

struct CreateTicketRequest: Codable {
    let subject: String
    let description: String
    let priority: String
}

struct AddMessageRequest: Codable {
    let message: String
}

// --- NOTIFICATION DATA CLASSES ---

struct NotificationResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let title: String
    let message: String
    let type: String
    let isRead: Bool
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case title, message, type, isRead, createdAt
    }
    
    init(idVal: String, title: String, message: String, type: String, isRead: Bool, createdAt: String) {
        self.idVal = idVal
        self.title = title
        self.message = message
        self.type = type
        self.isRead = isRead
        self.createdAt = createdAt
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        idVal = try container.decodeIfPresent(String.self, forKey: .idVal) ?? ""
        title = try container.decodeIfPresent(String.self, forKey: .title) ?? ""
        message = try container.decodeIfPresent(String.self, forKey: .message) ?? ""
        type = try container.decodeIfPresent(String.self, forKey: .type) ?? "System"
        isRead = try container.decodeIfPresent(Bool.self, forKey: .isRead) ?? false
        createdAt = try container.decodeIfPresent(String.self, forKey: .createdAt) ?? ""
    }
}

// --- ATTENDANCE DATA CLASSES ---

struct AttendanceResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let clockInAt: String
    let clockOutAt: String?
    let totalSeconds: Int
    let dateKey: String
    let notes: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case clockInAt, clockOutAt, totalSeconds, dateKey, notes
    }
}

struct ClockInRequest: Codable {
    let notes: String
}

// --- PARTNER DATA CLASSES ---

struct BankDetails: Codable {
    var accountName: String = ""
    var accountNumber: String = ""
    var ifscCode: String = ""
    var bankName: String = ""
}

struct PartnerProfileResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let name: String
    let email: String
    let role: String
    let phone: String?
    let panCard: String?
    let bankDetails: BankDetails?
    let commissionPercentage: Double?
    let isActive: Bool

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case name, email, role, phone, panCard, bankDetails, commissionPercentage, isActive
    }
}

struct PartnerProfileUpdateDto: Codable {
    let name: String
    let panCard: String
    let bankDetails: BankDetails
}

struct PartnerOrderResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let clientName: String
    let serviceName: String
    let price: Double
    let status: String
    let partnerCommissionAmount: Double
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case clientName, serviceName, price, status, partnerCommissionAmount, createdAt
    }
}

// --- CHECKOUT & VERIFICATION ---

struct CheckoutPayload: Codable {
    let serviceName: String
    let packageName: String
    let amount: Double
    let customerName: String
    let email: String
    let phone: String
    let referralCode: String
}

struct CheckoutOrderResponse: Codable {
    let key: String
    let orderId: String
    let amount: Int
    let currency: String
}

struct VerifyPayload: Codable {
    let serviceName: String
    let packageName: String
    let amount: Double
    let customerName: String
    let email: String
    let phone: String
    let referralCode: String
    let razorpay_order_id: String
    let razorpay_payment_id: String
    let razorpay_signature: String
}

struct VerifyResponse: Codable {
    let success: Bool
    let message: String?
    let resetLinkSent: Bool?
    let auth: AuthResponse?
}

// --- HRMS DATA CLASSES ---

struct LeaveRequest: Codable {
    let startDate: String
    let endDate: String
    let type: String
    let reason: String
}

struct LeaveResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let employee: EmployeeResponse?
    let startDate: String
    let endDate: String
    let type: String
    let reason: String
    let status: String
    let approvedBy: String?
    let adminNotes: String?
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case employee, startDate, endDate, type, reason, status, approvedBy, adminNotes, createdAt
    }
}

struct ApproveLeaveRequest: Codable {
    let status: String
    let adminNotes: String
}

struct HolidayRequest: Codable {
    let title: String
    let date: String
    let description: String
}

struct HolidayResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let title: String
    let date: String
    let description: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case title, date, description
    }
}

struct NoticeRequest: Codable {
    let title: String
    let message: String
    let priority: String
}

struct NoticeResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let title: String
    let message: String
    let priority: String
    let issuedBy: EmployeeResponse?
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case title, message, priority, issuedBy, createdAt
    }
}

struct LiveStatusEmployee: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let name: String
    let email: String
    let phone: String?
    let clockInAt: String?
    let source: String?
    let leaveType: String?
    let reason: String?

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case name, email, phone, clockInAt, source, leaveType, reason
    }
}

struct LiveStatusResponse: Codable {
    let date: String
    let clockedIn: [LiveStatusEmployee]
    let onLeave: [LiveStatusEmployee]
    let offline: [LiveStatusEmployee]
}

// --- TODO DATA CLASSES ---

struct TodoResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let title: String
    let description: String?
    let status: String
    let priority: String
    let assignedTo: EmployeeResponse?
    let orderId: OrderResponse?
    let dueDate: String?
    let createdBy: UserProfile?
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case title, description, status, priority, assignedTo, orderId, dueDate, createdBy, createdAt
    }
}

struct CreateTodoRequest: Codable {
    let title: String
    let description: String?
    let priority: String
    let assignedTo: String?
    let orderId: String?
    let dueDate: String?
}

struct OrderHistoryResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let order: String
    let user: UserProfile?
    let action: String
    let description: String
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case order, user, action, description, createdAt
    }
}

struct OrderAttendanceResponse: Codable, Identifiable {
    var id: String { idVal ?? UUID().uuidString }
    let idVal: String?
    let name: String
    let email: String
    let role: String
    let isClockedIn: Bool
    let clockInAt: String?

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case name, email, role, isClockedIn, clockInAt
    }
}

// --- DYNAMIC DTO FOR SERVER-DRIVEN SERVICES SYNC ---
struct MobileServiceHero: Codable {
    var title: String = ""
    var subtitle: String = ""
    var badgeText: String = ""
    var consultationPrice: Double = 499.0
}

struct MobileServiceStat: Codable, Identifiable {
    var id: String { label }
    var value: String = ""
    var label: String = ""
}

struct MobileServiceLogo: Codable, Identifiable {
    var id: String { name }
    var name: String = ""
    var iconKey: String = ""
    var colorClass: String = ""
}

struct MobileServicePackage: Codable, Identifiable {
    var id: String = ""
    var name: String = ""
    var price: Double = 0.0
    var description: String = ""
    var features: [String] = []
    var buttonText: String = "Select Plan"
    var isPopular: Bool = false
    var isAdjustable: Bool = false
}

struct MobileServiceReview: Codable, Identifiable {
    var id: String { name + date }
    var name: String = ""
    var company: String = ""
    var rating: Int = 5
    var date: String = ""
    var text: String = ""
    var avatar: String = ""
    var verified: Bool = true
}

struct MobileServiceStep: Codable, Identifiable {
    var id: String { number }
    var number: String = ""
    var title: String = ""
    var desc: String = ""
    var badge: String = ""
}

struct MobileServiceFaq: Codable, Identifiable {
    var id: String { q }
    var q: String = ""
    var a: String = ""
}

struct MobileServiceDetail: Codable, Identifiable {
    var id: String { pageId }
    var pageId: String = ""
    var title: String = ""
    var description: String = ""
    var iconKey: String = "Apartment"
    var hero: MobileServiceHero? = nil
    var stats: [MobileServiceStat] = []
    var logos: [MobileServiceLogo] = []
    var packages: [MobileServicePackage] = []
    var reviews: [MobileServiceReview] = []
    var steps: [MobileServiceStep] = []
    var faqs: [MobileServiceFaq] = []
}
