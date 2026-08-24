import Foundation

// --- AUTH DATA CLASSES ---

struct LoginRequest: Codable {
    let email: String
    let password: String
}

struct GoogleAuthRequest: Codable {
    let idToken: String
    let credential: String?
}

struct RegisterRequest: Codable {
    let name: String
    let email: String
    let phone: String
    let password: String
    var role: String = "client"
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
    
    init(idVal: String = "", name: String = "", email: String = "", role: String = "", isActive: Bool = false) {
        self.idVal = idVal
        self.name = name
        self.email = email
        self.role = role
        self.isActive = isActive
    }
    
    init(from decoder: Decoder) throws {
        if let container = try? decoder.singleValueContainer(),
           let idString = try? container.decode(String.self) {
            self.idVal = idString
            self.name = ""
            self.email = ""
            self.role = ""
            self.isActive = false
            return
        }
        
        let container = try decoder.container(keyedBy: CodingKeys.self)
        idVal = try container.decodeIfPresent(String.self, forKey: .idVal) ?? ""
        name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        email = try container.decodeIfPresent(String.self, forKey: .email) ?? ""
        role = try container.decodeIfPresent(String.self, forKey: .role) ?? ""
        isActive = try container.decodeIfPresent(Bool.self, forKey: .isActive) ?? false
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
        if let container = try? decoder.singleValueContainer(),
           let idString = try? container.decode(String.self) {
            self.idVal = idString
            self.name = ""
            self.email = ""
            self.role = ""
            return
        }
        
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
    let referralPartner: String?
    let partnerCommissionAmount: Double?
    let freelancerPayout: Double?

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case clientName, email, phone, serviceName, packageName, price, paymentId
        case razorpayOrderId, paymentStatus, status, assignedEmployee, clientDocuments
        case adminDocuments, finalCertificateUrl, tasks, invoices, customerRequirements
        case checklists, consultationAdjusted, linkedTodos, activityHistory, attendance, createdAt, updatedAt
        case referralPartner, partnerCommissionAmount, freelancerPayout
    }
    
    init(from decoder: Decoder) throws {
        if let container = try? decoder.singleValueContainer(),
           let idString = try? container.decode(String.self) {
            self.idVal = idString
            self.clientName = ""
            self.email = ""
            self.phone = ""
            self.serviceName = ""
            self.packageName = ""
            self.price = 0.0
            self.paymentId = ""
            self.razorpayOrderId = ""
            self.paymentStatus = ""
            self.status = ""
            self.assignedEmployee = nil
            self.clientDocuments = []
            self.adminDocuments = []
            self.finalCertificateUrl = nil
            self.tasks = []
            self.invoices = []
            self.customerRequirements = []
            self.checklists = []
            self.consultationAdjusted = false
            self.linkedTodos = []
            self.activityHistory = []
            self.attendance = []
            self.createdAt = ""
            self.updatedAt = ""
            self.referralPartner = nil
            self.partnerCommissionAmount = nil
            self.freelancerPayout = nil
            return
        }
        
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
        referralPartner = try container.decodeIfPresent(String.self, forKey: .referralPartner)
        partnerCommissionAmount = try container.decodeIfPresent(Double.self, forKey: .partnerCommissionAmount)
        freelancerPayout = try container.decodeIfPresent(Double.self, forKey: .freelancerPayout)
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
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        idVal = try container.decodeIfPresent(String.self, forKey: .idVal)
        name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        url = try container.decodeIfPresent(String.self, forKey: .url) ?? ""
        uploadedAt = try container.decodeIfPresent(String.self, forKey: .uploadedAt) ?? ""
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
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        idVal = try container.decodeIfPresent(String.self, forKey: .idVal)
        taskCode = try container.decodeIfPresent(String.self, forKey: .taskCode) ?? ""
        title = try container.decodeIfPresent(String.self, forKey: .title) ?? ""
        status = try container.decodeIfPresent(String.self, forKey: .status) ?? "Pending"
        ownerRole = try container.decodeIfPresent(String.self, forKey: .ownerRole) ?? ""
        description = try container.decodeIfPresent(String.self, forKey: .description) ?? ""
        subtasks = try container.decodeIfPresent([OrderSubtask].self, forKey: .subtasks) ?? []
        totalMinutes = try container.decodeIfPresent(Int.self, forKey: .totalMinutes) ?? 0
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
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        idVal = try container.decodeIfPresent(String.self, forKey: .idVal)
        subTaskCode = try container.decodeIfPresent(String.self, forKey: .subTaskCode) ?? ""
        title = try container.decodeIfPresent(String.self, forKey: .title) ?? ""
        isCompleted = try container.decodeIfPresent(Bool.self, forKey: .isCompleted) ?? false
        status = try container.decodeIfPresent(String.self, forKey: .status) ?? ""
        makerRole = try container.decodeIfPresent(String.self, forKey: .makerRole) ?? ""
        checkerRole = try container.decodeIfPresent(String.self, forKey: .checkerRole) ?? ""
        duration = try container.decodeIfPresent(String.self, forKey: .duration) ?? ""
        dependency = try container.decodeIfPresent(String.self, forKey: .dependency) ?? ""
        output = try container.decodeIfPresent(String.self, forKey: .output) ?? ""
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
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        idVal = try container.decodeIfPresent(String.self, forKey: .idVal)
        invoiceNumber = try container.decodeIfPresent(String.self, forKey: .invoiceNumber) ?? ""
        amount = try container.decodeIfPresent(Double.self, forKey: .amount) ?? 0.0
        status = try container.decodeIfPresent(String.self, forKey: .status) ?? ""
        url = try container.decodeIfPresent(String.self, forKey: .url)
        dueDate = try container.decodeIfPresent(String.self, forKey: .dueDate)
        notes = try container.decodeIfPresent(String.self, forKey: .notes)
        createdAt = try container.decodeIfPresent(String.self, forKey: .createdAt) ?? ""
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
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        idVal = try container.decodeIfPresent(String.self, forKey: .idVal)
        title = try container.decodeIfPresent(String.self, forKey: .title) ?? ""
        sheetName = try container.decodeIfPresent(String.self, forKey: .sheetName) ?? ""
        category = try container.decodeIfPresent(String.self, forKey: .category) ?? ""
        type = try container.decodeIfPresent(String.self, forKey: .type) ?? ""
        itemCode = try container.decodeIfPresent(String.self, forKey: .itemCode) ?? ""
        inputType = try container.decodeIfPresent(String.self, forKey: .inputType) ?? ""
        placeholder = try container.decodeIfPresent(String.self, forKey: .placeholder) ?? ""
        required = try container.decodeIfPresent(Bool.self, forKey: .required) ?? false
        status = try container.decodeIfPresent(String.self, forKey: .status) ?? ""
        description = try container.decodeIfPresent(String.self, forKey: .description) ?? ""
        value = try container.decodeIfPresent(String.self, forKey: .value) ?? ""
        clientValue = try container.decodeIfPresent(String.self, forKey: .clientValue) ?? ""
        clientNotes = try container.decodeIfPresent(String.self, forKey: .clientNotes) ?? ""
        documentUrl = try container.decodeIfPresent(String.self, forKey: .documentUrl) ?? ""
        uploadedDocumentUrl = try container.decodeIfPresent(String.self, forKey: .uploadedDocumentUrl) ?? ""
        uploadedDocumentName = try container.decodeIfPresent(String.self, forKey: .uploadedDocumentName) ?? ""
        isClientCompleted = try container.decodeIfPresent(Bool.self, forKey: .isClientCompleted) ?? false
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
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        idVal = try container.decodeIfPresent(String.self, forKey: .idVal)
        title = try container.decodeIfPresent(String.self, forKey: .title) ?? ""
        isCompleted = try container.decodeIfPresent(Bool.self, forKey: .isCompleted) ?? false
        required = try container.decodeIfPresent(Bool.self, forKey: .required) ?? false
        documentUrl = try container.decodeIfPresent(String.self, forKey: .documentUrl)
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
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        idVal = try container.decodeIfPresent(String.self, forKey: .idVal) ?? ""
        amount = try container.decodeIfPresent(Double.self, forKey: .amount) ?? 0.0
        currency = try container.decodeIfPresent(String.self, forKey: .currency) ?? ""
        paymentId = try container.decodeIfPresent(String.self, forKey: .paymentId) ?? ""
        razorpayOrderId = try container.decodeIfPresent(String.self, forKey: .razorpayOrderId) ?? ""
        status = try container.decodeIfPresent(String.self, forKey: .status) ?? ""
        method = try container.decodeIfPresent(String.self, forKey: .method) ?? ""
        customerName = try container.decodeIfPresent(String.self, forKey: .customerName) ?? ""
        email = try container.decodeIfPresent(String.self, forKey: .email) ?? ""
        phone = try container.decodeIfPresent(String.self, forKey: .phone) ?? ""
        serviceName = try container.decodeIfPresent(String.self, forKey: .serviceName) ?? ""
        packageName = try container.decodeIfPresent(String.self, forKey: .packageName) ?? ""
        invoiceUrl = try container.decodeIfPresent(String.self, forKey: .invoiceUrl)
        createdAt = try container.decodeIfPresent(String.self, forKey: .createdAt) ?? ""
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
    let user: UserProfile?
    let messages: [TicketMessage]
    let createdAt: String
    let updatedAt: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case subject, description, status, priority, user, messages, createdAt, updatedAt
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        idVal = try container.decodeIfPresent(String.self, forKey: .idVal) ?? ""
        subject = try container.decodeIfPresent(String.self, forKey: .subject) ?? ""
        description = try container.decodeIfPresent(String.self, forKey: .description) ?? ""
        status = try container.decodeIfPresent(String.self, forKey: .status) ?? ""
        priority = try container.decodeIfPresent(String.self, forKey: .priority) ?? ""
        user = try container.decodeIfPresent(UserProfile.self, forKey: .user)
        messages = try container.decodeIfPresent([TicketMessage].self, forKey: .messages) ?? []
        createdAt = try container.decodeIfPresent(String.self, forKey: .createdAt) ?? ""
        updatedAt = try container.decodeIfPresent(String.self, forKey: .updatedAt) ?? ""
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
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        idVal = try container.decodeIfPresent(String.self, forKey: .idVal)
        sender = try container.decodeIfPresent(UserProfile.self, forKey: .sender)
        message = try container.decodeIfPresent(String.self, forKey: .message) ?? ""
        createdAt = try container.decodeIfPresent(String.self, forKey: .createdAt) ?? ""
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

struct AttendanceSessionWrapper: Codable {
    let message: String
    let session: AttendanceResponse
}

struct FreelancerClockResponse: Codable {
    let message: String
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
    
    var completed: Bool {
        status.lowercased() == "completed"
    }

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case title, description, status, priority, assignedTo, orderId, dueDate, createdBy, createdAt
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        idVal = try container.decodeIfPresent(String.self, forKey: .idVal) ?? ""
        title = try container.decodeIfPresent(String.self, forKey: .title) ?? ""
        description = try container.decodeIfPresent(String.self, forKey: .description)
        status = try container.decodeIfPresent(String.self, forKey: .status) ?? ""
        priority = try container.decodeIfPresent(String.self, forKey: .priority) ?? ""
        // Custom decode for assignedTo (could be a String ID or full EmployeeResponse object)
        if let emp = try? container.decodeIfPresent(EmployeeResponse.self, forKey: .assignedTo) {
            assignedTo = emp
        } else if let idString = try? container.decodeIfPresent(String.self, forKey: .assignedTo) {
            assignedTo = EmployeeResponse(idVal: idString, name: "", email: "", role: "")
        } else {
            assignedTo = nil
        }
        
        // Custom decode for orderId (could be a String or full OrderResponse object)
        if let order = try? container.decodeIfPresent(OrderResponse.self, forKey: .orderId) {
            orderId = order
        } else {
            orderId = nil
        }
        
        dueDate = try container.decodeIfPresent(String.self, forKey: .dueDate)
        
        // Custom decode for createdBy (could be a String ID or full UserProfile object)
        if let profile = try? container.decodeIfPresent(UserProfile.self, forKey: .createdBy) {
            createdBy = profile
        } else if let idString = try? container.decodeIfPresent(String.self, forKey: .createdBy) {
            createdBy = UserProfile(idVal: idString, name: "", email: "", role: "admin", isActive: true)
        } else {
            createdBy = nil
        }
        
        createdAt = try container.decodeIfPresent(String.self, forKey: .createdAt) ?? ""
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
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        idVal = try container.decodeIfPresent(String.self, forKey: .idVal) ?? ""
        order = try container.decodeIfPresent(String.self, forKey: .order) ?? ""
        user = try container.decodeIfPresent(UserProfile.self, forKey: .user)
        action = try container.decodeIfPresent(String.self, forKey: .action) ?? ""
        description = try container.decodeIfPresent(String.self, forKey: .description) ?? ""
        createdAt = try container.decodeIfPresent(String.self, forKey: .createdAt) ?? ""
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
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        idVal = try container.decodeIfPresent(String.self, forKey: .idVal)
        name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        email = try container.decodeIfPresent(String.self, forKey: .email) ?? ""
        role = try container.decodeIfPresent(String.self, forKey: .role) ?? ""
        isClockedIn = try container.decodeIfPresent(Bool.self, forKey: .isClockedIn) ?? false
        clockInAt = try container.decodeIfPresent(String.self, forKey: .clockInAt)
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

// --- COMPLIANCE AND FINANCE MODELS ---

struct ComplianceResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let clientName: String
    let category: String
    let taskName: String
    let dueDate: String
    let status: String // Pending, Filed, Late, Missed
    let periodMonth: String
    let periodYear: String
    let notes: String
    
    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case clientName, category, taskName, dueDate, status, periodMonth, periodYear, notes
    }
}

struct FinanceRecordResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let type: String // Estimate, Invoice, Payment, CreditNote, Proforma
    let number: String
    let date: String
    let dueDate: String?
    let client: FinanceClient
    let items: [FinanceItem]
    let totals: FinanceTotals
    let status: String
    let notes: String?
    
    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case type, number, date, dueDate, client, items, totals, status, notes
    }
}

struct FinanceClient: Codable {
    let name: String
    let email: String?
    let phone: String?
    let address: String?
    let gstin: String?
}

struct FinanceItem: Codable {
    let description: String
    let rate: Double
    let qty: Double
    let amount: Double
}

struct FinanceTotals: Codable {
    let subtotal: Double
    let total: Double
}

struct UserResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let name: String
    let email: String
    let role: String
    let phone: String?
    let panCard: String?
    let commissionPercentage: Double?
    let isActive: Bool

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case name, email, role, phone, panCard, commissionPercentage, isActive
    }
}

struct UserMinResponse: Codable {
    let name: String
}

struct RecurringResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let serviceName: String
    let packageName: String
    let price: Double
    let frequency: String
    let dayOfMonth: Int
    let isActive: Bool
    let clientName: String?
    let user: UserMinResponse?
    let nextRunDate: String
    let lastOrderId: String?

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case serviceName, packageName, price, frequency, dayOfMonth, isActive, clientName, user, nextRunDate, lastOrderId
    }
}

struct PayoutResponse: Codable, Identifiable {
    var id: String { idVal }
    let idVal: String
    let amount: Double
    let status: String
    let method: String
    let transactionRef: String?
    let notes: String?
    let order: OrderResponse?
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case idVal = "_id"
        case amount, status, method, transactionRef, notes, order, createdAt
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        idVal = try container.decodeIfPresent(String.self, forKey: .idVal) ?? ""
        amount = try container.decodeIfPresent(Double.self, forKey: .amount) ?? 0.0
        status = try container.decodeIfPresent(String.self, forKey: .status) ?? ""
        method = try container.decodeIfPresent(String.self, forKey: .method) ?? ""
        transactionRef = try container.decodeIfPresent(String.self, forKey: .transactionRef)
        notes = try container.decodeIfPresent(String.self, forKey: .notes)
        order = try container.decodeIfPresent(OrderResponse.self, forKey: .order)
        createdAt = try container.decodeIfPresent(String.self, forKey: .createdAt) ?? ""
    }
}

struct GeneralResponse: Codable {
    let success: Bool
    let message: String?
}


