package com.sbr.vrherebms.data.model

import com.google.gson.annotations.SerializedName

// --- AUTH DATA CLASSES ---

data class LoginRequest(
    val email: String,
    val password: String
)

data class GoogleAuthRequest(
    val idToken: String,
    val credential: String? = null
)

data class RegisterRequest(
    val name: String,
    val email: String,
    val phone: String,
    val password: String,
    val role: String = "client"
)

data class RegisterPartnerRequest(
    val name: String,
    val email: String,
    val phone: String,
    val password: String,
    val panCard: String
)

data class AuthResponse(
    @SerializedName("_id") val id: String,
    val name: String,
    val email: String,
    val phone: String? = null,
    val role: String,
    val profilePhoto: String? = null,
    val companyLogo: String? = null,
    val companyName: String? = null,
    val businessType: String? = null,
    val gstin: String? = null,
    val panNumber: String? = null,
    val address: String? = null,
    val isActive: Boolean,
    val token: String
)

data class PartnerMinRef(
    @SerializedName("_id") val id: String? = null,
    val name: String? = null,
    val email: String? = null,
    val code: String? = null
)

data class UserProfile(
    @SerializedName("_id") val id: String,
    val name: String = "",
    val email: String = "",
    val phone: String? = null,
    val role: String = "client",
    val profilePhoto: String? = null,
    val companyLogo: String? = null,
    val companyName: String? = null,
    val businessType: String? = null,
    val gstin: String? = null,
    val panNumber: String? = null,
    val address: String? = null,
    val canManageCompliance: Boolean? = false,
    val assignedTicketCategories: List<String>? = emptyList(),
    val referredByPartner: PartnerMinRef? = null,
    val commissionPercentage: Double? = null,
    val isActive: Boolean = true,
    val createdAt: String? = null
) {
    val idVal: String get() = id
}

typealias UserResponse = UserProfile

// --- ORDER DATA CLASSES ---

data class EmployeeResponse(
    @SerializedName("_id") val id: String,
    val name: String = "",
    val email: String = "",
    val phone: String = "",
    val profilePhoto: String? = null,
    val role: String = ""
) {
    val idVal: String get() = id
}

data class FreelancerResponse(
    @SerializedName("_id") val id: String = "",
    val name: String = "",
    val email: String = "",
    val role: String = "freelancer"
)

data class OrderResponse(
    @SerializedName("_id") val id: String,
    val clientName: String = "",
    val email: String = "",
    val phone: String = "",
    val serviceName: String,
    val packageName: String,
    val price: Double,
    val paymentId: String,
    val razorpayOrderId: String = "",
    val paymentStatus: String = "Paid",
    val status: String = "Pending Documents",
    val assignedEmployee: EmployeeResponse? = null,
    val assignedMaker: EmployeeResponse? = null,
    val assignedChecker: EmployeeResponse? = null,
    val assignedProjectManager: EmployeeResponse? = null,
    val assignedFreelancer: EmployeeResponse? = null,
    val clientDocuments: List<OrderDocument> = emptyList(),
    val adminDocuments: List<OrderDocument> = emptyList(),
    val finalCertificateUrl: String? = null,
    val tasks: List<OrderTask> = emptyList(),
    val invoices: List<OrderInvoice> = emptyList(),
    val customerRequirements: List<CustomerRequirement> = emptyList(),
    val checklists: List<ChecklistItem> = emptyList(),
    val consultationAdjusted: Boolean = false,
    val linkedTodos: List<TodoResponse> = emptyList(),
    val activityHistory: List<OrderHistoryResponse> = emptyList(),
    val attendance: List<OrderAttendanceResponse> = emptyList(),
    val createdAt: String = "",
    val updatedAt: String = ""
)

data class OrderDocument(
    @SerializedName("_id") val id: String?,
    val name: String,
    val url: String,
    val uploadedAt: String = ""
)

data class OrderTask(
    @SerializedName("_id") val id: String?,
    val taskCode: String = "",
    val title: String,
    val status: String = "Pending", // 'Pending', 'In Progress', 'Completed'
    val ownerRole: String = "",
    val description: String = "",
    val subtasks: List<OrderSubtask> = emptyList(),
    val totalMinutes: Int = 0
)

data class OrderSubtask(
    @SerializedName("_id") val id: String?,
    val subTaskCode: String = "",
    val title: String,
    val isCompleted: Boolean = false,
    val status: String = "Pending",
    val makerRole: String = "",
    val checkerRole: String = "",
    val duration: String = "",
    val dependency: String = "",
    val output: String = ""
)

data class OrderInvoice(
    @SerializedName("_id") val id: String?,
    val invoiceNumber: String,
    val amount: Double,
    val status: String = "Draft", // 'Draft', 'Sent', 'Paid', 'Overdue'
    val url: String? = null,
    val dueDate: String? = null,
    val notes: String? = null,
    val createdAt: String = ""
)

data class CustomerRequirement(
    @SerializedName("_id") val id: String?,
    val title: String,
    val sheetName: String = "",
    val category: String = "Document", // 'Detail', 'Document'
    val type: String = "Document",
    val itemCode: String = "",
    val inputType: String = "text",
    val placeholder: String = "",
    val required: Boolean = true,
    val status: String = "Pending", // 'Pending', 'Received', 'Verified'
    val description: String = "",
    val value: String = "",
    val clientValue: String = "",
    val clientNotes: String = "",
    val documentUrl: String = "",
    val uploadedDocumentUrl: String = "",
    val uploadedDocumentName: String = "",
    val isClientCompleted: Boolean = false
)

data class ChecklistItem(
    @SerializedName("_id") val id: String?,
    val title: String,
    val isCompleted: Boolean = false,
    val required: Boolean = true,
    val documentUrl: String? = null
)

// --- PAYMENT DATA CLASSES ---

data class PaymentOrderReference(
    @SerializedName("_id") val id: String,
    val serviceName: String = "",
    val packageName: String = "",
    val status: String = ""
)

data class PaymentResponse(
    @SerializedName("_id") val id: String,
    val amount: Double,
    val currency: String = "INR",
    val paymentId: String,
    val razorpayOrderId: String = "",
    val status: String = "Pending", // 'Pending', 'Completed', 'Failed', 'Refunded'
    val method: String = "Razorpay",
    val customerName: String = "",
    val email: String = "",
    val phone: String = "",
    val serviceName: String = "",
    val packageName: String = "",
    val invoiceUrl: String? = null,
    val order: PaymentOrderReference? = null,
    val createdAt: String = ""
)

// --- TICKET DATA CLASSES ---

data class TicketResponse(
    @SerializedName("_id") val id: String,
    val ticketNumber: String? = null,
    val category: String? = "Support",
    val subject: String = "",
    val description: String = "",
    val status: String = "Open", // 'Open', 'In Progress', 'Resolved', 'Closed'
    val priority: String = "Low", // 'Low', 'Medium', 'High', 'Urgent'
    val user: UserProfile? = null,
    val assignedTo: UserProfile? = null,
    val messages: List<TicketMessage> = emptyList(),
    val createdAt: String = "",
    val updatedAt: String = ""
)

data class TicketMessage(
    @SerializedName("_id") val id: String?,
    val sender: UserProfile?,
    val message: String,
    val createdAt: String = ""
)

data class CreateTicketRequest(
    val category: String = "Service",
    val subject: String,
    val description: String,
    val priority: String = "Medium"
)

data class AddMessageRequest(
    val message: String
)

// --- NOTIFICATION DATA CLASSES ---

data class NotificationResponse(
    @SerializedName("_id") val id: String,
    val title: String,
    val message: String,
    val type: String = "System", // 'Order', 'Payment', 'Ticket', 'System'
    val isRead: Boolean = false,
    val createdAt: String = ""
)

// --- ATTENDANCE DATA CLASSES ---

data class AttendanceResponse(
    @SerializedName("_id") val id: String,
    val clockInAt: String,
    val clockOutAt: String?,
    val totalSeconds: Long = 0,
    val dateKey: String,
    val notes: String = ""
)

data class ClockInRequest(
    val notes: String = ""
)

// --- PARTNER DATA CLASSES ---

data class BankDetails(
    val accountName: String = "",
    val accountNumber: String = "",
    val ifscCode: String = "",
    val bankName: String = ""
)

data class PartnerProfileResponse(
    @SerializedName("_id") val id: String,
    val name: String,
    val email: String,
    val role: String,
    val phone: String?,
    val panCard: String?,
    val bankDetails: BankDetails?,
    val commissionPercentage: Double?,
    val isActive: Boolean
)

data class PartnerProfileUpdateDto(
    val name: String,
    val panCard: String,
    val bankDetails: BankDetails
)

data class PartnerOrderResponse(
    @SerializedName("_id") val id: String,
    val clientName: String = "",
    val serviceName: String = "",
    val price: Double = 0.0,
    val status: String = "",
    val partnerCommissionAmount: Double = 0.0,
    val createdAt: String = ""
)

// --- CHECKOUT & VERIFICATION ---

data class CheckoutPayload(
    val serviceName: String,
    val packageName: String,
    val amount: Double,
    val customerName: String,
    val email: String,
    val phone: String,
    val referralCode: String = ""
)

data class CheckoutOrderResponse(
    val key: String,
    val orderId: String,
    val amount: Long,
    val currency: String
)

data class VerifyPayload(
    val serviceName: String,
    val packageName: String,
    val amount: Double,
    val customerName: String,
    val email: String,
    val phone: String,
    val referralCode: String = "",
    val razorpay_order_id: String,
    val razorpay_payment_id: String,
    val razorpay_signature: String
)

data class VerifyResponse(
    val success: Boolean,
    val message: String?,
    val resetLinkSent: Boolean? = false,
    val auth: AuthResponse? = null
)

// --- HRMS DATA CLASSES ---

data class LeaveRequest(
    val startDate: String,
    val endDate: String,
    val type: String,
    val reason: String
)

data class LeaveResponse(
    @SerializedName("_id") val id: String,
    val employee: EmployeeResponse?,
    val startDate: String,
    val endDate: String,
    val type: String,
    val reason: String,
    val status: String = "Pending", // 'Pending', 'Approved', 'Rejected'
    val approvedBy: String? = null,
    val adminNotes: String? = null,
    val createdAt: String = ""
)

data class ApproveLeaveRequest(
    val status: String, // 'Approved' or 'Rejected'
    val adminNotes: String = ""
)

data class HolidayRequest(
    val title: String,
    val date: String,
    val description: String = ""
)

data class HolidayResponse(
    @SerializedName("_id") val id: String,
    val title: String,
    val date: String,
    val description: String = ""
)

data class NoticeRequest(
    val title: String,
    val message: String,
    val priority: String = "Medium" // 'Low', 'Medium', 'High'
)

data class NoticeResponse(
    @SerializedName("_id") val id: String,
    val title: String,
    val message: String,
    val priority: String = "Medium",
    val issuedBy: EmployeeResponse?,
    val createdAt: String = ""
)

data class LiveStatusEmployee(
    @SerializedName("_id") val id: String,
    val name: String,
    val email: String,
    val phone: String? = null,
    val clockInAt: String? = null,
    val source: String? = null,
    val leaveType: String? = null,
    val reason: String? = null
)

data class LiveStatusResponse(
    val date: String,
    val clockedIn: List<LiveStatusEmployee> = emptyList(),
    val onLeave: List<LiveStatusEmployee> = emptyList(),
    val offline: List<LiveStatusEmployee> = emptyList()
)

// --- TODO DATA CLASSES ---

data class TodoResponse(
    @SerializedName("_id") val id: String,
    val title: String,
    val description: String?,
    val status: String = "Pending", // 'Pending', 'Completed'
    val priority: String = "Medium", // 'Low', 'Medium', 'High'
    val assignedTo: EmployeeResponse? = null,
    val orderId: OrderResponse? = null,
    val dueDate: String? = null,
    val createdBy: UserProfile? = null,
    val createdAt: String = ""
)

data class CreateTodoRequest(
    val title: String,
    val description: String?,
    val priority: String = "Medium", // 'Low', 'Medium', 'High'
    val assignedTo: String? = null,
    val orderId: String? = null,
    val dueDate: String? = null
)

data class OrderHistoryResponse(
    @SerializedName("_id") val id: String,
    val order: String,
    val user: UserProfile?,
    val action: String,
    val description: String,
    val createdAt: String
) {
    val author: String get() = user?.name ?: "System"
    val timestamp: String get() = createdAt
}

data class OrderAttendanceResponse(
    @SerializedName("_id") val id: String?,
    val name: String,
    val email: String,
    val role: String,
    val isClockedIn: Boolean = false,
    val clockInAt: String? = null
)


// --- DYNAMIC DTO FOR SERVER-DRIVEN SERVICES SYNC ---
data class MobileServiceHero(
    val title: String = "",
    val subtitle: String = "",
    val badgeText: String = "",
    val consultationPrice: Double = 499.0
)

data class MobileServiceStat(
    val value: String = "",
    val label: String = ""
)

data class MobileServiceLogo(
    val name: String = "",
    val iconKey: String = "",
    val colorClass: String = ""
)

data class MobileServicePackage(
    val id: String = "",
    val name: String = "",
    val price: Double = 0.0,
    val description: String = "",
    val features: List<String> = emptyList(),
    val buttonText: String = "Select Plan",
    val isPopular: Boolean = false,
    val isAdjustable: Boolean = false
)

data class MobileServiceReview(
    val name: String = "",
    val company: String = "",
    val rating: Int = 5,
    val date: String = "",
    val text: String = "",
    val avatar: String = "",
    val verified: Boolean = true
)

data class MobileServiceStep(
    val number: String = "",
    val title: String = "",
    val desc: String = "",
    val badge: String = ""
)

data class MobileServiceFaq(
    val q: String = "",
    val a: String = ""
)

data class MobileServiceDetail(
    val pageId: String = "",
    val title: String = "",
    val description: String = "",
    val iconKey: String = "Apartment",
    val hero: MobileServiceHero? = null,
    val stats: List<MobileServiceStat> = emptyList(),
    val logos: List<MobileServiceLogo> = emptyList(),
    val packages: List<MobileServicePackage> = emptyList(),
    val reviews: List<MobileServiceReview> = emptyList(),
    val steps: List<MobileServiceStep> = emptyList(),
    val faqs: List<MobileServiceFaq> = emptyList()
)

// --- CRM LEAD TELEMETRY & MANAGEMENT DTOs ---
data class LeadTelemetryRequest(
    val customerId: String? = null,
    val customerName: String? = null,
    val email: String? = null,
    val phone: String? = null,
    val serviceId: String,
    val serviceName: String,
    val packageName: String? = null,
    val price: Double? = null,
    val category: String = "PAGE_VIEW", // 'PAGE_VIEW' (Warm / View) or 'PACKAGE_CLICK' (Hot / Intent)
    val source: String = "android",
    val deviceInfo: String? = "Android App"
)

data class LeadNote(
    @SerializedName("_id") val idVal: String? = null,
    val text: String = "",
    val authorName: String? = null,
    val createdAt: String? = null
) {
    val id: String get() = idVal ?: ""
}

data class LeadResponse(
    @SerializedName("_id") val id: String = "",
    val customerName: String? = null,
    val email: String? = null,
    val phone: String? = null,
    val serviceId: String? = null,
    val serviceName: String? = null,
    val packageName: String? = null,
    val price: Double? = null,
    val category: String? = "PAGE_VIEW",
    val priority: String? = "MEDIUM",
    val status: String? = "NEW",
    val source: String? = "android",
    val deviceInfo: String? = null,
    val assignedTo: EmployeeResponse? = null,
    val notes: List<LeadNote> = emptyList(),
    val createdAt: String? = null,
    val lastActivityAt: String? = null
) {
    val idVal: String get() = id
}

data class LeadListResponse(
    val leads: List<LeadResponse> = emptyList(),
    val total: Int? = 0,
    val page: Int? = 1,
    val pages: Int? = 1
)

data class LeadStatsResponse(
    val total: Int = 0,
    val packageClicks: Int = 0,
    val pageViews: Int = 0,
    val conversions: Int = 0
) {
    val converted: Int get() = conversions
    val conversionRate: String get() = if (total == 0) "0.0" else "%.1f".format((conversions.toDouble() / total) * 100)
}

// --- CUSTOMER REFERRAL MODELS ---

data class CustomerReferralItem(
    @SerializedName("_id") val id: String = "",
    val refereeName: String = "",
    val refereePhone: String = "",
    val refereeEmail: String? = null,
    val interestedService: String? = null,
    val status: String = "Invited",
    val rewardAmount: Double? = 500.0,
    val payoutStatus: String? = "None",
    val createdAt: String? = null
)

data class CustomerReferralStatsResponse(
    val success: Boolean? = true,
    val referralCode: String = "",
    val referralLink: String = "",
    val walletBalance: Double = 0.0,
    val savedUpiId: String? = null,
    val totalInvited: Int = 0,
    val successfulConversions: Int = 0,
    val totalEarned: Double = 0.0,
    val rewardPerReferral: Double? = 500.0,
    val referrals: List<CustomerReferralItem> = emptyList()
)

data class AddReferralLeadRequest(
    val name: String,
    val phone: String,
    val email: String? = null,
    val interestedService: String? = null
)

data class UpiPayoutRequest(
    val amount: Double,
    val upiId: String
)

data class GeneralApiResponse(
    val success: Boolean? = true,
    val message: String? = null
)

// --- USER VAULT DOCUMENT MODELS ---

data class UserVaultDocument(
    @SerializedName("_id") val id: String = "",
    val docType: String = "",
    val fileName: String = "",
    val gdriveWebViewLink: String? = null,
    val verificationStatus: String? = "Verified",
    val notes: String? = null,
    val createdAt: String? = null
)

data class UserVaultDocumentsResponse(
    val success: Boolean? = true,
    val count: Int? = 0,
    val data: List<UserVaultDocument> = emptyList()
)

// --- DYNAMIC BLOGS & PROMOTIONAL OFFERS MODELS ---

data class BlogResponse(
    @SerializedName("_id") val id: String = "",
    val title: String = "",
    val slug: String = "",
    val summary: String = "",
    val category: String = "Corporate & Legal",
    val categoryColor: String? = "#3B82F6",
    val readTime: String = "4 min read",
    val coverImageUrl: String? = "",
    val keyTakeaways: List<String> = emptyList(),
    val fullArticle: String = "",
    val isPublished: Boolean = true,
    val priority: Int = 0,
    val author: String = "VR HERE Editorial Board",
    val publishedAt: String? = null
)

data class OfferResponse(
    @SerializedName("_id") val id: String = "",
    val title: String = "",
    val subtitle: String = "",
    val badgeTag: String = "LIMITED TIME",
    val badgeColor: String = "#DC2626",
    val bannerImageUrl: String? = "",
    val targetServiceKey: String? = "",
    val targetUrl: String? = "",
    val discountAmount: Double = 0.0,
    val originalPrice: Double = 0.0,
    val discountedPrice: Double = 0.0,
    val eligibilityText: String = "Tap to view eligibility & apply",
    val ctaText: String = "Register Today →",
    val isActive: Boolean = true,
    val priority: Int = 0
)

// --- FREELANCER APPLICANT & PAYOUT MODELS ---

data class FreelancerApplicant(
    @SerializedName("_id") val id: String = "",
    val name: String = "",
    val email: String = "",
    val phone: String? = null,
    val skills: List<String>? = emptyList(),
    val yearsOfExperience: Int? = 0,
    val panCard: String? = null,
    val resumeUrl: String? = null,
    val bankDetails: BankDetails? = null,
    val verificationStatus: String? = "Pending",
    val isActive: Boolean? = true,
    val createdAt: String? = null
)

data class FreelancerPayoutItem(
    @SerializedName("_id") val id: String = "",
    val orderId: String? = null,
    val orderTitle: String? = null,
    val freelancerName: String? = null,
    val freelancerEmail: String? = null,
    val amount: Double = 0.0,
    val status: String = "Pending",
    val paymentMethod: String? = null,
    val transactionRef: String? = null,
    val notes: String? = null,
    val createdAt: String? = null,
    val settledAt: String? = null
)

data class FreelancerPayoutsResponse(
    val success: Boolean? = true,
    val count: Int? = 0,
    val payouts: List<FreelancerPayoutItem> = emptyList()
)

data class SettlePayoutRequest(
    val paymentMethod: String,
    val transactionRef: String,
    val notes: String? = null
)

data class BroadcastOrderRequest(
    val orderId: String,
    val payoutAmount: Double? = null
)

data class UpdateApplicantStatusRequest(
    val status: String
)

// --- ATTENDANCE SUMMARY MODELS ---

data class AttendanceSummaryItem(
    @SerializedName("_id") val id: String? = null,
    val name: String = "",
    val role: String? = null,
    val isClockedIn: Boolean = false,
    val clockInAt: String? = null,
    val totalMinutesToday: Int? = 0
) {
    val idVal: String get() = id ?: ""
    val trackedMinutes: Int get() = totalMinutesToday ?: 0
}

data class AttendanceSummaryResponse(
    val items: List<AttendanceSummaryItem>? = emptyList()
)

// --- SERVICES HEADER CONFIG & CAPSULES ---

data class InteractiveCapsuleItem(
    val id: String = "",
    val text: String = "",
    val bg: String = "#EFF6FF",
    val color: String = "#2563EB",
    val icon: String = "✨"
)

data class ServicesHeaderConfigRequest(
    val showTicker: Boolean = false,
    val tickerMessage: String = "",
    val tickerGradient: String = "from-indigo-600 to-purple-600",
    val capsules: List<InteractiveCapsuleItem> = emptyList()
)

// --- PASSWORD LINK & WORKFLOW TICKETS ---

data class PasswordLinkResponse(
    val success: Boolean? = true,
    val link: String = "",
    val expiresAt: String? = null
)

data class WorkflowTicketResponse(
    @SerializedName("_id") val id: String = "",
    val ticketNumber: String = "",
    val orderId: String? = null,
    val clientName: String = "",
    val serviceName: String = "",
    val subject: String = "",
    val category: String = "Technical",
    val priority: String = "Normal",
    val status: String = "Open",
    val createdAt: String? = null
)

data class TicketWorkflowCreateRequest(
    val subject: String,
    val category: String = "Technical",
    val priority: String = "Normal",
    val description: String = ""
)

data class RecurringScheduleRequest(
    val frequency: String = "Monthly",
    val intervalMonths: Int = 1,
    val startDate: String = "",
    val nextBillingDate: String = "",
    val autoInvoice: Boolean = true
)








