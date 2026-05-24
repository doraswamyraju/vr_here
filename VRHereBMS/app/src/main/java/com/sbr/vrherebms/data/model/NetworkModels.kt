package com.sbr.vrherebms.data.model

import com.google.gson.annotations.SerializedName

// --- AUTH DATA CLASSES ---

data class LoginRequest(
    val email: String,
    val password: String
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
    val phone: String?,
    val role: String,
    val isActive: Boolean,
    val token: String
)

data class UserProfile(
    @SerializedName("_id") val id: String,
    val name: String,
    val email: String,
    val role: String,
    val isActive: Boolean
)

// --- ORDER DATA CLASSES ---

data class EmployeeResponse(
    @SerializedName("_id") val id: String,
    val name: String = "",
    val email: String = "",
    val role: String = ""
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
    val clientDocuments: List<OrderDocument> = emptyList(),
    val adminDocuments: List<OrderDocument> = emptyList(),
    val finalCertificateUrl: String? = null,
    val tasks: List<OrderTask> = emptyList(),
    val invoices: List<OrderInvoice> = emptyList(),
    val customerRequirements: List<CustomerRequirement> = emptyList(),
    val checklists: List<ChecklistItem> = emptyList(),
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
    val createdAt: String = ""
)

// --- TICKET DATA CLASSES ---

data class TicketResponse(
    @SerializedName("_id") val id: String,
    val subject: String,
    val description: String,
    val status: String = "Open", // 'Open', 'In Progress', 'Closed'
    val priority: String = "Low", // 'Low', 'Medium', 'High'
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
    val subject: String,
    val description: String,
    val priority: String = "Low"
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


