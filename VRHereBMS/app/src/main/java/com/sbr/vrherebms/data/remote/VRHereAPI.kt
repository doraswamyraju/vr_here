package com.sbr.vrherebms.data.remote

import android.content.Context
import com.sbr.vrherebms.data.local.SessionManager
import com.sbr.vrherebms.data.model.*
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.*
import java.util.concurrent.TimeUnit

interface VRHereAPI {

    // --- AUTHENTICATION ---
    @POST("api/auth/login")
    suspend fun login(@Body request: LoginRequest): Response<AuthResponse>

    @POST("api/auth/google")
    suspend fun googleLogin(@Body request: GoogleAuthRequest): Response<AuthResponse>

    @POST("api/auth/register")
    suspend fun register(@Body request: RegisterRequest): Response<AuthResponse>

    @POST("api/auth/register-partner")
    suspend fun registerPartner(@Body request: RegisterPartnerRequest): Response<AuthResponse>

    @GET("api/auth/profile")
    suspend fun getProfile(): Response<UserProfile>

    // --- ORDERS ---
    @GET("api/orders")
    suspend fun getOrders(): Response<List<OrderResponse>>

    @GET("api/orders/{id}")
    suspend fun getOrderById(@Path("id") id: String): Response<OrderResponse>

    @PUT("api/orders/{id}/status")
    suspend fun updateOrderStatus(
        @Path("id") id: String,
        @Body body: Map<String, String>
    ): Response<OrderResponse>

    // --- PAYMENTS ---
    @GET("api/payments")
    suspend fun getPayments(): Response<List<PaymentResponse>>

    @POST("api/payments/checkout-order")
    suspend fun checkoutOrder(@Body payload: CheckoutPayload): Response<CheckoutOrderResponse>

    @POST("api/payments/verify")
    suspend fun verifyPayment(@Body payload: VerifyPayload): Response<VerifyResponse>


    // --- TICKETS ---
    @GET("api/tickets")
    suspend fun getTickets(): Response<List<TicketResponse>>

    @POST("api/tickets")
    suspend fun createTicket(@Body request: CreateTicketRequest): Response<TicketResponse>

    @POST("api/tickets/{id}/messages")
    suspend fun addTicketMessage(
        @Path("id") ticketId: String,
        @Body request: AddMessageRequest
    ): Response<TicketResponse>

    // --- NOTIFICATIONS ---
    @GET("api/notifications")
    suspend fun getNotifications(): Response<List<NotificationResponse>>

    @PUT("api/notifications/{id}/read")
    suspend fun markNotificationAsRead(@Path("id") id: String): Response<NotificationResponse>

    @PUT("api/auth/fcm-token")
    suspend fun updateFcmToken(@Body body: Map<String, String>): Response<Map<String, Any>>

    // --- ATTENDANCE ---
    @GET("api/attendance")
    suspend fun getAttendance(): Response<List<AttendanceResponse>>

    @POST("api/attendance/clock-in")
    suspend fun clockIn(@Body request: ClockInRequest): Response<AttendanceResponse>

    @POST("api/attendance/clock-out")
    suspend fun clockOut(): Response<AttendanceResponse>

    // --- HRMS Endpoints ---
    @POST("api/hrms/leaves")
    suspend fun applyLeave(@Body request: LeaveRequest): Response<Map<String, Any>>

    @GET("api/hrms/leaves/my")
    suspend fun getMyLeaves(): Response<List<LeaveResponse>>

    @GET("api/hrms/leaves/admin")
    suspend fun getAdminLeaves(): Response<List<LeaveResponse>>

    @PUT("api/hrms/leaves/{id}/approve")
    suspend fun approveLeave(
        @Path("id") id: String,
        @Body request: ApproveLeaveRequest
    ): Response<Map<String, Any>>

    @GET("api/hrms/holidays")
    suspend fun getHolidays(): Response<List<HolidayResponse>>

    @POST("api/hrms/holidays")
    suspend fun createHoliday(@Body request: HolidayRequest): Response<Map<String, Any>>

    @DELETE("api/hrms/holidays/{id}")
    suspend fun deleteHoliday(@Path("id") id: String): Response<Map<String, Any>>

    @GET("api/hrms/notices")
    suspend fun getNotices(): Response<List<NoticeResponse>>

    @POST("api/hrms/notices")
    suspend fun createNotice(@Body request: NoticeRequest): Response<Map<String, Any>>

    @DELETE("api/hrms/notices/{id}")
    suspend fun deleteNotice(@Path("id") id: String): Response<Map<String, Any>>

    @GET("api/hrms/admin/live-status")
    suspend fun getLiveStatus(): Response<LiveStatusResponse>

    // --- PARTNER ---
    @GET("api/partner/orders")
    suspend fun getPartnerOrders(): Response<List<PartnerOrderResponse>>

    @GET("api/partner/profile")
    suspend fun getPartnerProfile(): Response<PartnerProfileResponse>

    @PUT("api/partner/profile")
    suspend fun updatePartnerProfile(@Body profile: PartnerProfileUpdateDto): Response<PartnerProfileResponse>

    // --- ADMIN COMMANDS ---
    @POST("api/orders")
    suspend fun createOrder(@Body body: Map<String, @JvmSuppressWildcards Any>): Response<OrderResponse>

    @GET("api/todos")
    suspend fun getTodos(): Response<List<TodoResponse>>

    @POST("api/todos")
    suspend fun createTodo(@Body request: CreateTodoRequest): Response<TodoResponse>

    @GET("api/auth/employees")
    suspend fun getEmployees(): Response<List<EmployeeResponse>>

    // --- EMPLOYEE TRANSACTION Endpoints ---
    @PUT("api/todos/{id}")
    suspend fun updateTodoStatus(
        @Path("id") id: String,
        @Body body: Map<String, String>
    ): Response<TodoResponse>

    @PUT("api/orders/{orderId}/tasks/{taskId}")
    suspend fun updateTaskStatus(
        @Path("orderId") orderId: String,
        @Path("taskId") taskId: String,
        @Body body: Map<String, String>
    ): Response<OrderResponse>

    @PUT("api/orders/{orderId}/tasks/{taskId}/subtasks/{subtaskId}")
    suspend fun updateSubtask(
        @Path("orderId") orderId: String,
        @Path("taskId") taskId: String,
        @Path("subtaskId") subtaskId: String,
        @Body body: Map<String, @JvmSuppressWildcards Any>
    ): Response<OrderResponse>

    @POST("api/orders/{orderId}/tasks/{taskId}/time-log")
    suspend fun logTaskTime(
        @Path("orderId") orderId: String,
        @Path("taskId") taskId: String,
        @Body body: Map<String, @JvmSuppressWildcards Any>
    ): Response<OrderResponse>

    @PUT("api/orders/{orderId}/requirements/{requirementId}/status")
    suspend fun updateRequirementStatus(
        @Path("orderId") orderId: String,
        @Path("requirementId") requirementId: String,
        @Body body: Map<String, String>
    ): Response<OrderResponse>

    @POST("api/orders/{orderId}/requirements")
    suspend fun raiseRequirement(
        @Path("orderId") orderId: String,
        @Body body: Map<String, String>
    ): Response<OrderResponse>

    @Multipart
    @POST("api/orders/{id}/documents")
    suspend fun uploadFinalCertificate(
        @Path("id") id: String,
        @Part document: okhttp3.MultipartBody.Part
    ): Response<OrderResponse>

    // --- DYNAMIC SERVER-DRIVEN SERVICES ---
    @GET("api/service-pages")
    suspend fun getDynamicServices(): Response<List<com.sbr.vrherebms.data.model.MobileServiceDetail>>

    companion object {
        // base URL pointing directly to the live website database
        var BASE_URL = "https://vrhere.in/"

        private var instance: VRHereAPI? = null

        fun getInstance(context: Context): VRHereAPI {
            if (instance == null) {
                val sessionManager = SessionManager(context)
                val loggingInterceptor = HttpLoggingInterceptor().apply {
                    level = HttpLoggingInterceptor.Level.BODY
                }

                val okHttpClient = OkHttpClient.Builder()
                    .addInterceptor(AuthInterceptor(sessionManager))
                    .addInterceptor(loggingInterceptor)
                    .connectTimeout(30, TimeUnit.SECONDS)
                    .readTimeout(30, TimeUnit.SECONDS)
                    .build()

                instance = Retrofit.Builder()
                    .baseUrl(BASE_URL)
                    .client(okHttpClient)
                    .addConverterFactory(GsonConverterFactory.create())
                    .build()
                    .create(VRHereAPI::class.java)
            }
            return instance!!
        }
    }
}
