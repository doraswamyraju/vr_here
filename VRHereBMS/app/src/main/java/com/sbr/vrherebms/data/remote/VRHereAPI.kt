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

    // --- PARTNER ---
    @GET("api/partner/orders")
    suspend fun getPartnerOrders(): Response<List<PartnerOrderResponse>>

    @GET("api/partner/profile")
    suspend fun getPartnerProfile(): Response<PartnerProfileResponse>

    @PUT("api/partner/profile")
    suspend fun updatePartnerProfile(@Body profile: PartnerProfileUpdateDto): Response<PartnerProfileResponse>

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
