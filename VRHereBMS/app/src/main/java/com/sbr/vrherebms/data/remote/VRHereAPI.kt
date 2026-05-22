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

    // --- ATTENDANCE ---
    @GET("api/attendance")
    suspend fun getAttendance(): Response<List<AttendanceResponse>>

    @POST("api/attendance/clock-in")
    suspend fun clockIn(@Body request: ClockInRequest): Response<AttendanceResponse>

    @POST("api/attendance/clock-out")
    suspend fun clockOut(): Response<AttendanceResponse>

    companion object {
        // base URL pointing to the standard local dev server from Android emulator
        // In a real device or production, replace this with your domain name (e.g., https://vrhere.in/)
        var BASE_URL = "http://10.0.2.2:5002/"

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
