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

    @PUT("api/auth/profile")
    suspend fun updateProfile(@Body body: Map<String, @JvmSuppressWildcards Any>): Response<UserProfile>

    @Multipart
    @POST("api/auth/upload-avatar")
    suspend fun uploadAvatar(@Part image: okhttp3.MultipartBody.Part): Response<Map<String, String>>

    @Multipart
    @POST("api/auth/upload-logo")
    suspend fun uploadCompanyLogo(@Part image: okhttp3.MultipartBody.Part): Response<Map<String, String>>

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

    @PUT("api/orders/{id}/requirements/{reqId}")
    suspend fun updateOrderRequirement(
        @Path("id") id: String,
        @Path("reqId") reqId: String,
        @Body body: Map<String, @JvmSuppressWildcards Any>
    ): Response<OrderResponse>

    @Multipart
    @POST("api/orders/{id}/documents")
    suspend fun uploadRequirementDocument(
        @Path("id") id: String,
        @Part document: okhttp3.MultipartBody.Part,
        @Part("requirementId") requirementId: okhttp3.RequestBody
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

    @PUT("api/tickets/{id}/status")
    suspend fun updateTicketStatus(
        @Path("id") ticketId: String,
        @Body request: Map<String, String>
    ): Response<TicketResponse>

    // --- NOTIFICATIONS ---
    @GET("api/notifications")
    suspend fun getNotifications(): Response<List<NotificationResponse>>

    @PUT("api/notifications/{id}/read")
    suspend fun markNotificationAsRead(@Path("id") id: String): Response<NotificationResponse>

    @PUT("api/notifications/readall")
    suspend fun markAllNotificationsAsRead(): Response<Map<String, Any>>

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

    @GET("api/auth/users")
    suspend fun getAdminUsers(): Response<List<UserProfile>>

    @GET("api/freelancers/admin/users")
    suspend fun getAdminFreelancers(): Response<List<FreelancerResponse>>

    @POST("api/auth/users")
    suspend fun createAdminUser(@Body body: Map<String, @JvmSuppressWildcards Any>): Response<UserProfile>

    @PUT("api/auth/users/{id}")
    suspend fun updateAdminUser(@Path("id") id: String, @Body body: Map<String, @JvmSuppressWildcards Any>): Response<UserProfile>

    @DELETE("api/auth/users/{id}")
    suspend fun deleteAdminUser(@Path("id") id: String): Response<GeneralApiResponse>

    // --- ORDER CHAT & MESSAGES ---
    @GET("api/orders/{id}/messages")
    suspend fun getOrderMessages(
        @Path("id") orderId: String,
        @Query("messageType") messageType: String? = null
    ): Response<List<OrderChatMessage>>

    @Multipart
    @POST("api/orders/{id}/messages")
    suspend fun sendOrderMessage(
        @Path("id") orderId: String,
        @Part("message") message: okhttp3.RequestBody,
        @Part("messageType") messageType: okhttp3.RequestBody,
        @Part file: okhttp3.MultipartBody.Part? = null
    ): Response<OrderChatMessage>

    @GET("api/orders/{id}/messages/unread-count")
    suspend fun getOrderUnreadCount(
        @Path("id") orderId: String
    ): Response<OrderUnreadCountResponse>

    // --- EMPLOYEE TRANSACTION Endpoints ---
    @PUT("api/todos/{id}")
    suspend fun updateTodoStatus(
        @Path("id") id: String,
        @Body body: Map<String, String>
    ): Response<TodoResponse>

    @DELETE("api/todos/{id}")
    suspend fun deleteTodo(
        @Path("id") id: String
    ): Response<Map<String, Any>>

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

    // --- DYNAMIC SERVER-DRIVEN SERVICES & LEADS TELEMETRY ---
    @GET("api/service-pages")
    suspend fun getDynamicServices(): Response<List<com.sbr.vrherebms.data.model.MobileServiceDetail>>

    @GET("api/service-pages/{pageId}")
    suspend fun getServicePageById(@Path("pageId") pageId: String): Response<com.sbr.vrherebms.data.model.MobileServiceDetail>

    @POST("api/leads/telemetry")
    suspend fun sendLeadTelemetry(@Body request: com.sbr.vrherebms.data.model.LeadTelemetryRequest): Response<Map<String, Any>>

    // --- CRM LEADS ---
    @GET("api/leads")
    suspend fun getLeads(): Response<LeadListResponse>

    @GET("api/leads/stats")
    suspend fun getLeadStats(): Response<LeadStatsResponse>

    @PUT("api/leads/{id}/status")
    suspend fun updateLeadStatus(
        @Path("id") id: String,
        @Body body: Map<String, String>
    ): Response<LeadResponse>

    @PUT("api/leads/{id}/assign")
    suspend fun assignLead(
        @Path("id") id: String,
        @Body body: Map<String, String>
    ): Response<LeadResponse>

    @POST("api/leads/{id}/notes")
    suspend fun addLeadNote(
        @Path("id") id: String,
        @Body body: Map<String, String>
    ): Response<LeadResponse>

    // --- DYNAMIC BLOGS & PROMOTIONAL OFFERS CMS ---
    @GET("api/blogs")
    suspend fun getBlogs(): Response<List<BlogResponse>>

    @GET("api/blogs/{slug}")
    suspend fun getBlogBySlug(@Path("slug") slug: String): Response<BlogResponse>

    @GET("api/offers")
    suspend fun getOffers(): Response<List<OfferResponse>>

    // --- CUSTOMER REFERRAL ENDPOINTS ---
    @GET("api/customer/referrals/stats")
    suspend fun getCustomerReferralStats(): Response<CustomerReferralStatsResponse>

    @POST("api/customer/referrals/lead")
    suspend fun addCustomerReferralLead(@Body request: AddReferralLeadRequest): Response<GeneralApiResponse>

    @POST("api/customer/referrals/payout-request")
    suspend fun requestCustomerUpiPayout(@Body request: UpiPayoutRequest): Response<GeneralApiResponse>

    // --- USER VAULT DOCUMENT ENDPOINTS ---
    @GET("api/documents")
    suspend fun getUserVaultDocuments(): Response<UserVaultDocumentsResponse>

    @Multipart
    @POST("api/documents/upload")
    suspend fun uploadUserVaultDocument(
        @Part document: okhttp3.MultipartBody.Part,
        @Part("docType") docType: okhttp3.RequestBody
    ): Response<GeneralApiResponse>

    @DELETE("api/documents/{id}")
    suspend fun deleteUserVaultDocument(@Path("id") id: String): Response<GeneralApiResponse>

    // --- BOOKKEEPING & AAAS (ACCOUNTING) ENDPOINTS ---
    @GET("api/accounting/transactions")
    suspend fun getAccountingTransactions(
        @Query("type") type: String? = null,
        @Query("month") month: String? = null,
        @Query("status") status: String? = null
    ): Response<List<TransactionDto>>

    @POST("api/accounting/transactions")
    suspend fun createAccountingTransaction(@Body transaction: TransactionDto): Response<TransactionDto>

    @PUT("api/accounting/transactions/{id}")
    suspend fun updateAccountingTransaction(
        @Path("id") id: String,
        @Body transaction: TransactionDto
    ): Response<TransactionDto>

    @DELETE("api/accounting/transactions/{id}")
    suspend fun deleteAccountingTransaction(@Path("id") id: String): Response<GeneralApiResponse>

    @POST("api/accounting/transactions/{id}/payment")
    suspend fun recordAccountingPayment(
        @Path("id") id: String,
        @Body request: RecordPaymentRequest
    ): Response<TransactionDto>

    @GET("api/accounting/company")
    suspend fun getCompanyDetails(): Response<CompanyDetailsDto>

    @POST("api/accounting/company")
    suspend fun updateCompanyDetails(@Body details: CompanyDetailsDto): Response<CompanyDetailsDto>

    @GET("api/accounting/parties")
    suspend fun getAccountingParties(@Query("partyType") partyType: String? = null): Response<List<PartyDto>>

    @POST("api/accounting/parties")
    suspend fun createAccountingParty(@Body party: PartyDto): Response<PartyDto>

    @PUT("api/accounting/parties/{id}")
    suspend fun updateAccountingParty(
        @Path("id") id: String,
        @Body party: PartyDto
    ): Response<PartyDto>

    @DELETE("api/accounting/parties/{id}")
    suspend fun deleteAccountingParty(@Path("id") id: String): Response<GeneralApiResponse>

    @GET("api/accounting/bank-statements")
    suspend fun getBankStatements(): Response<List<BankStatementDto>>

    @POST("api/accounting/bank-statements")
    suspend fun createBankStatement(@Body statement: BankStatementDto): Response<BankStatementDto>

    @DELETE("api/accounting/bank-statements/{id}")
    suspend fun deleteBankStatement(@Path("id") id: String): Response<GeneralApiResponse>

    @POST("api/accounting/bank-statements/{id}/tag")
    suspend fun tagBankTransaction(
        @Path("id") id: String,
        @Body request: TagBankTransactionRequest
    ): Response<GeneralApiResponse>

    // --- BOOKKEEPING / FILINGS MATRIX & CLIENT AUDIT ---
    @GET("api/accounting/filings/matrix")
    suspend fun getFilingsMatrix(@Query("month") month: String): Response<FilingsMatrixResponse>

    @GET("api/accounting/transactions")
    suspend fun getClientAccountingTransactions(
        @Query("clientId") clientId: String
    ): Response<List<TransactionDto>>

    @GET("api/accounting/payroll")
    suspend fun getClientPayroll(
        @Query("clientId") clientId: String
    ): Response<List<AccountingPayrollRecord>>

    @POST("api/accounting/payroll")
    suspend fun createPayrollRecord(
        @Body request: CreatePayrollRequest
    ): Response<AccountingPayrollRecord>

    @GET("api/accounting/export/gstr3b")
    suspend fun getGstr3bExport(
        @Query("clientId") clientId: String
    ): Response<Gstr3bResponseData>

    // --- PARTNER ADMIN PAYOUTS ---
    @GET("api/partner/admin/payouts")
    suspend fun getPartnerPayouts(): Response<List<PartnerAdminPayoutItem>>

    @PUT("api/partner/admin/payouts/{id}")
    suspend fun updatePartnerPayoutStatus(
        @Path("id") id: String,
        @Body request: UpdatePartnerPayoutRequest
    ): Response<PartnerAdminPayoutItem>

    // --- RECURRING SERVICES HUB ---
    @GET("api/recurring")
    suspend fun getRecurringSubscriptions(): Response<List<RecurringSubscriptionItem>>

    @PUT("api/recurring/{id}")
    suspend fun updateRecurringSubscriptionStatus(
        @Path("id") id: String,
        @Body request: UpdateRecurringStatusRequest
    ): Response<RecurringSubscriptionItem>

    @DELETE("api/recurring/{id}")
    suspend fun deleteRecurringSubscription(
        @Path("id") id: String
    ): Response<GeneralApiResponse>

    @POST("api/recurring")
    suspend fun createRecurringSubscription(
        @Body request: CreateRecurringSubscriptionRequest
    ): Response<RecurringSubscriptionItem>

    // --- BLOGS & INSIGHTS ---
    @GET("api/blogs")
    suspend fun getAdminBlogs(): Response<List<BlogItem>>

    @POST("api/blogs")
    suspend fun createBlog(@Body blog: BlogItem): Response<BlogItem>

    @DELETE("api/blogs/{id}")
    suspend fun deleteBlog(@Path("id") id: String): Response<GeneralApiResponse>

    // --- OFFERS & SCHEMES ---
    @GET("api/offers")
    suspend fun getAdminOffers(): Response<List<OfferItem>>

    @POST("api/offers")
    suspend fun createOffer(@Body offer: OfferItem): Response<OfferItem>

    @DELETE("api/offers/{id}")
    suspend fun deleteOffer(@Path("id") id: String): Response<GeneralApiResponse>

    // --- RENEWALS HUB ---
    @GET("api/renewals/pending")
    suspend fun getPendingRenewals(): Response<RenewalsPendingResponse>

    // --- FREELANCERS & APPLICANTS ---
    @GET("api/freelancers/applicants")
    suspend fun getFreelancerApplicants(): Response<List<FreelancerApplicant>>

    @PATCH("api/freelancers/applicants/{id}/status")
    suspend fun updateFreelancerApplicantStatus(
        @Path("id") id: String,
        @Body request: UpdateApplicantStatusRequest
    ): Response<FreelancerApplicant>

    @GET("api/freelancers/admin/payouts")
    suspend fun getFreelancerPayouts(): Response<FreelancerPayoutsResponse>

    @POST("api/freelancers/admin/payouts/{id}/settle")
    suspend fun settleFreelancerPayout(
        @Path("id") id: String,
        @Body request: SettlePayoutRequest
    ): Response<GeneralApiResponse>

    @POST("api/freelancers/broadcast-order")
    suspend fun broadcastFreelancerOrder(
        @Body request: BroadcastOrderRequest
    ): Response<GeneralApiResponse>

    // --- LIVE ATTENDANCE SUMMARY ---
    @GET("api/attendance/summary")
    suspend fun getAttendanceSummary(): Response<AttendanceSummaryResponse>

    // --- SERVICES HEADER CONFIG ---
    @PUT("api/services/header-config")
    suspend fun saveServicesHeaderConfig(
        @Body request: ServicesHeaderConfigRequest
    ): Response<GeneralApiResponse>

    // --- PASSWORD RESET LINK GENERATION ---
    @POST("api/auth/generate-reset-link")
    suspend fun generatePasswordResetLink(
        @Body body: Map<String, String>
    ): Response<PasswordLinkResponse>

    // --- WORKFLOW TICKETS & ORDER ACTIONS ---
    @POST("api/orders/{id}/workflow-tickets")
    suspend fun createOrderWorkflowTicket(
        @Path("id") id: String,
        @Body request: TicketWorkflowCreateRequest
    ): Response<WorkflowTicketResponse>

    @POST("api/orders/{id}/recurring")
    suspend fun setupOrderRecurringSchedule(
        @Path("id") id: String,
        @Body request: RecurringScheduleRequest
    ): Response<OrderResponse>

    @PATCH("api/orders/{id}/assignments")
    suspend fun updateOrderAssignments(
        @Path("id") id: String,
        @Body body: Map<String, String?>
    ): Response<OrderResponse>

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

                val gson = com.google.gson.GsonBuilder()
                    .registerTypeAdapter(UserProfile::class.java, com.google.gson.JsonDeserializer { json, _, _ ->
                        if (json == null || json.isJsonNull) return@JsonDeserializer null
                        if (json.isJsonPrimitive && json.asJsonPrimitive.isString) {
                            return@JsonDeserializer UserProfile(id = json.asString, name = "")
                        }
                        if (json.isJsonObject) {
                            val obj = json.asJsonObject
                            return@JsonDeserializer UserProfile(
                                id = obj.get("_id")?.takeIf { !it.isJsonNull }?.asString
                                    ?: obj.get("id")?.takeIf { !it.isJsonNull }?.asString ?: "",
                                name = obj.get("name")?.takeIf { !it.isJsonNull }?.asString ?: "",
                                email = obj.get("email")?.takeIf { !it.isJsonNull }?.asString ?: "",
                                phone = obj.get("phone")?.takeIf { !it.isJsonNull }?.asString,
                                role = obj.get("role")?.takeIf { !it.isJsonNull }?.asString ?: "client",
                                profilePhoto = obj.get("profilePhoto")?.takeIf { !it.isJsonNull }?.asString,
                                companyLogo = obj.get("companyLogo")?.takeIf { !it.isJsonNull }?.asString,
                                companyName = obj.get("companyName")?.takeIf { !it.isJsonNull }?.asString,
                                businessType = obj.get("businessType")?.takeIf { !it.isJsonNull }?.asString,
                                gstin = obj.get("gstin")?.takeIf { !it.isJsonNull }?.asString,
                                panNumber = obj.get("panNumber")?.takeIf { !it.isJsonNull }?.asString,
                                address = obj.get("address")?.takeIf { !it.isJsonNull }?.asString,
                                isActive = obj.get("isActive")?.takeIf { !it.isJsonNull }?.asBoolean ?: true
                            )
                        }
                        null
                    })
                    .registerTypeAdapter(EmployeeResponse::class.java, com.google.gson.JsonDeserializer { json, _, _ ->
                        if (json == null || json.isJsonNull) return@JsonDeserializer null
                        if (json.isJsonPrimitive && json.asJsonPrimitive.isString) {
                            return@JsonDeserializer EmployeeResponse(id = json.asString, name = "")
                        }
                        if (json.isJsonObject) {
                            val obj = json.asJsonObject
                            return@JsonDeserializer EmployeeResponse(
                                id = obj.get("_id")?.takeIf { !it.isJsonNull }?.asString
                                    ?: obj.get("id")?.takeIf { !it.isJsonNull }?.asString ?: "",
                                name = obj.get("name")?.takeIf { !it.isJsonNull }?.asString ?: "",
                                email = obj.get("email")?.takeIf { !it.isJsonNull }?.asString ?: "",
                                phone = obj.get("phone")?.takeIf { !it.isJsonNull }?.asString ?: "",
                                profilePhoto = obj.get("profilePhoto")?.takeIf { !it.isJsonNull }?.asString,
                                role = obj.get("role")?.takeIf { !it.isJsonNull }?.asString ?: ""
                            )
                        }
                        null
                    })
                    .registerTypeAdapter(PartnerMinRef::class.java, com.google.gson.JsonDeserializer { json, _, _ ->
                        if (json == null || json.isJsonNull) return@JsonDeserializer null
                        if (json.isJsonPrimitive && json.asJsonPrimitive.isString) {
                            return@JsonDeserializer PartnerMinRef(id = json.asString)
                        }
                        if (json.isJsonObject) {
                            val obj = json.asJsonObject
                            return@JsonDeserializer PartnerMinRef(
                                id = obj.get("_id")?.takeIf { !it.isJsonNull }?.asString
                                    ?: obj.get("id")?.takeIf { !it.isJsonNull }?.asString ?: "",
                                name = obj.get("name")?.takeIf { !it.isJsonNull }?.asString,
                                email = obj.get("email")?.takeIf { !it.isJsonNull }?.asString,
                                code = obj.get("code")?.takeIf { !it.isJsonNull }?.asString
                            )
                        }
                        null
                    })
                    .registerTypeAdapter(PaymentOrderReference::class.java, com.google.gson.JsonDeserializer { json, _, _ ->
                        if (json == null || json.isJsonNull) return@JsonDeserializer null
                        if (json.isJsonPrimitive && json.asJsonPrimitive.isString) {
                            return@JsonDeserializer PaymentOrderReference(id = json.asString)
                        }
                        if (json.isJsonObject) {
                            val obj = json.asJsonObject
                            return@JsonDeserializer PaymentOrderReference(
                                id = obj.get("_id")?.takeIf { !it.isJsonNull }?.asString
                                    ?: obj.get("id")?.takeIf { !it.isJsonNull }?.asString ?: "",
                                serviceName = obj.get("serviceName")?.takeIf { !it.isJsonNull }?.asString ?: "",
                                packageName = obj.get("packageName")?.takeIf { !it.isJsonNull }?.asString ?: "",
                                status = obj.get("status")?.takeIf { !it.isJsonNull }?.asString ?: ""
                            )
                        }
                        null
                    })
                    .registerTypeAdapter(TodoOrderReference::class.java, com.google.gson.JsonDeserializer { json, _, _ ->
                        if (json == null || json.isJsonNull) return@JsonDeserializer null
                        if (json.isJsonPrimitive && json.asJsonPrimitive.isString) {
                            return@JsonDeserializer TodoOrderReference(id = json.asString)
                        }
                        if (json.isJsonObject) {
                            val obj = json.asJsonObject
                            return@JsonDeserializer TodoOrderReference(
                                id = obj.get("_id")?.takeIf { !it.isJsonNull }?.asString
                                    ?: obj.get("id")?.takeIf { !it.isJsonNull }?.asString ?: "",
                                serviceName = obj.get("serviceName")?.takeIf { !it.isJsonNull }?.asString ?: "",
                                clientName = obj.get("clientName")?.takeIf { !it.isJsonNull }?.asString ?: ""
                            )
                        }
                        null
                    })
                    .setLenient()
                    .create()

                instance = Retrofit.Builder()
                    .baseUrl(BASE_URL)
                    .client(okHttpClient)
                    .addConverterFactory(GsonConverterFactory.create(gson))
                    .build()
                    .create(VRHereAPI::class.java)
            }
            return instance!!
        }
    }
}
