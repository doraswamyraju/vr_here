package com.sbr.vrherebms.viewmodel

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.sbr.vrherebms.data.model.*
import com.sbr.vrherebms.data.remote.VRHereAPI
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch

class AdminDashboardViewModel(application: Application) : AndroidViewModel(application) {
    private val api = VRHereAPI.getInstance(application)

    // State Variables
    var orders by mutableStateOf<List<OrderResponse>>(emptyList())
    var todos by mutableStateOf<List<TodoResponse>>(emptyList())
    var employees by mutableStateOf<List<EmployeeResponse>>(emptyList())
    var freelancers by mutableStateOf<List<FreelancerResponse>>(emptyList())
    var users by mutableStateOf<List<UserProfile>>(emptyList())
    var notifications by mutableStateOf<List<NotificationResponse>>(emptyList())
    var payments by mutableStateOf<List<PaymentResponse>>(emptyList())
    var leads by mutableStateOf<List<LeadResponse>>(emptyList())
    var leadStats by mutableStateOf<LeadStatsResponse?>(null)
    var attendanceItems by mutableStateOf<List<AttendanceSummaryItem>>(emptyList())
    var selectedOrderId by mutableStateOf<String?>(null)
    var activeBannerNotification by mutableStateOf<NotificationResponse?>(null)
        private set
    var isLoading by mutableStateOf(false)

    // Dynamic Calculations
    val activePipelineCount: Int
        get() = orders.filter { it.status != "Completed" }.size

    val totalPipelineValue: Double
        get() = orders.sumOf { it.price }

    val statTotalOrders: Int
        get() = orders.size

    val statPending: Int
        get() = orders.filter { it.status != "Completed" }.size

    val statCompleted: Int
        get() = orders.filter { it.status == "Completed" }.size

    // UI Event Flow
    private val _eventFlow = MutableSharedFlow<UiEvent>()
    val eventFlow = _eventFlow.asSharedFlow()

    sealed class UiEvent {
        data class ShowToast(val message: String) : UiEvent()
    }

    fun dismissBanner() {
        activeBannerNotification = null
    }

    fun markNotificationAsRead(id: String) {
        viewModelScope.launch {
            try {
                val response = api.markNotificationAsRead(id)
                if (response.isSuccessful) {
                    notifications = notifications.map {
                        if (it.id == id) it.copy(isRead = true) else it
                    }
                }
            } catch (e: Exception) {
                // Fail silently for background notification action
            }
        }
    }

    fun markAllNotificationsAsRead() {
        viewModelScope.launch {
            try {
                val response = api.markAllNotificationsAsRead()
                if (response.isSuccessful) {
                    notifications = notifications.map { it.copy(isRead = true) }
                }
            } catch (e: Exception) {
                // Fail silently for background notification action
            }
        }
    }

    // Refresh Dashboard Data
    fun syncDashboardData(silent: Boolean = false) {
        if (!silent) {
            isLoading = true
        }
        viewModelScope.launch {
            try {
                // 1. Fetch Orders
                try {
                    val ordersCall = api.getOrders()
                    if (ordersCall.isSuccessful) {
                        orders = ordersCall.body() ?: emptyList()
                    } else if (!silent) {
                        _eventFlow.emit(UiEvent.ShowToast("Failed to fetch orders: ${ordersCall.message()}"))
                    }
                } catch (e: Exception) {
                    android.util.Log.e("AdminDashboard", "Failed to sync orders", e)
                }

                // 2. Fetch Todos
                try {
                    val todosCall = api.getTodos()
                    if (todosCall.isSuccessful) {
                        todos = todosCall.body() ?: emptyList()
                    }
                } catch (e: Exception) {
                    android.util.Log.e("AdminDashboard", "Failed to sync todos", e)
                }

                // 3. Fetch Employees
                try {
                    val employeesCall = api.getEmployees()
                    if (employeesCall.isSuccessful) {
                        employees = employeesCall.body() ?: emptyList()
                    }
                } catch (e: Exception) {
                    android.util.Log.e("AdminDashboard", "Failed to sync employees", e)
                }

                // 4. Fetch Freelancers
                try {
                    val freelancersCall = api.getAdminFreelancers()
                    if (freelancersCall.isSuccessful) {
                        freelancers = freelancersCall.body() ?: emptyList()
                    }
                } catch (e: Exception) { }

                // 5. Fetch Users
                try {
                    val usersCall = api.getAdminUsers()
                    if (usersCall.isSuccessful) {
                        users = usersCall.body() ?: emptyList()
                    }
                } catch (e: Exception) { }

                // 6. Fetch Notifications
                try {
                    val notificationsCall = api.getNotifications()
                    if (notificationsCall.isSuccessful) {
                        val newNotifications = notificationsCall.body() ?: emptyList()
                        if (notifications.isNotEmpty() && newNotifications.isNotEmpty()) {
                            val newUnreads = newNotifications.filter { item ->
                                !item.isRead && !notifications.any { old -> old.id == item.id }
                            }
                            if (newUnreads.isNotEmpty()) {
                                val latest = newUnreads.first()
                                activeBannerNotification = latest
                                com.sbr.vrherebms.utils.NotificationHelper.showNotification(
                                    getApplication(),
                                    latest.id.hashCode(),
                                    latest.title,
                                    latest.message,
                                    latest.type
                                )
                            }
                        }
                        notifications = newNotifications
                    }
                } catch (e: Exception) {
                    android.util.Log.e("AdminDashboard", "Failed to sync notifications", e)
                }

                // 7. Fetch Payments
                try {
                    val paymentsCall = api.getPayments()
                    if (paymentsCall.isSuccessful) {
                        payments = paymentsCall.body() ?: emptyList()
                    }
                } catch (e: Exception) {
                    android.util.Log.e("AdminDashboard", "Failed to sync payments", e)
                }

                // 8. Fetch Leads & Stats
                try {
                    val leadsCall = api.getLeads()
                    if (leadsCall.isSuccessful) {
                        leads = leadsCall.body()?.leads ?: emptyList()
                    }
                    val statsCall = api.getLeadStats()
                    if (statsCall.isSuccessful) {
                        leadStats = statsCall.body()
                    }
                } catch (e: Exception) {
                    android.util.Log.e("AdminDashboard", "Failed to sync leads", e)
                }

                // 9. Fetch Attendance Summary
                try {
                    val attCall = api.getAttendanceSummary()
                    if (attCall.isSuccessful) {
                        attendanceItems = attCall.body()?.items ?: emptyList()
                    }
                } catch (e: Exception) {
                    android.util.Log.e("AdminDashboard", "Failed to sync attendance summary", e)
                }

                if (!silent) {
                    isLoading = false
                }
            } catch (e: Exception) {
                if (!silent) {
                    isLoading = false
                    _eventFlow.emit(UiEvent.ShowToast("Sync error: ${e.localizedMessage}"))
                }
            }
        }
    }

    // CRM Actions
    fun updateLeadStatus(leadId: String, status: String, onComplete: (() -> Unit)? = null) {
        viewModelScope.launch {
            try {
                val call = api.updateLeadStatus(leadId, mapOf("status" to status))
                if (call.isSuccessful) {
                    _eventFlow.emit(UiEvent.ShowToast("Lead status updated to $status!"))
                    syncDashboardData(silent = true)
                    onComplete?.invoke()
                }
            } catch (e: Exception) {
                _eventFlow.emit(UiEvent.ShowToast("Failed to update lead: ${e.localizedMessage}"))
            }
        }
    }

    fun assignLead(leadId: String, employeeId: String, onComplete: (() -> Unit)? = null) {
        viewModelScope.launch {
            try {
                val call = api.assignLead(leadId, mapOf("assignedTo" to employeeId))
                if (call.isSuccessful) {
                    _eventFlow.emit(UiEvent.ShowToast("Lead assigned successfully!"))
                    syncDashboardData(silent = true)
                    onComplete?.invoke()
                }
            } catch (e: Exception) {
                _eventFlow.emit(UiEvent.ShowToast("Failed to assign lead: ${e.localizedMessage}"))
            }
        }
    }

    fun addLeadNote(leadId: String, text: String, onComplete: (() -> Unit)? = null) {
        viewModelScope.launch {
            try {
                val call = api.addLeadNote(leadId, mapOf("text" to text))
                if (call.isSuccessful) {
                    _eventFlow.emit(UiEvent.ShowToast("Note added!"))
                    syncDashboardData(silent = true)
                    onComplete?.invoke()
                }
            } catch (e: Exception) {
                _eventFlow.emit(UiEvent.ShowToast("Failed to add note: ${e.localizedMessage}"))
            }
        }
    }

    // Update Order Status
    fun updateOrderStatus(orderId: String, status: String) {
        viewModelScope.launch {
            try {
                val call = api.updateOrderStatus(orderId, mapOf("status" to status))
                if (call.isSuccessful) {
                    _eventFlow.emit(UiEvent.ShowToast("Status updated to $status!"))
                    syncDashboardData(silent = true)
                }
            } catch (e: Exception) {
                _eventFlow.emit(UiEvent.ShowToast("Failed to update status: ${e.localizedMessage}"))
            }
        }
    }

    // Update Order Client Name
    fun updateOrderClientName(orderId: String, clientName: String) {
        viewModelScope.launch {
            try {
                val call = api.updateOrderStatus(orderId, mapOf("clientName" to clientName))
                if (call.isSuccessful) {
                    _eventFlow.emit(UiEvent.ShowToast("Client name updated!"))
                    syncDashboardData(silent = true)
                }
            } catch (e: Exception) {
                _eventFlow.emit(UiEvent.ShowToast("Failed to update name: ${e.localizedMessage}"))
            }
        }
    }

    // Update 5-column Assignments
    fun updateAssignments(
        orderId: String,
        employeeId: String?,
        makerId: String?,
        checkerId: String?,
        pmId: String?,
        freelancerId: String?
    ) {
        viewModelScope.launch {
            try {
                val map = mutableMapOf<String, String?>()
                if (employeeId != null) map["assignedEmployee"] = employeeId
                if (makerId != null) map["assignedMaker"] = makerId
                if (checkerId != null) map["assignedChecker"] = checkerId
                if (pmId != null) map["assignedProjectManager"] = pmId
                if (freelancerId != null) map["assignedFreelancer"] = freelancerId

                val call = api.updateOrderAssignments(orderId, map)
                if (call.isSuccessful) {
                    _eventFlow.emit(UiEvent.ShowToast("Specialist assignments updated!"))
                    syncDashboardData(silent = true)
                }
            } catch (e: Exception) {
                _eventFlow.emit(UiEvent.ShowToast("Assignment update failed: ${e.localizedMessage}"))
            }
        }
    }

    // Create Order Manual Call
    fun createOrder(body: Map<String, Any>, onResult: (Boolean) -> Unit) {
        isLoading = true
        viewModelScope.launch {
            try {
                val call = api.createOrder(body)
                if (call.isSuccessful && call.body() != null) {
                    _eventFlow.emit(UiEvent.ShowToast("New order created successfully!"))
                    syncDashboardData()
                    onResult(true)
                } else {
                    _eventFlow.emit(UiEvent.ShowToast("Order creation failed: ${call.message()}"))
                    onResult(false)
                }
                isLoading = false
            } catch (e: Exception) {
                isLoading = false
                _eventFlow.emit(UiEvent.ShowToast("Network error: ${e.localizedMessage}"))
                onResult(false)
            }
        }
    }

    // 1:1 Web NewOrderModal: register client if requested, then create order
    fun createOrderWithClientRegistration(
        body: Map<String, Any>,
        isRegisteringClient: Boolean,
        clientName: String,
        email: String,
        phone: String,
        onResult: (Boolean) -> Unit
    ) {
        isLoading = true
        viewModelScope.launch {
            try {
                val orderPayload = body.toMutableMap()
                var finalUserId = (orderPayload["userId"] as? String) ?: ""

                if (isRegisteringClient && finalUserId.isBlank()) {
                    try {
                        val userCall = api.createAdminUser(
                            mapOf(
                                "name" to clientName,
                                "email" to email,
                                "phone" to phone,
                                "role" to "client"
                            )
                        )
                        if (userCall.isSuccessful && userCall.body() != null) {
                            finalUserId = userCall.body()!!.id
                            orderPayload["userId"] = finalUserId
                        }
                    } catch (err: Exception) {
                        // Log and proceed or show toast
                    }
                }

                val call = api.createOrder(orderPayload)
                if (call.isSuccessful && call.body() != null) {
                    _eventFlow.emit(UiEvent.ShowToast("New order created successfully!"))
                    syncDashboardData()
                    onResult(true)
                } else {
                    _eventFlow.emit(UiEvent.ShowToast("Order creation failed: ${call.message()}"))
                    onResult(false)
                }
                isLoading = false
            } catch (e: Exception) {
                isLoading = false
                _eventFlow.emit(UiEvent.ShowToast("Network error: ${e.localizedMessage}"))
                onResult(false)
            }
        }
    }

    // Create Todo Call
    fun createTodo(request: CreateTodoRequest, onResult: (Boolean) -> Unit) {
        isLoading = true
        viewModelScope.launch {
            try {
                val call = api.createTodo(request)
                if (call.isSuccessful && call.body() != null) {
                    _eventFlow.emit(UiEvent.ShowToast("Task added successfully!"))
                    syncDashboardData()
                    onResult(true)
                } else {
                    _eventFlow.emit(UiEvent.ShowToast("Failed to create task: ${call.message()}"))
                    onResult(false)
                }
                isLoading = false
            } catch (e: Exception) {
                isLoading = false
                _eventFlow.emit(UiEvent.ShowToast("Network error: ${e.localizedMessage}"))
                onResult(false)
            }
        }
    }

    fun updateTodoStatus(todoId: String, status: String) {
        viewModelScope.launch {
            try {
                val response = api.updateTodoStatus(todoId, mapOf("status" to status))
                if (response.isSuccessful) {
                    _eventFlow.emit(UiEvent.ShowToast("Task updated!"))
                    syncDashboardData(silent = true)
                }
            } catch (e: Exception) {
                _eventFlow.emit(UiEvent.ShowToast("Failed to update task: ${e.localizedMessage}"))
            }
        }
    }

    fun deleteTodo(todoId: String) {
        viewModelScope.launch {
            try {
                val response = api.deleteTodo(todoId)
                if (response.isSuccessful) {
                    _eventFlow.emit(UiEvent.ShowToast("Task deleted!"))
                    syncDashboardData(silent = true)
                }
            } catch (e: Exception) {
                _eventFlow.emit(UiEvent.ShowToast("Failed to delete task: ${e.localizedMessage}"))
            }
        }
    }
}
