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
    var notifications by mutableStateOf<List<NotificationResponse>>(emptyList())
    var payments by mutableStateOf<List<PaymentResponse>>(emptyList())
    var activeBannerNotification by mutableStateOf<NotificationResponse?>(null)
        private set
    var isLoading by mutableStateOf(false)

    init {
        syncAdminDashboard()
        startFirestoreNotificationsListener()
    }

    private fun startFirestoreNotificationsListener() {
        com.sbr.vrherebms.utils.FirestoreNotificationHelper.startListening(getApplication()) { list ->
            if (list.isNotEmpty()) {
                val oldList = notifications
                if (oldList.isNotEmpty()) {
                    val newUnreads = list.filter { item ->
                        !item.isRead && !oldList.any { old -> old.id == item.id }
                    }
                    if (newUnreads.isNotEmpty()) {
                        activeBannerNotification = newUnreads.first()
                    }
                }
                notifications = list
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        com.sbr.vrherebms.utils.FirestoreNotificationHelper.stopListening()
    }

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
        // 1. Update Firestore
        com.sbr.vrherebms.utils.FirestoreNotificationHelper.markAsRead(getApplication(), id)

        // 2. Sync MongoDB
        viewModelScope.launch {
            try {
                api.markNotificationAsRead(id)
                notifications = notifications.map {
                    if (it.id == id) it.copy(isRead = true) else it
                }
            } catch (e: Exception) {
                // ignore
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
                val ordersCall = api.getOrders()
                if (ordersCall.isSuccessful) {
                    orders = ordersCall.body() ?: emptyList()
                } else if (!silent) {
                    _eventFlow.emit(UiEvent.ShowToast("Failed to fetch orders: ${ordersCall.message()}"))
                }

                // 2. Fetch Todos
                val todosCall = api.getTodos()
                if (todosCall.isSuccessful) {
                    todos = todosCall.body() ?: emptyList()
                } else if (!silent) {
                    _eventFlow.emit(UiEvent.ShowToast("Failed to fetch tasks: ${todosCall.message()}"))
                }

                // 3. Fetch Employees
                val employeesCall = api.getEmployees()
                if (employeesCall.isSuccessful) {
                    employees = employeesCall.body() ?: emptyList()
                }

                // 4. Fetch Notifications (Non-blocking catch to prevent deployment delay crash)
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

                // 5. Fetch Payments
                try {
                    val paymentsCall = api.getPayments()
                    if (paymentsCall.isSuccessful) {
                        payments = paymentsCall.body() ?: emptyList()
                    }
                } catch (e: Exception) {
                    android.util.Log.e("AdminDashboard", "Failed to sync payments", e)
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
}
