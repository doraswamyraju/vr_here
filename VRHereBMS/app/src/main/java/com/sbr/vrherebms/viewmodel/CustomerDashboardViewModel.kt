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

sealed class DashboardState {
    object Idle : DashboardState()
    object Loading : DashboardState()
    object Success : DashboardState()
    data class Error(val message: String) : DashboardState()
}

class CustomerDashboardViewModel(application: Application) : AndroidViewModel(application) {
    private val api = VRHereAPI.getInstance(application)

    var dashboardState by mutableStateOf<DashboardState>(DashboardState.Idle)
        private set

    // Cached lists
    var orders by mutableStateOf<List<OrderResponse>>(emptyList())
    var payments by mutableStateOf<List<PaymentResponse>>(emptyList())
    var tickets by mutableStateOf<List<TicketResponse>>(emptyList())
    var notifications by mutableStateOf<List<NotificationResponse>>(emptyList())
    
    var activeBannerNotification by mutableStateOf<NotificationResponse?>(null)
        private set

    init {
        refreshAllData()
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

    fun dismissBanner() {
        activeBannerNotification = null
    }

    // Raising support ticket inputs
    var ticketSubject by mutableStateOf("")
    var ticketDescription by mutableStateOf("")
    var ticketPriority by mutableStateOf("Low")

    var ticketReplyMessage by mutableStateOf("")

    private val _eventFlow = MutableSharedFlow<UiEvent>()
    val eventFlow = _eventFlow.asSharedFlow()

    sealed class UiEvent {
        data class ShowToast(val message: String) : UiEvent()
        object TicketCreated : UiEvent()
    }

    fun refreshAllData(silent: Boolean = false) {
        if (!silent) {
            dashboardState = DashboardState.Loading
        }
        viewModelScope.launch {
            var hasErrors = false
            var lastErrorMessage = ""

            // 1. Fetch Orders
            try {
                val ordersCall = api.getOrders()
                if (ordersCall.isSuccessful) {
                    orders = ordersCall.body() ?: emptyList()
                } else {
                    hasErrors = true
                    lastErrorMessage = "Orders: ${ordersCall.message()}"
                    android.util.Log.e("CustomerDashboard", "Orders fetch failed: ${ordersCall.message()} code: ${ordersCall.code()}")
                }
            } catch (e: Exception) {
                hasErrors = true
                lastErrorMessage = "Orders: ${e.localizedMessage}"
                android.util.Log.e("CustomerDashboard", "Orders sync exception", e)
            }

            // 2. Fetch Payments
            try {
                val paymentsCall = api.getPayments()
                if (paymentsCall.isSuccessful) {
                    payments = paymentsCall.body() ?: emptyList()
                } else {
                    hasErrors = true
                    lastErrorMessage = "Payments: ${paymentsCall.message()}"
                    android.util.Log.e("CustomerDashboard", "Payments fetch failed: ${paymentsCall.message()}")
                }
            } catch (e: Exception) {
                hasErrors = true
                lastErrorMessage = "Payments: ${e.localizedMessage}"
                android.util.Log.e("CustomerDashboard", "Payments sync exception", e)
            }

            // 3. Fetch Tickets
            try {
                val ticketsCall = api.getTickets()
                if (ticketsCall.isSuccessful) {
                    tickets = ticketsCall.body() ?: emptyList()
                } else {
                    hasErrors = true
                    lastErrorMessage = "Tickets: ${ticketsCall.message()}"
                    android.util.Log.e("CustomerDashboard", "Tickets fetch failed: ${ticketsCall.message()}")
                }
            } catch (e: Exception) {
                hasErrors = true
                lastErrorMessage = "Tickets: ${e.localizedMessage}"
                android.util.Log.e("CustomerDashboard", "Tickets sync exception", e)
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
                } else {
                    android.util.Log.e("CustomerDashboard", "Notifications fetch failed: ${notificationsCall.message()}")
                }
            } catch (e: Exception) {
                android.util.Log.e("CustomerDashboard", "Failed to sync notifications", e)
            }

            if (hasErrors) {
                if (!silent) {
                    dashboardState = DashboardState.Error(lastErrorMessage)
                    _eventFlow.emit(UiEvent.ShowToast(lastErrorMessage))
                }
            } else {
                dashboardState = DashboardState.Success
            }
        }
    }

    fun createSupportTicket() {
        if (ticketSubject.isEmpty() || ticketDescription.isEmpty()) {
            viewModelScope.launch {
                _eventFlow.emit(UiEvent.ShowToast("Please enter subject and description"))
            }
            return
        }

        viewModelScope.launch {
            try {
                val response = api.createTicket(
                    CreateTicketRequest(ticketSubject, ticketDescription, ticketPriority)
                )
                if (response.isSuccessful && response.body() != null) {
                    val newTicket = response.body()!!
                    tickets = listOf(newTicket) + tickets
                    ticketSubject = ""
                    ticketDescription = ""
                    ticketPriority = "Low"
                    _eventFlow.emit(UiEvent.ShowToast("Support ticket raised successfully!"))
                    _eventFlow.emit(UiEvent.TicketCreated)
                } else {
                    _eventFlow.emit(UiEvent.ShowToast("Failed to create ticket: ${response.message()}"))
                }
            } catch (e: Exception) {
                _eventFlow.emit(UiEvent.ShowToast("Connection error: ${e.localizedMessage}"))
            }
        }
    }

    fun replyToTicket(ticketId: String) {
        if (ticketReplyMessage.isEmpty()) return

        viewModelScope.launch {
            try {
                val response = api.addTicketMessage(ticketId, AddMessageRequest(ticketReplyMessage))
                if (response.isSuccessful && response.body() != null) {
                    val updatedTicket = response.body()!!
                    tickets = tickets.map { if (it.id == ticketId) updatedTicket else it }
                    ticketReplyMessage = ""
                    _eventFlow.emit(UiEvent.ShowToast("Reply sent!"))
                } else {
                    _eventFlow.emit(UiEvent.ShowToast("Failed to reply: ${response.message()}"))
                }
            } catch (e: Exception) {
                _eventFlow.emit(UiEvent.ShowToast("Connection error: ${e.localizedMessage}"))
            }
        }
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
                // Fail silently for background notification action
            }
        }
    }
}
