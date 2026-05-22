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

    fun refreshAllData() {
        dashboardState = DashboardState.Loading
        viewModelScope.launch {
            try {
                // Fetch in parallel
                val ordersCall = api.getOrders()
                val paymentsCall = api.getPayments()
                val ticketsCall = api.getTickets()
                val notificationsCall = api.getNotifications()

                if (ordersCall.isSuccessful) orders = ordersCall.body() ?: emptyList()
                if (paymentsCall.isSuccessful) payments = paymentsCall.body() ?: emptyList()
                if (ticketsCall.isSuccessful) tickets = ticketsCall.body() ?: emptyList()
                if (notificationsCall.isSuccessful) notifications = notificationsCall.body() ?: emptyList()

                dashboardState = DashboardState.Success
            } catch (e: Exception) {
                dashboardState = DashboardState.Error(e.localizedMessage ?: "Failed to sync data")
                _eventFlow.emit(UiEvent.ShowToast("Sync error: ${e.localizedMessage}"))
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
}
