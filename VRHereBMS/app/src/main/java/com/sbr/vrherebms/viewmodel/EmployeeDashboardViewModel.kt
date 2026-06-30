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
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.asRequestBody

class EmployeeDashboardViewModel(application: Application) : AndroidViewModel(application) {
    private val api = VRHereAPI.getInstance(application)

    var attendanceLogs by mutableStateOf<List<AttendanceResponse>>(emptyList())
    var assignedOrders by mutableStateOf<List<OrderResponse>>(emptyList())
    var assignedTodos by mutableStateOf<List<TodoResponse>>(emptyList())
    var supportTickets by mutableStateOf<List<TicketResponse>>(emptyList())
    var notifications by mutableStateOf<List<NotificationResponse>>(emptyList())

    var isClockedIn by mutableStateOf(false)
    var currentAttendanceRecord by mutableStateOf<AttendanceResponse?>(null)
    var clockInNote by mutableStateOf("")

    var isLoading by mutableStateOf(false)

    private val _eventFlow = MutableSharedFlow<UiEvent>()
    val eventFlow = _eventFlow.asSharedFlow()

    init {
        syncDashboardData()
        startFirestoreNotificationsListener()
    }

    private fun startFirestoreNotificationsListener() {
        com.sbr.vrherebms.utils.FirestoreNotificationHelper.startListening(getApplication()) { list ->
            if (list.isNotEmpty()) {
                notifications = list
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        com.sbr.vrherebms.utils.FirestoreNotificationHelper.stopListening()
    }

    sealed class UiEvent {
        data class ShowToast(val message: String) : UiEvent()
    }

    fun syncDashboardData() {
        isLoading = true
        viewModelScope.launch {
            try {
                // Fetch attendance logs
                val attendanceCall = api.getAttendance()
                if (attendanceCall.isSuccessful) {
                    attendanceLogs = attendanceCall.body() ?: emptyList()
                    // Find active record that has no clock-out date yet
                    val activeRecord = attendanceLogs.find { it.clockOutAt == null }
                    isClockedIn = activeRecord != null
                    currentAttendanceRecord = activeRecord
                }

                // Fetch assigned orders/tasks
                val ordersCall = api.getOrders()
                if (ordersCall.isSuccessful) {
                    assignedOrders = ordersCall.body() ?: emptyList()
                }

                // Fetch todos
                val todosCall = api.getTodos()
                if (todosCall.isSuccessful) {
                    assignedTodos = todosCall.body() ?: emptyList()
                }

                // Fetch tickets
                val ticketsCall = api.getTickets()
                if (ticketsCall.isSuccessful) {
                    supportTickets = ticketsCall.body() ?: emptyList()
                }

                // Fetch notifications
                val notificationsCall = api.getNotifications()
                if (notificationsCall.isSuccessful) {
                    notifications = notificationsCall.body() ?: emptyList()
                }

                isLoading = false
            } catch (e: Exception) {
                isLoading = false
                _eventFlow.emit(UiEvent.ShowToast("Sync error: ${e.localizedMessage}"))
            }
        }
    }

    // --- EMPLOYEE TRANSACTION APIs ---
    fun updateTodoStatus(todoId: String, status: String) {
        isLoading = true
        viewModelScope.launch {
            try {
                val response = api.updateTodoStatus(todoId, mapOf("status" to status))
                if (response.isSuccessful) {
                    _eventFlow.emit(UiEvent.ShowToast("Todo status updated!"))
                    syncDashboardData()
                } else {
                    _eventFlow.emit(UiEvent.ShowToast("Failed: ${response.message()}"))
                }
                isLoading = false
            } catch (e: Exception) {
                isLoading = false
                _eventFlow.emit(UiEvent.ShowToast("Error: ${e.localizedMessage}"))
            }
        }
    }

    fun updateOrderStatus(orderId: String, status: String) {
        isLoading = true
        viewModelScope.launch {
            try {
                val response = api.updateOrderStatus(orderId, mapOf("status" to status))
                if (response.isSuccessful) {
                    _eventFlow.emit(UiEvent.ShowToast("Order status updated!"))
                    syncDashboardData()
                } else {
                    _eventFlow.emit(UiEvent.ShowToast("Failed: ${response.message()}"))
                }
                isLoading = false
            } catch (e: Exception) {
                isLoading = false
                _eventFlow.emit(UiEvent.ShowToast("Error: ${e.localizedMessage}"))
            }
        }
    }

    fun updateTaskStatus(orderId: String, taskId: String, status: String) {
        isLoading = true
        viewModelScope.launch {
            try {
                val response = api.updateTaskStatus(orderId, taskId, mapOf("status" to status))
                if (response.isSuccessful) {
                    _eventFlow.emit(UiEvent.ShowToast("Task status updated!"))
                    syncDashboardData()
                } else {
                    _eventFlow.emit(UiEvent.ShowToast("Failed: ${response.message()}"))
                }
                isLoading = false
            } catch (e: Exception) {
                isLoading = false
                _eventFlow.emit(UiEvent.ShowToast("Error: ${e.localizedMessage}"))
            }
        }
    }

    fun updateSubtaskStatus(orderId: String, taskId: String, subtaskId: String, isCompleted: Boolean, status: String) {
        isLoading = true
        viewModelScope.launch {
            try {
                val response = api.updateSubtask(
                    orderId, taskId, subtaskId,
                    mapOf("isCompleted" to isCompleted, "status" to status)
                )
                if (response.isSuccessful) {
                    _eventFlow.emit(UiEvent.ShowToast("Subtask updated!"))
                    syncDashboardData()
                } else {
                    _eventFlow.emit(UiEvent.ShowToast("Failed: ${response.message()}"))
                }
                isLoading = false
            } catch (e: Exception) {
                isLoading = false
                _eventFlow.emit(UiEvent.ShowToast("Error: ${e.localizedMessage}"))
            }
        }
    }

    fun logTaskTime(orderId: String, taskId: String, minutes: Int, notes: String) {
        isLoading = true
        viewModelScope.launch {
            try {
                val response = api.logTaskTime(orderId, taskId, mapOf("minutes" to minutes, "notes" to notes))
                if (response.isSuccessful) {
                    _eventFlow.emit(UiEvent.ShowToast("Logged $minutes minutes successfully!"))
                    syncDashboardData()
                } else {
                    _eventFlow.emit(UiEvent.ShowToast("Failed to log time: ${response.message()}"))
                }
                isLoading = false
            } catch (e: Exception) {
                isLoading = false
                _eventFlow.emit(UiEvent.ShowToast("Error: ${e.localizedMessage}"))
            }
        }
    }

    fun updateRequirementStatus(orderId: String, requirementId: String, status: String) {
        isLoading = true
        viewModelScope.launch {
            try {
                val response = api.updateRequirementStatus(orderId, requirementId, mapOf("status" to status))
                if (response.isSuccessful) {
                    _eventFlow.emit(UiEvent.ShowToast("Requirement status updated!"))
                    syncDashboardData()
                } else {
                    _eventFlow.emit(UiEvent.ShowToast("Failed: ${response.message()}"))
                }
                isLoading = false
            } catch (e: Exception) {
                isLoading = false
                _eventFlow.emit(UiEvent.ShowToast("Error: ${e.localizedMessage}"))
            }
        }
    }

    fun raiseRequirement(orderId: String, title: String, type: String) {
        isLoading = true
        viewModelScope.launch {
            try {
                val response = api.raiseRequirement(
                    orderId,
                    mapOf("title" to title, "type" to type, "description" to "")
                )
                if (response.isSuccessful) {
                    _eventFlow.emit(UiEvent.ShowToast("New query raised!"))
                    syncDashboardData()
                } else {
                    _eventFlow.emit(UiEvent.ShowToast("Failed: ${response.message()}"))
                }
                isLoading = false
            } catch (e: Exception) {
                isLoading = false
                _eventFlow.emit(UiEvent.ShowToast("Error: ${e.localizedMessage}"))
            }
        }
    }

    fun uploadFinalCertificate(orderId: String, fileUri: android.net.Uri, context: android.content.Context) {
        isLoading = true
        viewModelScope.launch {
            try {
                val contentResolver = context.contentResolver
                // Get filename from Uri
                var fileName = "certificate.pdf"
                contentResolver.query(fileUri, null, null, null, null)?.use { cursor ->
                    val nameIndex = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                    if (nameIndex != -1 && cursor.moveToFirst()) {
                        fileName = cursor.getString(nameIndex)
                    }
                }

                // Create temp file
                val tempFile = java.io.File(context.cacheDir, fileName)
                contentResolver.openInputStream(fileUri)?.use { inputStream ->
                    tempFile.outputStream().use { outputStream ->
                        inputStream.copyTo(outputStream)
                    }
                }

                val mediaType = (contentResolver.getType(fileUri) ?: "application/pdf").toMediaTypeOrNull()
                val requestFile = tempFile.asRequestBody(mediaType)
                val body = okhttp3.MultipartBody.Part.createFormData("document", tempFile.name, requestFile)

                val response = api.uploadFinalCertificate(orderId, body)
                if (response.isSuccessful) {
                    _eventFlow.emit(UiEvent.ShowToast("Final certificate uploaded successfully!"))
                    syncDashboardData()
                } else {
                    _eventFlow.emit(UiEvent.ShowToast("Upload failed: ${response.message()}"))
                }
                isLoading = false
            } catch (e: java.lang.Exception) {
                isLoading = false
                _eventFlow.emit(UiEvent.ShowToast("Upload error: ${e.localizedMessage}"))
            }
        }
    }

    fun markNotificationAsRead(notificationId: String) {
        // 1. Update Firestore
        com.sbr.vrherebms.utils.FirestoreNotificationHelper.markAsRead(getApplication(), notificationId)

        // 2. Sync MongoDB
        viewModelScope.launch {
            try {
                api.markNotificationAsRead(notificationId)
            } catch (e: Exception) {
                // ignore
            }
        }
    }

    fun toggleClockStatus() {
        isLoading = true
        viewModelScope.launch {
            try {
                if (isClockedIn) {
                    // Clock out
                    val response = api.clockOut()
                    if (response.isSuccessful) {
                        isClockedIn = false
                        currentAttendanceRecord = null
                        _eventFlow.emit(UiEvent.ShowToast("Successfully Clocked Out!"))
                        syncDashboardData()
                    } else {
                        _eventFlow.emit(UiEvent.ShowToast("Clock out failed: ${response.message()}"))
                    }
                } else {
                    // Clock in
                    val response = api.clockIn(ClockInRequest(notes = clockInNote))
                    if (response.isSuccessful && response.body() != null) {
                        isClockedIn = true
                        currentAttendanceRecord = response.body()
                        clockInNote = ""
                        _eventFlow.emit(UiEvent.ShowToast("Successfully Clocked In!"))
                        syncDashboardData()
                    } else {
                        _eventFlow.emit(UiEvent.ShowToast("Clock in failed: ${response.message()}"))
                    }
                }
                isLoading = false
            } catch (e: Exception) {
                isLoading = false
                _eventFlow.emit(UiEvent.ShowToast("Network error: ${e.localizedMessage}"))
            }
        }
    }
}
