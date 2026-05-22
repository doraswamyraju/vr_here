package com.sbr.vrherebms.viewmodel

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.sbr.vrherebms.data.model.AttendanceResponse
import com.sbr.vrherebms.data.model.ClockInRequest
import com.sbr.vrherebms.data.model.OrderResponse
import com.sbr.vrherebms.data.remote.VRHereAPI
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch

class EmployeeDashboardViewModel(application: Application) : AndroidViewModel(application) {
    private val api = VRHereAPI.getInstance(application)

    var attendanceLogs by mutableStateOf<List<AttendanceResponse>>(emptyList())
    var assignedOrders by mutableStateOf<List<OrderResponse>>(emptyList())

    var isClockedIn by mutableStateOf(false)
    var currentAttendanceRecord by mutableStateOf<AttendanceResponse?>(null)
    var clockInNote by mutableStateOf("")

    var isLoading by mutableStateOf(false)

    private val _eventFlow = MutableSharedFlow<UiEvent>()
    val eventFlow = _eventFlow.asSharedFlow()

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

                isLoading = false
            } catch (e: Exception) {
                isLoading = false
                _eventFlow.emit(UiEvent.ShowToast("Sync error: ${e.localizedMessage}"))
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
