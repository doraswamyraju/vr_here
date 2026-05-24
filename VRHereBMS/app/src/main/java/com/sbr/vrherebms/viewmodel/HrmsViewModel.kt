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

class HrmsViewModel(application: Application) : AndroidViewModel(application) {
    private val api = VRHereAPI.getInstance(application)

    // Observables
    var isLoading by mutableStateOf(false)
        private set

    var errorMessage by mutableStateOf<String?>(null)
        private set

    var leaves by mutableStateOf<List<LeaveResponse>>(emptyList())
        private set

    var adminLeaves by mutableStateOf<List<LeaveResponse>>(emptyList())
        private set

    var holidays by mutableStateOf<List<HolidayResponse>>(emptyList())
        private set

    var notices by mutableStateOf<List<NoticeResponse>>(emptyList())
        private set

    var liveStatus by mutableStateOf<LiveStatusResponse?>(null)
        private set

    private val _uiEvent = MutableSharedFlow<UiEvent>()
    val uiEvent = _uiEvent.asSharedFlow()

    sealed class UiEvent {
        data class ShowToast(val message: String) : UiEvent()
        object LeaveSubmitted : UiEvent()
        object LeaveProcessed : UiEvent()
        object BulletinCreated : UiEvent()
    }

    fun clearError() {
        errorMessage = null
    }

    // ==========================================
    // EMPLOYEE OPERATIONS
    // ==========================================

    fun fetchMyLeaves() {
        isLoading = true
        errorMessage = null
        viewModelScope.launch {
            try {
                val response = api.getMyLeaves()
                if (response.isSuccessful) {
                    leaves = response.body() ?: emptyList()
                } else {
                    errorMessage = "Failed to load leave history: ${response.message()}"
                }
            } catch (e: Exception) {
                errorMessage = "Network error: ${e.localizedMessage}"
            } finally {
                isLoading = false
            }
        }
    }

    fun applyLeave(startDate: String, endDate: String, type: String, reason: String) {
        isLoading = true
        errorMessage = null
        viewModelScope.launch {
            try {
                val request = LeaveRequest(startDate, endDate, type, reason)
                val response = api.applyLeave(request)
                if (response.isSuccessful) {
                    _uiEvent.emit(UiEvent.ShowToast("Leave request submitted! Admins alerted."))
                    _uiEvent.emit(UiEvent.LeaveSubmitted)
                    fetchMyLeaves()
                } else {
                    _uiEvent.emit(UiEvent.ShowToast("Apply leave failed: ${response.message()}"))
                }
            } catch (e: Exception) {
                _uiEvent.emit(UiEvent.ShowToast("Connection error: ${e.localizedMessage}"))
            } finally {
                isLoading = false
            }
        }
    }

    // ==========================================
    // ADMIN OPERATIONS
    // ==========================================

    fun fetchAdminLeaves() {
        isLoading = true
        errorMessage = null
        viewModelScope.launch {
            try {
                val response = api.getAdminLeaves()
                if (response.isSuccessful) {
                    adminLeaves = response.body() ?: emptyList()
                } else {
                    errorMessage = "Failed to load admin leaves: ${response.message()}"
                }
            } catch (e: Exception) {
                errorMessage = "Network error: ${e.localizedMessage}"
            } finally {
                isLoading = false
            }
        }
    }

    fun approveLeave(leaveId: String, status: String, adminNotes: String) {
        isLoading = true
        viewModelScope.launch {
            try {
                val request = ApproveLeaveRequest(status, adminNotes)
                val response = api.approveLeave(leaveId, request)
                if (response.isSuccessful) {
                    _uiEvent.emit(UiEvent.ShowToast("Leave request updated successfully!"))
                    _uiEvent.emit(UiEvent.LeaveProcessed)
                    fetchAdminLeaves()
                } else {
                    _uiEvent.emit(UiEvent.ShowToast("Failed to process: ${response.message()}"))
                }
            } catch (e: Exception) {
                _uiEvent.emit(UiEvent.ShowToast("Error: ${e.localizedMessage}"))
            } finally {
                isLoading = false
            }
        }
    }

    fun fetchLiveStatus() {
        isLoading = true
        errorMessage = null
        viewModelScope.launch {
            try {
                val response = api.getLiveStatus()
                if (response.isSuccessful) {
                    liveStatus = response.body()
                } else {
                    errorMessage = "Failed to load live tracking: ${response.message()}"
                }
            } catch (e: Exception) {
                errorMessage = "Network error: ${e.localizedMessage}"
            } finally {
                isLoading = false
            }
        }
    }

    // ==========================================
    // ANNOUNCEMENTS & HOLIDAYS
    // ==========================================

    fun fetchBulletins() {
        isLoading = true
        errorMessage = null
        viewModelScope.launch {
            try {
                val hRes = api.getHolidays()
                val nRes = api.getNotices()
                
                if (hRes.isSuccessful && nRes.isSuccessful) {
                    holidays = hRes.body() ?: emptyList()
                    notices = nRes.body() ?: emptyList()
                } else {
                    errorMessage = "Failed to load announcement feeds"
                }
            } catch (e: Exception) {
                errorMessage = "Network error: ${e.localizedMessage}"
            } finally {
                isLoading = false
            }
        }
    }

    fun createHoliday(title: String, date: String, description: String) {
        isLoading = true
        viewModelScope.launch {
            try {
                val request = HolidayRequest(title, date, description)
                val response = api.createHoliday(request)
                if (response.isSuccessful) {
                    _uiEvent.emit(UiEvent.ShowToast("Company holiday declared!"))
                    _uiEvent.emit(UiEvent.BulletinCreated)
                    fetchBulletins()
                } else {
                    _uiEvent.emit(UiEvent.ShowToast("Failed to create holiday: ${response.message()}"))
                }
            } catch (e: Exception) {
                _uiEvent.emit(UiEvent.ShowToast("Error: ${e.localizedMessage}"))
            } finally {
                isLoading = false
            }
        }
    }

    fun deleteHoliday(id: String) {
        isLoading = true
        viewModelScope.launch {
            try {
                val response = api.deleteHoliday(id)
                if (response.isSuccessful) {
                    _uiEvent.emit(UiEvent.ShowToast("Holiday removed successfully"))
                    fetchBulletins()
                } else {
                    _uiEvent.emit(UiEvent.ShowToast("Delete holiday failed"))
                }
            } catch (e: Exception) {
                _uiEvent.emit(UiEvent.ShowToast("Network error"))
            } finally {
                isLoading = false
            }
        }
    }

    fun createNotice(title: String, message: String, priority: String) {
        isLoading = true
        viewModelScope.launch {
            try {
                val request = NoticeRequest(title, message, priority)
                val response = api.createNotice(request)
                if (response.isSuccessful) {
                    _uiEvent.emit(UiEvent.ShowToast("Notice published! Staff notified."))
                    _uiEvent.emit(UiEvent.BulletinCreated)
                    fetchBulletins()
                } else {
                    _uiEvent.emit(UiEvent.ShowToast("Failed to publish: ${response.message()}"))
                }
            } catch (e: Exception) {
                _uiEvent.emit(UiEvent.ShowToast("Error: ${e.localizedMessage}"))
            } finally {
                isLoading = false
            }
        }
    }

    fun deleteNotice(id: String) {
        isLoading = true
        viewModelScope.launch {
            try {
                val response = api.deleteNotice(id)
                if (response.isSuccessful) {
                    _uiEvent.emit(UiEvent.ShowToast("Notice deleted successfully"))
                    fetchBulletins()
                } else {
                    _uiEvent.emit(UiEvent.ShowToast("Delete notice failed"))
                }
            } catch (e: Exception) {
                _uiEvent.emit(UiEvent.ShowToast("Network error"))
            } finally {
                isLoading = false
            }
        }
    }
}
