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

sealed class PartnerDashboardState {
    object Idle : PartnerDashboardState()
    object Loading : PartnerDashboardState()
    object Success : PartnerDashboardState()
    data class Error(val message: String) : PartnerDashboardState()
}

class PartnerDashboardViewModel(application: Application) : AndroidViewModel(application) {
    private val api = VRHereAPI.getInstance(application)

    var dashboardState by mutableStateOf<PartnerDashboardState>(PartnerDashboardState.Idle)
        private set

    var orders by mutableStateOf<List<PartnerOrderResponse>>(emptyList())
    var profile by mutableStateOf<PartnerProfileResponse?>(null)

    // Form inputs for Settings
    var nameInput by mutableStateOf("")
    var panCardInput by mutableStateOf("")
    
    var bankAccountNameInput by mutableStateOf("")
    var bankAccountNumberInput by mutableStateOf("")
    var bankIfscCodeInput by mutableStateOf("")
    var bankNameInput by mutableStateOf("")

    var isSavingProfile by mutableStateOf(false)

    private val _eventFlow = MutableSharedFlow<UiEvent>()
    val eventFlow = _eventFlow.asSharedFlow()

    sealed class UiEvent {
        data class ShowToast(val message: String) : UiEvent()
        object ProfileUpdated : UiEvent()
    }

    fun refreshAllData() {
        dashboardState = PartnerDashboardState.Loading
        viewModelScope.launch {
            try {
                val ordersCall = api.getPartnerOrders()
                val profileCall = api.getPartnerProfile()

                if (profileCall.isSuccessful && profileCall.body() != null) {
                    val p = profileCall.body()!!
                    profile = p
                    nameInput = p.name
                    panCardInput = p.panCard ?: ""
                    
                    p.bankDetails?.let {
                        bankAccountNameInput = it.accountName
                        bankAccountNumberInput = it.accountNumber
                        bankIfscCodeInput = it.ifscCode
                        bankNameInput = it.bankName
                    }
                }

                if (ordersCall.isSuccessful) {
                    orders = ordersCall.body() ?: emptyList()
                }

                dashboardState = PartnerDashboardState.Success
            } catch (e: Exception) {
                dashboardState = PartnerDashboardState.Error(e.localizedMessage ?: "Failed to sync partner data")
                _eventFlow.emit(UiEvent.ShowToast("Sync error: ${e.localizedMessage}"))
            }
        }
    }

    fun updateProfile() {
        if (nameInput.isEmpty()) {
            viewModelScope.launch {
                _eventFlow.emit(UiEvent.ShowToast("Name cannot be empty"))
            }
            return
        }

        if (panCardInput.isEmpty()) {
            viewModelScope.launch {
                _eventFlow.emit(UiEvent.ShowToast("PAN Card cannot be empty"))
            }
            return
        }

        isSavingProfile = true
        viewModelScope.launch {
            try {
                val bank = BankDetails(
                    accountName = bankAccountNameInput,
                    accountNumber = bankAccountNumberInput,
                    ifscCode = bankIfscCodeInput,
                    bankName = bankNameInput
                )
                val response = api.updatePartnerProfile(
                    PartnerProfileUpdateDto(
                        name = nameInput,
                        panCard = panCardInput,
                        bankDetails = bank
                    )
                )

                if (response.isSuccessful && response.body() != null) {
                    profile = response.body()!!
                    _eventFlow.emit(UiEvent.ShowToast("Profile updated successfully!"))
                    _eventFlow.emit(UiEvent.ProfileUpdated)
                } else {
                    val err = response.errorBody()?.string() ?: "Failed to update profile"
                    _eventFlow.emit(UiEvent.ShowToast(err))
                }
            } catch (e: Exception) {
                _eventFlow.emit(UiEvent.ShowToast("Connection error: ${e.localizedMessage}"))
            } finally {
                isSavingProfile = false
            }
        }
    }
}
