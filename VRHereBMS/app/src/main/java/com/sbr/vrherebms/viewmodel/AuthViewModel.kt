package com.sbr.vrherebms.viewmodel

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.sbr.vrherebms.data.local.SessionManager
import com.sbr.vrherebms.data.model.LoginRequest
import com.sbr.vrherebms.data.model.RegisterPartnerRequest
import com.sbr.vrherebms.data.model.RegisterRequest
import com.sbr.vrherebms.data.remote.VRHereAPI
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch

sealed class AuthState {
    object Idle : AuthState()
    object Loading : AuthState()
    data class Success(val role: String) : AuthState()
    data class Error(val message: String) : AuthState()
}

class AuthViewModel(application: Application) : AndroidViewModel(application) {
    private val sessionManager = SessionManager(application)
    private val api = VRHereAPI.getInstance(application)

    var authState by mutableStateOf<AuthState>(AuthState.Idle)
        private set

    var nameInput by mutableStateOf("")
    var emailInput by mutableStateOf("")
    var phoneInput by mutableStateOf("")
    var passwordInput by mutableStateOf("")
    var panCardInput by mutableStateOf("")
    var roleInput by mutableStateOf("client") // default to client

    private val _eventFlow = MutableSharedFlow<UiEvent>()
    val eventFlow = _eventFlow.asSharedFlow()

    sealed class UiEvent {
        data class ShowToast(val message: String) : UiEvent()
    }

    init {
        // Auto login if already logged in
        if (sessionManager.isLoggedIn()) {
            val role = sessionManager.getUserRole() ?: "client"
            authState = AuthState.Success(role)
        }
    }

    fun login() {
        if (emailInput.isEmpty() || passwordInput.isEmpty()) {
            viewModelScope.launch {
                _eventFlow.emit(UiEvent.ShowToast("Please enter email and password"))
            }
            return
        }

        authState = AuthState.Loading
        viewModelScope.launch {
            try {
                val response = api.login(LoginRequest(emailInput, passwordInput))
                if (response.isSuccessful && response.body() != null) {
                    val authData = response.body()!!
                    sessionManager.saveSession(
                        token = authData.token,
                        userId = authData.id,
                        name = authData.name,
                        email = authData.email,
                        role = authData.role,
                        isActive = authData.isActive
                    )
                    sessionManager.savePhone(authData.phone ?: "")
                    authState = AuthState.Success(authData.role)
                    _eventFlow.emit(UiEvent.ShowToast("Welcome back, ${authData.name}!"))
                } else {
                    val errorMsg = response.errorBody()?.string() ?: "Login failed"
                    authState = AuthState.Error(errorMsg)
                    _eventFlow.emit(UiEvent.ShowToast(errorMsg))
                }
            } catch (e: Exception) {
                val errorMsg = e.localizedMessage ?: "Connection error"
                authState = AuthState.Error(errorMsg)
                _eventFlow.emit(UiEvent.ShowToast(errorMsg))
            }
        }
    }

    fun register() {
        if (nameInput.isEmpty() || emailInput.isEmpty() || phoneInput.isEmpty() || passwordInput.isEmpty()) {
            viewModelScope.launch {
                _eventFlow.emit(UiEvent.ShowToast("Please fill in all details"))
            }
            return
        }

        authState = AuthState.Loading
        viewModelScope.launch {
            try {
                val response = if (roleInput == "partner") {
                    if (panCardInput.isEmpty()) {
                        authState = AuthState.Idle
                        _eventFlow.emit(UiEvent.ShowToast("PAN card is strictly required for partners"))
                        return@launch
                    }
                    api.registerPartner(
                        RegisterPartnerRequest(
                            name = nameInput,
                            email = emailInput,
                            phone = phoneInput,
                            password = passwordInput,
                            panCard = panCardInput
                        )
                    )
                } else {
                    api.register(
                        RegisterRequest(
                            name = nameInput,
                            email = emailInput,
                            phone = phoneInput,
                            password = passwordInput,
                            role = roleInput
                        )
                    )
                }

                if (response.isSuccessful && response.body() != null) {
                    val authData = response.body()!!
                    sessionManager.saveSession(
                        token = authData.token,
                        userId = authData.id,
                        name = authData.name,
                        email = authData.email,
                        role = authData.role,
                        isActive = authData.isActive
                    )
                    sessionManager.savePhone(authData.phone ?: "")
                    
                    if (authData.isActive) {
                        authState = AuthState.Success(authData.role)
                        _eventFlow.emit(UiEvent.ShowToast("Registration successful!"))
                    } else {
                        authState = AuthState.Idle
                        _eventFlow.emit(UiEvent.ShowToast("Partner registered successfully! Account is pending admin validation."))
                    }
                } else {
                    val errorMsg = response.errorBody()?.string() ?: "Registration failed"
                    authState = AuthState.Error(errorMsg)
                    _eventFlow.emit(UiEvent.ShowToast(errorMsg))
                }
            } catch (e: Exception) {
                val errorMsg = e.localizedMessage ?: "Connection error"
                authState = AuthState.Error(errorMsg)
                _eventFlow.emit(UiEvent.ShowToast(errorMsg))
            }
        }
    }

    fun logout() {
        sessionManager.clearSession()
        
        // Stop persistent notification polling service on logout
        try {
            val serviceIntent = android.content.Intent(getApplication(), com.sbr.vrherebms.services.NotificationPollingService::class.java)
            getApplication<Application>().stopService(serviceIntent)
            android.util.Log.d("AuthViewModel", "Successfully stopped notification polling service on logout")
        } catch (e: Exception) {
            e.printStackTrace()
        }

        authState = AuthState.Idle
        emailInput = ""
        passwordInput = ""
        nameInput = ""
        phoneInput = ""
        panCardInput = ""
    }

    fun isUserLoggedIn(): Boolean {
        return sessionManager.isLoggedIn()
    }

    fun getUserRole(): String {
        return sessionManager.getUserRole() ?: "client"
    }

    fun getUserName(): String {
        return sessionManager.getUserName() ?: ""
    }
}
