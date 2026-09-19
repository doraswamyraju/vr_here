package com.sbr.vrherebms

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.compose.ui.Modifier
import com.sbr.vrherebms.ui.screens.*
import com.sbr.vrherebms.ui.screens.admin.AdminDashboardScreen
import com.sbr.vrherebms.ui.screens.employee.EmployeeDashboardScreen
import com.sbr.vrherebms.ui.screens.partner.PartnerDashboardScreen
import com.sbr.vrherebms.ui.theme.VRHereBMSTheme
import com.sbr.vrherebms.viewmodel.AuthViewModel
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel
import com.sbr.vrherebms.viewmodel.EmployeeDashboardViewModel
import com.sbr.vrherebms.viewmodel.PartnerDashboardViewModel
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel

class MainActivity : ComponentActivity(), com.razorpay.PaymentResultWithDataListener {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Initialize native Razorpay Mobile Checkout SDK
        com.sbr.vrherebms.utils.RazorpayManager.initialize(applicationContext)

        // Request notification permission at runtime for Android 13+
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            val requestPermissionLauncher = registerForActivityResult(
                androidx.activity.result.contract.ActivityResultContracts.RequestPermission()
            ) { _ -> }
            
            if (androidx.core.content.ContextCompat.checkSelfPermission(
                    this,
                    android.Manifest.permission.POST_NOTIFICATIONS
                ) != android.content.pm.PackageManager.PERMISSION_GRANTED
            ) {
                requestPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        // Initialize Notification Channel (safely registers channel for system alerts)
        com.sbr.vrherebms.utils.NotificationHelper.createNotificationChannel(applicationContext)

        // Retrieve and sync FCM token on launch
        try {
            com.google.firebase.messaging.FirebaseMessaging.getInstance().token.addOnCompleteListener { task ->
                if (task.isSuccessful && task.result != null) {
                    val token = task.result
                    android.util.Log.d("MainActivity", "FCM token fetched successfully on launch: $token")
                    com.sbr.vrherebms.utils.FcmTokenHelper.uploadFcmToken(applicationContext, token)
                } else {
                    android.util.Log.e("MainActivity", "FCM token fetch failed on launch", task.exception)
                }
            }
        } catch (e: Exception) {
            android.util.Log.e("MainActivity", "Failed to initialize Firebase Messaging on launch", e)
        }

        enableEdgeToEdge()
        setContent {
            VRHereBMSTheme {
                val navController = rememberNavController()
                val authViewModel: AuthViewModel = viewModel()
                
                // Helper to robustly resolve screen destination based on normalized role
                fun resolveRoleDestination(role: String?): String {
                    val normalized = role?.trim()?.lowercase() ?: "client"
                    return when {
                        normalized == "admin" || normalized.contains("admin") -> "admin_dashboard"
                        normalized in listOf("employee", "staff", "freelancer", "specialist") ||
                            normalized.contains("employee") ||
                            normalized.contains("staff") ||
                            normalized.contains("freelancer") -> "employee_dashboard"
                        normalized == "partner" || normalized.contains("partner") -> "partner_dashboard"
                        else -> "customer_dashboard"
                    }
                }

                // Determine starting destination based on session status
                val startDestination = if (authViewModel.isUserLoggedIn()) {
                    resolveRoleDestination(authViewModel.getUserRole())
                } else {
                    "login"
                }

                NavHost(
                    navController = navController,
                    startDestination = startDestination,
                    modifier = Modifier.fillMaxSize()
                ) {
                    composable("login") {
                        LoginScreen(
                            viewModel = authViewModel,
                            onNavigateToRegister = { navController.navigate("register") },
                            onLoginSuccess = { role ->
                                // Sync FCM token on login success
                                com.sbr.vrherebms.utils.FcmTokenHelper.uploadFcmToken(applicationContext)
                                val destination = resolveRoleDestination(role)
                                navController.navigate(destination) {
                                    popUpTo("login") { inclusive = true }
                                }
                            }
                        )
                    }

                    composable("register") {
                        RegisterScreen(
                            viewModel = authViewModel,
                            onNavigateToLogin = { navController.navigate("login") },
                            onRegistrationSuccess = {
                                // Sync FCM token on registration success
                                com.sbr.vrherebms.utils.FcmTokenHelper.uploadFcmToken(applicationContext)
                                val role = authViewModel.getUserRole()
                                val destination = resolveRoleDestination(role)
                                navController.navigate(destination) {
                                    popUpTo("register") { inclusive = true }
                                }
                            }
                        )
                    }

                    composable("customer_dashboard") {
                        val customerViewModel: CustomerDashboardViewModel = viewModel()
                        CustomerDashboardScreen(
                            viewModel = customerViewModel,
                            userName = authViewModel.getUserName(),
                            onLogout = {
                                authViewModel.logout()
                                navController.navigate("login") {
                                    popUpTo("customer_dashboard") { inclusive = true }
                                }
                            }
                        )
                    }

                    composable("employee_dashboard") {
                        val employeeViewModel: EmployeeDashboardViewModel = viewModel()
                        EmployeeDashboardScreen(
                            viewModel = employeeViewModel,
                            userName = authViewModel.getUserName(),
                            onLogout = {
                                authViewModel.logout()
                                navController.navigate("login") {
                                    popUpTo("employee_dashboard") { inclusive = true }
                                }
                            }
                        )
                    }

                    composable("partner_dashboard") {
                        val partnerViewModel: PartnerDashboardViewModel = viewModel()
                        PartnerDashboardScreen(
                            viewModel = partnerViewModel,
                            userName = authViewModel.getUserName(),
                            onLogout = {
                                authViewModel.logout()
                                navController.navigate("login") {
                                    popUpTo("partner_dashboard") { inclusive = true }
                                }
                            }
                        )
                    }

                    composable("admin_dashboard") {
                        val adminViewModel: AdminDashboardViewModel = viewModel()
                        AdminDashboardScreen(
                            authViewModel = authViewModel,
                            adminViewModel = adminViewModel,
                            userName = authViewModel.getUserName(),
                            onLogout = {
                                authViewModel.logout()
                                navController.navigate("login") {
                                    popUpTo("admin_dashboard") { inclusive = true }
                                }
                            }
                        )
                    }
                }
            }
        }
    }

    override fun onPaymentSuccess(razorpayPaymentId: String?, paymentData: com.razorpay.PaymentData?) {
        com.sbr.vrherebms.utils.RazorpayManager.onPaymentSuccess(razorpayPaymentId, paymentData)
    }

    override fun onPaymentError(errorCode: Int, response: String?, paymentData: com.razorpay.PaymentData?) {
        com.sbr.vrherebms.utils.RazorpayManager.onPaymentError(errorCode, response, paymentData)
    }
}