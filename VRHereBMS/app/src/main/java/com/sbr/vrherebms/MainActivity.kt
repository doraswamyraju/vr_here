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

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
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
                
                // Determine starting destination based on session status
                val startDestination = if (authViewModel.isUserLoggedIn()) {
                    when (authViewModel.getUserRole()) {
                        "admin" -> "admin_dashboard"
                        "employee" -> "employee_dashboard"
                        "partner" -> "partner_dashboard"
                        else -> "customer_dashboard"
                    }
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
                                val destination = when (role) {
                                    "admin" -> "admin_dashboard"
                                    "employee" -> "employee_dashboard"
                                    "partner" -> "partner_dashboard"
                                    else -> "customer_dashboard"
                                }
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
                                val destination = when (role) {
                                    "admin" -> "admin_dashboard"
                                    "employee" -> "employee_dashboard"
                                    "partner" -> "partner_dashboard"
                                    else -> "customer_dashboard"
                                }
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
}