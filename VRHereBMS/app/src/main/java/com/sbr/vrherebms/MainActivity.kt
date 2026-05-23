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
import com.sbr.vrherebms.ui.theme.VRHereBMSTheme
import com.sbr.vrherebms.viewmodel.AuthViewModel
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel
import com.sbr.vrherebms.viewmodel.EmployeeDashboardViewModel
import com.sbr.vrherebms.viewmodel.PartnerDashboardViewModel

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

        // Start Foreground Notification Sync Service if user is logged in on startup
        if (com.sbr.vrherebms.data.local.SessionManager(applicationContext).isLoggedIn()) {
            try {
                val serviceIntent = android.content.Intent(this, com.sbr.vrherebms.services.NotificationPollingService::class.java)
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                    startForegroundService(serviceIntent)
                } else {
                    startService(serviceIntent)
                }
                android.util.Log.d("MainActivity", "Successfully started persistent notification sync service on launch")
            } catch (e: Exception) {
                android.util.Log.e("MainActivity", "Failed to start notification sync service on launch", e)
            }
        }

        // Schedule periodic background notification sync worker as an additional robust fallback
        try {
            val syncRequest = androidx.work.PeriodicWorkRequestBuilder<com.sbr.vrherebms.utils.NotificationSyncWorker>(
                15, java.util.concurrent.TimeUnit.MINUTES
            ).setConstraints(
                androidx.work.Constraints.Builder()
                    .setRequiredNetworkType(androidx.work.NetworkType.CONNECTED)
                    .build()
            ).build()

            androidx.work.WorkManager.getInstance(applicationContext).enqueueUniquePeriodicWork(
                "NotificationSyncWork",
                androidx.work.ExistingPeriodicWorkPolicy.KEEP,
                syncRequest
            )
            android.util.Log.d("MainActivity", "Successfully enqueued unique periodic notification sync worker")
        } catch (e: Exception) {
            android.util.Log.e("MainActivity", "Failed to initialize background worker", e)
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
                                try {
                                    val serviceIntent = android.content.Intent(this@MainActivity, com.sbr.vrherebms.services.NotificationPollingService::class.java)
                                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                                        startForegroundService(serviceIntent)
                                    } else {
                                        startService(serviceIntent)
                                    }
                                    android.util.Log.d("MainActivity", "Started notification sync service on login")
                                } catch (e: Exception) {
                                    android.util.Log.e("MainActivity", "Failed to start notification sync service on login", e)
                                }
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
                                try {
                                    val serviceIntent = android.content.Intent(this@MainActivity, com.sbr.vrherebms.services.NotificationPollingService::class.java)
                                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                                        startForegroundService(serviceIntent)
                                    } else {
                                        startService(serviceIntent)
                                    }
                                    android.util.Log.d("MainActivity", "Started notification sync service on registration")
                                } catch (e: Exception) {
                                    android.util.Log.e("MainActivity", "Failed to start notification sync service on registration", e)
                                }
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
                        AdminDashboardScreen(
                            authViewModel = authViewModel,
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