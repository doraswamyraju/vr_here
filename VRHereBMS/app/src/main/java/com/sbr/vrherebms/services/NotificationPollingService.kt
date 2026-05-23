package com.sbr.vrherebms.services

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.sbr.vrherebms.MainActivity
import com.sbr.vrherebms.data.local.SessionManager
import com.sbr.vrherebms.data.remote.VRHereAPI
import com.sbr.vrherebms.utils.NotificationHelper
import kotlinx.coroutines.*

class NotificationPollingService : Service() {

    private val serviceJob = SupervisorJob()
    private val serviceScope = CoroutineScope(Dispatchers.IO + serviceJob)
    private var pollingJob: Job? = null

    companion object {
        private const val SERVICE_NOTIFICATION_ID = 9999
        private const val CHANNEL_ID = "vr_here_polling_channel"
        private const val CHANNEL_NAME = "VR HERE Background Service"
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d("NotificationPollingService", "Background Polling Service started command")
        
        // Start as foreground service immediately to satisfy Android OS rules
        val notification = createForegroundNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                SERVICE_NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else {
            startForeground(SERVICE_NOTIFICATION_ID, notification)
        }

        // Start 15-second background polling loop
        startPolling()

        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startPolling() {
        pollingJob?.cancel()
        pollingJob = serviceScope.launch {
            val sessionManager = SessionManager(applicationContext)
            while (isActive) {
                if (sessionManager.isLoggedIn()) {
                    try {
                        val api = VRHereAPI.getInstance(applicationContext)
                        val response = api.getNotifications()
                        if (response.isSuccessful && response.body() != null) {
                            val notificationsList = response.body()!!
                            val unreadNotifications = notificationsList.filter { !it.isRead }

                            if (unreadNotifications.isNotEmpty()) {
                                val prefs = applicationContext.getSharedPreferences("notification_worker_prefs", Context.MODE_PRIVATE)
                                val notifiedIds = prefs.getStringSet("notified_ids", emptySet()) ?: emptySet()
                                val newUnnotified = unreadNotifications.filter { !notifiedIds.contains(it.id) }

                                if (newUnnotified.isNotEmpty()) {
                                    Log.d("NotificationPollingService", "Found ${newUnnotified.size} new unread notifications in background")
                                    
                                    newUnnotified.forEach { notif ->
                                        NotificationHelper.showNotification(
                                            applicationContext,
                                            notif.id.hashCode(),
                                            notif.title,
                                            notif.message,
                                            notif.type
                                        )
                                    }

                                    // Persist notified IDs to prevent repeating sound/vibration for the same notifications
                                    val updatedIds = notifiedIds.toMutableSet().apply {
                                        addAll(newUnnotified.map { it.id })
                                    }
                                    prefs.edit().putStringSet("notified_ids", updatedIds).apply()
                                }
                            }
                        } else {
                            Log.e("NotificationPollingService", "Failed to poll notifications: ${response.message()}")
                        }
                    } catch (e: Exception) {
                        Log.e("NotificationPollingService", "Error polling notifications in background", e)
                    }
                } else {
                    Log.d("NotificationPollingService", "User not logged in, stopping background polling service")
                    stopSelf()
                    break
                }
                
                // Poll every 15 seconds for real-time background sync
                delay(15_000)
            }
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Keeps VR HERE notification syncing active in background"
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun createForegroundNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("VR HERE Background Sync")
            .setContentText("Checking for updates in the background...")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        super.onDestroy()
        pollingJob?.cancel()
        serviceJob.cancel()
        Log.d("NotificationPollingService", "Background Polling Service destroyed")
    }
}
