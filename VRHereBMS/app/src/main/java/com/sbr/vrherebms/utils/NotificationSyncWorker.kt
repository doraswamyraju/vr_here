package com.sbr.vrherebms.utils

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.sbr.vrherebms.data.local.SessionManager
import com.sbr.vrherebms.data.remote.VRHereAPI

class NotificationSyncWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        Log.d("NotificationSyncWorker", "Background notification sync started...")
        val context = applicationContext
        val sessionManager = SessionManager(context)

        // Only sync if user is logged in
        if (!sessionManager.isLoggedIn()) {
            Log.d("NotificationSyncWorker", "User not logged in, skipping background sync")
            return Result.success()
        }

        try {
            val api = VRHereAPI.getInstance(context)
            val response = api.getNotifications()

            if (response.isSuccessful && response.body() != null) {
                val notificationsList = response.body()!!
                val unreadNotifications = notificationsList.filter { !it.isRead }

                if (unreadNotifications.isNotEmpty()) {
                    // Track which notification IDs have already been triggered as alerts
                    val prefs = context.getSharedPreferences("notification_worker_prefs", Context.MODE_PRIVATE)
                    val notifiedIds = prefs.getStringSet("notified_ids", emptySet()) ?: emptySet()
                    
                    val newUnnotified = unreadNotifications.filter { !notifiedIds.contains(it.id) }

                    if (newUnnotified.isNotEmpty()) {
                        Log.d("NotificationSyncWorker", "Found ${newUnnotified.size} new unread notifications in background")
                        
                        // Fire native status bar tray notifications
                        newUnnotified.forEach { notif ->
                            NotificationHelper.showNotification(
                                context,
                                notif.id.hashCode(),
                                notif.title,
                                notif.message,
                                notif.type
                            )
                        }

                        // Save notified IDs to prevent duplicate alerts
                        val updatedIds = notifiedIds.toMutableSet().apply {
                            addAll(newUnnotified.map { it.id })
                        }
                        prefs.edit().putStringSet("notified_ids", updatedIds).apply()
                    }
                }
            } else {
                Log.e("NotificationSyncWorker", "Failed to load notifications: ${response.message()}")
                return Result.retry()
            }
        } catch (e: Exception) {
            Log.e("NotificationSyncWorker", "Background sync exception", e)
            return Result.retry()
        }

        return Result.success()
    }
}
