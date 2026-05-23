package com.sbr.vrherebms.utils

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.sbr.vrherebms.MainActivity
import com.sbr.vrherebms.R

object NotificationHelper {
    private const val CHANNEL_ID = "vr_here_notifications"
    private const val CHANNEL_NAME = "VR HERE Notifications"
    private const val CHANNEL_DESC = "Notifications for VR HERE order updates and support tickets"

    // Set up and register notification channel (required for Android 8.0+)
    fun createNotificationChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val importance = NotificationManager.IMPORTANCE_DEFAULT
            val channel = NotificationChannel(CHANNEL_ID, CHANNEL_NAME, importance).apply {
                description = CHANNEL_DESC
            }
            // Register the channel with the system
            val notificationManager: NotificationManager =
                context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }

    // Dispatches a physical notification to the device tray and lockscreen
    fun showNotification(
        context: Context,
        notificationId: Int,
        title: String,
        message: String,
        type: String = "System"
    ) {
        // First register channel
        createNotificationChannel(context)

        // Set up intent to open MainActivity when clicked
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        
        val pendingIntent: PendingIntent = PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        // Select resource small icon (we can fall back to standard Android app icon or mipmap)
        // Usually, android.R.drawable.ic_dialog_info is safe to use in any Android SDK
        val iconRes = android.R.drawable.ic_dialog_info

        // Build notification
        val builder = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(iconRes)
            .setContentTitle(title)
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC) // Make visible on lockscreen

        try {
            with(NotificationManagerCompat.from(context)) {
                // Check if notification permission is granted (required for Android 13+)
                // On older devices or if granted, this executes
                notify(notificationId, builder.build())
            }
        } catch (e: SecurityException) {
            // Permission not granted on Android 13+, fail silently or log
            e.printStackTrace()
        }
    }
}
