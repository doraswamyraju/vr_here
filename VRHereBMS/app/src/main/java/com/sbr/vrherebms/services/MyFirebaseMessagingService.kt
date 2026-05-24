package com.sbr.vrherebms.services

import android.util.Log
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import com.sbr.vrherebms.utils.FcmTokenHelper
import com.sbr.vrherebms.utils.NotificationHelper

class MyFirebaseMessagingService : FirebaseMessagingService() {

    override fun onNewToken(token: String) {
        super.onNewToken(token)
        Log.d("MyFirebaseMessaging", "Refreshed FCM token received: $token")
        // Cache and upload the token
        FcmTokenHelper.uploadFcmToken(applicationContext, token)
    }

    override fun onMessageReceived(remoteMessage: RemoteMessage) {
        super.onMessageReceived(remoteMessage)
        Log.d("MyFirebaseMessaging", "FCM push notification received from: ${remoteMessage.from}")

        // 1. Process notification payload
        val title = remoteMessage.notification?.title ?: remoteMessage.data["title"] ?: "VR HERE Alert"
        val body = remoteMessage.notification?.body ?: remoteMessage.data["body"] ?: "You have a new update"
        val type = remoteMessage.data["type"] ?: "System"

        Log.d("MyFirebaseMessaging", "Push Details - Title: $title, Body: $body, Type: $type")

        // 2. Display the notification
        val notificationId = remoteMessage.messageId?.hashCode() ?: System.currentTimeMillis().toInt()
        NotificationHelper.showNotification(
            context = applicationContext,
            notificationId = notificationId,
            title = title,
            message = body,
            type = type
        )
    }
}
