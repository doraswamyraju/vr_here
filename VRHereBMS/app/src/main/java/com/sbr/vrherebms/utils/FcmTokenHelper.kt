package com.sbr.vrherebms.utils

import android.content.Context
import android.util.Log
import com.sbr.vrherebms.data.local.SessionManager
import com.sbr.vrherebms.data.remote.VRHereAPI
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

object FcmTokenHelper {
    private val scope = CoroutineScope(Dispatchers.IO)

    /**
     * Cache token locally, and upload to the server if the user is authenticated.
     */
    fun uploadFcmToken(context: Context, token: String? = null) {
        val sessionManager = SessionManager(context)
        
        // 1. If token is supplied, cache it
        if (token != null) {
            sessionManager.saveFcmToken(token)
            Log.d("FcmTokenHelper", "FCM token saved locally in SessionManager: $token")
        }

        // 2. Retrieve cached or current token
        val tokenToUpload = sessionManager.getFcmToken()
        if (tokenToUpload.isNullOrEmpty()) {
            Log.w("FcmTokenHelper", "FCM token is empty, skipping upload")
            return
        }

        // 3. Only upload if user is logged in
        if (!sessionManager.isLoggedIn()) {
            Log.d("FcmTokenHelper", "User is not logged in, cached FCM token will be uploaded on login")
            return
        }

        // 4. Fire network request in IO thread
        scope.launch {
            try {
                Log.d("FcmTokenHelper", "Uploading FCM token to server: $tokenToUpload")
                val api = VRHereAPI.getInstance(context)
                val body = mapOf("fcmToken" to tokenToUpload)
                val response = api.updateFcmToken(body)
                if (response.isSuccessful) {
                    Log.d("FcmTokenHelper", "FCM token successfully synced with backend")
                } else {
                    Log.e("FcmTokenHelper", "Failed to sync FCM token: ${response.message()}")
                }
            } catch (e: Exception) {
                Log.e("FcmTokenHelper", "Exception during FCM token upload", e)
            }
        }
    }
}
