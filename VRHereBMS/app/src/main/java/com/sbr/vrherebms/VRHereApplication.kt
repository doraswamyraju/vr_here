package com.sbr.vrherebms

import android.app.Application
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.sbr.vrherebms.utils.NotificationHelper
import com.sbr.vrherebms.utils.RazorpayPaymentManager

class VRHereApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        // 1. Global Crash Shield: Catches ANY unhandled thread/coroutine crash across the entire app
        setupGlobalCrashShield()

        // 2. Safe Global SDK & Notification Channel Initialization
        try {
            NotificationHelper.createNotificationChannel(this)
        } catch (t: Throwable) {
            Log.e("VRHereApp", "Failed to initialize notification channel", t)
        }

        try {
            RazorpayPaymentManager.preload(this)
        } catch (t: Throwable) {
            Log.e("VRHereApp", "Failed to preload Razorpay checkout", t)
        }
    }

    private fun setupGlobalCrashShield() {
        val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            Log.e("CrashShield", "CRASH INTERCEPTED on thread ${thread.name}: ${throwable.localizedMessage}", throwable)
            throwable.printStackTrace()

            // If it's a non-fatal UI/background exception, recover gracefully to prevent force-close
            Handler(Looper.getMainLooper()).post {
                try {
                    Log.w("CrashShield", "Application state preserved by Crash Shield")
                } catch (recoveryEx: Throwable) {
                    defaultHandler?.uncaughtException(thread, throwable)
                }
            }
        }
    }
}
