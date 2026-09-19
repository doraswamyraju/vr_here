package com.sbr.vrherebms.utils

import android.app.Activity
import android.content.Context
import android.util.Log
import com.razorpay.Checkout
import com.razorpay.PaymentData
import org.json.JSONObject

object RazorpayManager {
    private const val TAG = "RazorpayManager"

    private var currentSuccessCallback: ((paymentId: String, orderId: String, signature: String) -> Unit)? = null
    private var currentFailureCallback: ((errorMsg: String) -> Unit)? = null

    fun initialize(context: Context) {
        try {
            Checkout.preload(context.applicationContext)
            Log.d(TAG, "Razorpay Checkout preloaded successfully")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to preload Razorpay Checkout", e)
        }
    }

    fun startPayment(
        activity: Activity,
        key: String,
        orderId: String,
        amount: Long, // amount in paise
        currency: String = "INR",
        serviceName: String,
        packageName: String,
        customerName: String,
        customerEmail: String,
        customerPhone: String,
        onSuccess: (paymentId: String, orderId: String, signature: String) -> Unit,
        onFailure: (errorMsg: String) -> Unit
    ) {
        this.currentSuccessCallback = onSuccess
        this.currentFailureCallback = onFailure

        try {
            val checkout = Checkout()
            checkout.setKeyID(key.trim())

            val options = JSONObject().apply {
                put("name", "VR HERE")
                put("description", "$serviceName - $packageName")
                put("image", "https://vrhere.in/logo.png")
                put("order_id", orderId.trim())
                put("currency", currency.trim().ifEmpty { "INR" })
                put("amount", amount)

                val prefill = JSONObject().apply {
                    if (customerEmail.isNotBlank()) put("email", customerEmail.trim())
                    if (customerPhone.isNotBlank()) put("contact", customerPhone.trim())
                    if (customerName.isNotBlank()) put("name", customerName.trim())
                }
                put("prefill", prefill)

                val theme = JSONObject().apply {
                    put("color", "#DC2626")
                }
                put("theme", theme)

                put("send_sms_hash", true)
            }

            Log.d(TAG, "Opening Native Razorpay SDK for Order: $orderId, Amount: $amount")
            checkout.open(activity, options)
        } catch (e: Exception) {
            Log.e(TAG, "Error opening Razorpay native SDK", e)
            onFailure(e.localizedMessage ?: "Failed to open Razorpay gateway")
            clearCallbacks()
        }
    }

    fun onPaymentSuccess(razorpayPaymentId: String?, paymentData: PaymentData?) {
        val paymentId = razorpayPaymentId ?: paymentData?.paymentId ?: ""
        val orderId = paymentData?.orderId ?: ""
        val signature = paymentData?.signature ?: ""
        Log.d(TAG, "Native Payment Success: paymentId=$paymentId, orderId=$orderId, signature=$signature")
        currentSuccessCallback?.invoke(paymentId, orderId, signature)
        clearCallbacks()
    }

    fun onPaymentError(errorCode: Int, response: String?, paymentData: PaymentData?) {
        Log.e(TAG, "Native Payment Error: code=$errorCode, response=$response")
        val errorMsg = when (errorCode) {
            Checkout.NETWORK_ERROR -> "Network error during transaction. Please check your internet."
            Checkout.INVALID_OPTIONS -> "Invalid transaction options: $response"
            Checkout.PAYMENT_CANCELED -> "Payment cancelled by user"
            Checkout.TLS_ERROR -> "Device does not support TLS v1.2"
            else -> response ?: "Payment failed (code: $errorCode)"
        }
        currentFailureCallback?.invoke(errorMsg)
        clearCallbacks()
    }

    private fun clearCallbacks() {
        currentSuccessCallback = null
        currentFailureCallback = null
    }
}
