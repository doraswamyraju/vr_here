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
        Checkout.preload(context.applicationContext)
        Log.d(TAG, "Razorpay Manager Initialized for Native Checkout")
    }

    fun submitPayment(
        activity: Activity,
        key: String,
        payload: JSONObject,
        onSuccess: (paymentId: String, orderId: String, signature: String) -> Unit,
        onFailure: (errorMsg: String) -> Unit
    ) {
        this.currentSuccessCallback = onSuccess
        this.currentFailureCallback = onFailure

        try {
            val checkout = Checkout()
            checkout.setKeyID(key)
            checkout.open(activity, payload)
        } catch (e: Exception) {
            Log.e(TAG, "Error submitting native checkout payment", e)
            onFailure(e.localizedMessage ?: "Failed to submit payment")
            clearCallbacks()
        }
    }

    // Called from MainActivity's PaymentResultWithDataListener
    fun onPaymentSuccess(razorpayPaymentId: String?, paymentData: PaymentData?) {
        val paymentId = razorpayPaymentId ?: paymentData?.paymentId ?: ""
        val orderId = paymentData?.orderId ?: ""
        val signature = paymentData?.signature ?: ""
        currentSuccessCallback?.invoke(paymentId, orderId, signature)
        clearCallbacks()
    }

    // Called from MainActivity's PaymentResultWithDataListener
    fun onPaymentError(errorCode: Int, response: String?, paymentData: PaymentData?) {
        currentFailureCallback?.invoke(response ?: "Payment failed with code $errorCode")
        clearCallbacks()
    }

    private fun clearCallbacks() {
        currentSuccessCallback = null
        currentFailureCallback = null
    }
}
