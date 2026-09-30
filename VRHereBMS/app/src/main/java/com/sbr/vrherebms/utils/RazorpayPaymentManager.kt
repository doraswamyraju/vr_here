package com.sbr.vrherebms.utils

import android.app.Activity
import android.widget.Toast
import com.razorpay.Checkout
import com.razorpay.PaymentData
import org.json.JSONObject

object RazorpayPaymentManager {

    private var currentSuccessCallback: ((paymentId: String, orderId: String, signature: String) -> Unit)? = null
    private var currentFailureCallback: ((errorMsg: String) -> Unit)? = null

    fun preload(activity: Activity) {
        try {
            Checkout.preload(activity.applicationContext)
        } catch (e: Exception) {
            android.util.Log.e("RazorpayManager", "Failed to preload checkout", e)
        }
    }

    fun startPayment(
        activity: Activity,
        key: String,
        orderId: String,
        amount: Long, // amount in paise
        currency: String = "INR",
        serviceName: String,
        packageName: String = "",
        customerName: String,
        customerEmail: String,
        customerPhone: String,
        onSuccess: (paymentId: String, orderId: String, signature: String) -> Unit,
        onFailure: (errorMsg: String) -> Unit
    ) {
        currentSuccessCallback = onSuccess
        currentFailureCallback = onFailure

        val checkout = Checkout()
        checkout.setKeyID(key.ifBlank { "rzp_live_default_key" })
        checkout.setImage(com.sbr.vrherebms.R.mipmap.ic_launcher)

        try {
            val options = JSONObject().apply {
                put("name", "VR HERE Business Solutions")
                put("description", if (packageName.isNotBlank()) "$serviceName - $packageName" else serviceName)
                put("currency", currency.ifBlank { "INR" })
                put("amount", amount)
                if (orderId.isNotBlank()) {
                    put("order_id", orderId)
                }
                put("theme.color", "#4F46E5")

                val prefill = JSONObject().apply {
                    if (customerEmail.isNotBlank()) put("email", customerEmail)
                    if (customerPhone.isNotBlank()) put("contact", customerPhone)
                    if (customerName.isNotBlank()) put("name", customerName)
                }
                put("prefill", prefill)

                val retryObj = JSONObject().apply {
                    put("enabled", true)
                    put("max_count", 2)
                }
                put("retry", retryObj)
            }

            checkout.open(activity, options)
        } catch (e: Exception) {
            val err = "Error initializing payment: ${e.localizedMessage}"
            Toast.makeText(activity, err, Toast.LENGTH_LONG).show()
            onFailure(err)
        }
    }

    fun onPaymentSuccess(razorpayPaymentID: String?, paymentData: PaymentData?) {
        val pId = razorpayPaymentID ?: paymentData?.paymentId ?: ""
        val oId = paymentData?.orderId ?: ""
        val sig = paymentData?.signature ?: ""
        currentSuccessCallback?.invoke(pId, oId, sig)
        currentSuccessCallback = null
        currentFailureCallback = null
    }

    fun onPaymentError(code: Int, response: String?, paymentData: PaymentData?) {
        val err = response ?: "Payment cancelled or failed (code: $code)"
        currentFailureCallback?.invoke(err)
        currentSuccessCallback = null
        currentFailureCallback = null
    }
}
