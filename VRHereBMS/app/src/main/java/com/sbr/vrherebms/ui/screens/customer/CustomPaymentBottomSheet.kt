package com.sbr.vrherebms.ui.screens.customer

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.utils.RazorpayPaymentManager

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomPaymentBottomSheet(
    key: String,
    orderId: String,
    amount: Long,
    currency: String,
    serviceName: String,
    packageName: String,
    customerName: String,
    customerEmail: String,
    customerPhone: String,
    onSuccess: (paymentId: String, orderId: String, signature: String) -> Unit,
    onFailure: (errorMsg: String) -> Unit,
    onClose: () -> Unit
) {
    val context = LocalContext.current
    val activity = remember(context) { context.findActivity() }
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    var hasLaunched by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        if (!hasLaunched && activity != null) {
            hasLaunched = true
            RazorpayPaymentManager.startPayment(
                activity = activity,
                key = key,
                orderId = orderId,
                amount = amount,
                currency = currency,
                serviceName = serviceName,
                packageName = packageName,
                customerName = customerName,
                customerEmail = customerEmail,
                customerPhone = customerPhone,
                onSuccess = { paymentId, oId, sig ->
                    onSuccess(paymentId, oId, sig)
                    onClose()
                },
                onFailure = { errorMsg ->
                    onFailure(errorMsg)
                    onClose()
                }
            )
        }
    }

    ModalBottomSheet(
        onDismissRequest = onClose,
        sheetState = sheetState,
        containerColor = Color.White,
        dragHandle = null
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Lock,
                        contentDescription = null,
                        tint = Color(0xFF16A34A),
                        modifier = Modifier.size(16.dp)
                    )
                    Text(
                        text = "SECURE RAZORPAY CHECKOUT",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF16A34A),
                        letterSpacing = 0.5.sp
                    )
                }

                IconButton(
                    onClick = onClose,
                    modifier = Modifier
                        .size(32.dp)
                        .background(Color(0xFFF1F5F9), CircleShape)
                ) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Close",
                        tint = Color(0xFF64748B),
                        modifier = Modifier.size(16.dp)
                    )
                }
            }

            HorizontalDivider(color = Color(0xFFF1F5F9))

            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = serviceName,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF0F172A),
                    textAlign = TextAlign.Center
                )

                if (packageName.isNotBlank()) {
                    Surface(
                        shape = RoundedCornerShape(6.dp),
                        color = Color(0xFFEEF2FF)
                    ) {
                        Text(
                            text = packageName,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF4F46E5),
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }
                }

                val amountInRupees = amount / 100.0
                Text(
                    text = "₹%.2f".format(amountInRupees),
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF0F172A)
                )
            }

            CircularProgressIndicator(
                color = Color(0xFF4F46E5),
                strokeWidth = 3.dp,
                modifier = Modifier.size(36.dp)
            )

            Text(
                text = "Launching Razorpay Secure Gateway...\nChoose UPI, Cards, NetBanking or Wallet",
                fontSize = 12.sp,
                color = Color(0xFF64748B),
                textAlign = TextAlign.Center,
                lineHeight = 16.sp
            )

            Button(
                onClick = {
                    if (activity != null) {
                        RazorpayPaymentManager.startPayment(
                            activity = activity,
                            key = key,
                            orderId = orderId,
                            amount = amount,
                            currency = currency,
                            serviceName = serviceName,
                            packageName = packageName,
                            customerName = customerName,
                            customerEmail = customerEmail,
                            customerPhone = customerPhone,
                            onSuccess = { paymentId, oId, sig ->
                                onSuccess(paymentId, oId, sig)
                                onClose()
                            },
                            onFailure = { errorMsg ->
                                onFailure(errorMsg)
                                onClose()
                            }
                        )
                    }
                },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth().height(48.dp)
            ) {
                Text("Re-open Razorpay Gateway", fontWeight = FontWeight.Bold, fontSize = 13.sp)
            }
        }
    }
}

private fun Context.findActivity(): Activity? {
    var currentContext = this
    while (currentContext is ContextWrapper) {
        if (currentContext is Activity) {
            return currentContext
        }
        currentContext = currentContext.baseContext
    }
    return null
}
