package com.sbr.vrherebms.ui.screens.customer

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import org.json.JSONObject
import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import com.sbr.vrherebms.utils.RazorpayManager
import android.widget.Toast

fun Context.getActivity(): Activity? {
    var context = this
    while (context is ContextWrapper) {
        if (context is Activity) {
            return context
        }
        context = context.baseContext
    }
    return null
}

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
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val context = LocalContext.current
    var isProcessing by remember { mutableStateOf(false) }

    ModalBottomSheet(
        onDismissRequest = onClose,
        sheetState = sheetState,
        containerColor = Color.White,
        dragHandle = { BottomSheetDefaults.DragHandle() }
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp, vertical = 16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Select Payment Method",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF0F172A)
                )
                IconButton(onClick = onClose) {
                    Icon(imageVector = Icons.Default.Close, contentDescription = "Close", tint = Color(0xFF64748B))
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
            
            val displayPrice = if (amount > 100) amount / 100 else amount
            Text(
                text = "Paying ₹$displayPrice for $serviceName",
                fontSize = 14.sp,
                color = Color(0xFF64748B)
            )

            Spacer(modifier = Modifier.height(24.dp))

            // UPI Button (Simplest custom integration)
            Button(
                onClick = {
                    val activity = context.getActivity()
                    if (activity != null) {
                        isProcessing = true
                        val payload = JSONObject().apply {
                            put("amount", amount)
                            put("currency", currency)
                            put("email", customerEmail.ifBlank { "test@vrhere.in" })
                            put("contact", customerPhone.ifBlank { "9999999999" })
                            put("order_id", orderId)
                            put("method", "upi")
                            put("_[flow]", "intent")
                        }
                        RazorpayManager.submitPayment(
                            activity = activity,
                            key = key,
                            payload = payload,
                            onSuccess = { pid, oid, sig ->
                                isProcessing = false
                                onSuccess(pid, oid, sig)
                            },
                            onFailure = { err ->
                                isProcessing = false
                                onFailure(err)
                            }
                        )
                    } else {
                        Toast.makeText(context, "Cannot resolve activity for payment", Toast.LENGTH_SHORT).show()
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                enabled = !isProcessing
            ) {
                if (isProcessing) {
                    CircularProgressIndicator(color = Color.White, modifier = Modifier.size(24.dp))
                } else {
                    Text("Pay via UPI Apps (GPay, PhonePe)", fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
            
            // Dummy Card Button for now
            OutlinedButton(
                onClick = {
                    Toast.makeText(context, "Card Payments require custom form integration. Use UPI for now.", Toast.LENGTH_LONG).show()
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                enabled = !isProcessing
            ) {
                Text("Pay via Credit/Debit Card", fontSize = 16.sp, color = Color(0xFF0F172A))
            }
            
            Spacer(modifier = Modifier.height(32.dp))
        }
    }
}
