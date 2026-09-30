package com.sbr.vrherebms.ui.screens.customer.bookkeeping.components

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.TransactionDto
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils.IndianCurrencyFormatter

@Composable
fun TransactionItemCard(
    transaction: TransactionDto,
    onView: () -> Unit,
    onEdit: (() -> Unit)? = null,
    onRecordPayment: (() -> Unit)? = null,
    onDelete: (() -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val primaryIndigo = Color(0xFF4F46E5)
    val textDark = Color(0xFF0F172A)
    val textMuted = Color(0xFF64748B)

    val isPaid = transaction.paymentStatus.equals("Paid", ignoreCase = true)
    val statusBg = if (isPaid) Color(0xFFDCFCE7) else Color(0xFFFEF3C7)
    val statusText = if (isPaid) Color(0xFF16A34A) else Color(0xFFD97706)

    val totalAmount = transaction.summary.totalAmount.takeIf { it > 0 }
        ?: transaction.items.sumOf { it.total }

    val formattedDate = transaction.docDate.take(10)

    Surface(
        modifier = modifier
            .fillMaxWidth()
            .clickable { onView() },
        shape = RoundedCornerShape(16.dp),
        color = Color.White,
        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
        shadowElevation = 1.dp
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            // Header Row: Doc Number + Status Badge
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(24.dp)
                            .background(
                                when (transaction.transactionType) {
                                    "Sales" -> Color(0xFF4F46E5).copy(alpha = 0.12f)
                                    "Purchase" -> Color(0xFF059669).copy(alpha = 0.12f)
                                    else -> Color(0xFFD97706).copy(alpha = 0.12f)
                                },
                                RoundedCornerShape(6.dp)
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = when (transaction.transactionType) {
                                "Sales" -> Icons.Default.Description
                                "Purchase" -> Icons.Default.ShoppingCart
                                else -> Icons.Default.TrendingDown
                            },
                            contentDescription = null,
                            tint = when (transaction.transactionType) {
                                "Sales" -> Color(0xFF4F46E5)
                                "Purchase" -> Color(0xFF059669)
                                else -> Color(0xFFD97706)
                            },
                            modifier = Modifier.size(14.dp)
                        )
                    }
                    Text(
                        text = transaction.docNumber.ifEmpty { "Voucher" },
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Black,
                        color = textDark
                    )
                }

                Surface(
                    shape = RoundedCornerShape(20.dp),
                    color = statusBg
                ) {
                    Text(
                        text = transaction.paymentStatus.ifEmpty { "Unpaid" },
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Black,
                        color = statusText,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                    )
                }
            }

            // Party Name and GSTIN
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    text = transaction.partyName.ifEmpty { "Cash / Direct" },
                    fontSize = 13.5.sp,
                    fontWeight = FontWeight.Bold,
                    color = textDark,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                if (transaction.partyGstin.isNotEmpty()) {
                    Text(
                        text = "GSTIN: ${transaction.partyGstin}",
                        fontSize = 11.sp,
                        color = textMuted
                    )
                }
            }

            HorizontalDivider(color = Color(0xFFF1F5F9))

            // Footer Row: Date / Payment Mode & Total Amount + Actions
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = formattedDate,
                        fontSize = 11.sp,
                        color = textMuted,
                        fontWeight = FontWeight.Medium
                    )
                    Text(
                        text = transaction.paymentMode,
                        fontSize = 10.5.sp,
                        color = primaryIndigo,
                        fontWeight = FontWeight.SemiBold
                    )
                }

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = IndianCurrencyFormatter.format(totalAmount),
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Black,
                        color = textDark
                    )

                    // WhatsApp Share Button
                    IconButton(
                        onClick = {
                            val msg = "Hello, here are the details for ${transaction.docNumber}:\nParty: ${transaction.partyName}\nAmount: ${IndianCurrencyFormatter.format(totalAmount)}\nStatus: ${transaction.paymentStatus}\nThank you!"
                            val intent = Intent(Intent.ACTION_VIEW).apply {
                                data = Uri.parse("https://api.whatsapp.com/send?text=" + Uri.encode(msg))
                            }
                            try {
                                context.startActivity(intent)
                            } catch (e: Exception) {
                                Toast.makeText(context, "WhatsApp not installed", Toast.LENGTH_SHORT).show()
                            }
                        },
                        modifier = Modifier
                            .size(28.dp)
                            .background(Color(0xFF22C55E).copy(alpha = 0.12f), CircleShape)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Share,
                            contentDescription = "Share",
                            tint = Color(0xFF16A34A),
                            modifier = Modifier.size(14.dp)
                        )
                    }

                    if (onDelete != null) {
                        IconButton(
                            onClick = onDelete,
                            modifier = Modifier
                                .size(28.dp)
                                .background(Color(0xFFFEE2E2), CircleShape)
                        ) {
                            Icon(
                                imageVector = Icons.Default.DeleteOutline,
                                contentDescription = "Delete",
                                tint = Color(0xFFDC2626),
                                modifier = Modifier.size(14.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}
