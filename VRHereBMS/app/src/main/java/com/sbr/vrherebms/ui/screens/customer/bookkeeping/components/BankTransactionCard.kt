package com.sbr.vrherebms.ui.screens.customer.bookkeeping.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Link
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.BankTransactionDto
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils.IndianCurrencyFormatter

@Composable
fun BankTransactionCard(
    transaction: BankTransactionDto,
    onTagClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val primaryIndigo = Color(0xFF4F46E5)
    val textDark = Color(0xFF0F172A)
    val textMuted = Color(0xFF64748B)

    val isCredit = transaction.type.equals("CREDIT", ignoreCase = true)
    val isTagged = transaction.reconciliationStatus.equals("TAGGED", ignoreCase = true)

    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = Color.White,
        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
        shadowElevation = 1.dp
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            // Header Row: Date + Type Pill & Status
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Surface(
                        shape = RoundedCornerShape(6.dp),
                        color = if (isCredit) Color(0xFFDCFCE7) else Color(0xFFFEE2E2)
                    ) {
                        Text(
                            text = if (isCredit) "CR" else "DR",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Black,
                            color = if (isCredit) Color(0xFF16A34A) else Color(0xFFDC2626),
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }

                    Text(
                        text = transaction.date.take(10),
                        fontSize = 11.5.sp,
                        fontWeight = FontWeight.Bold,
                        color = textDark
                    )
                }

                Surface(
                    shape = RoundedCornerShape(20.dp),
                    color = if (isTagged) Color(0xFFDCFCE7) else Color(0xFFFEF3C7)
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        if (isTagged) {
                            Icon(
                                imageVector = Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = Color(0xFF16A34A),
                                modifier = Modifier.size(11.dp)
                            )
                        }
                        Text(
                            text = if (isTagged) "TAGGED" else "UNRECONCILED",
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Black,
                            color = if (isTagged) Color(0xFF16A34A) else Color(0xFFD97706)
                        )
                    }
                }
            }

            // Description / Narration
            Text(
                text = transaction.description,
                fontSize = 12.5.sp,
                fontWeight = FontWeight.SemiBold,
                color = textDark,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )

            if (transaction.referenceNo.isNotBlank()) {
                Text(
                    text = "Ref/UTR: ${transaction.referenceNo}",
                    fontSize = 10.5.sp,
                    color = textMuted
                )
            }

            // Tagged Category or Allocation Notes
            if (isTagged && transaction.taggedCategory.isNotBlank()) {
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = Color(0xFFF1F5F9)
                ) {
                    Text(
                        text = "Linked to: ${transaction.taggedCategory}",
                        fontSize = 11.sp,
                        color = primaryIndigo,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }
            }

            HorizontalDivider(color = Color(0xFFF1F5F9))

            // Footer Row: Amount & Tagging Action Button
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = if (isCredit) "+ ${IndianCurrencyFormatter.format(transaction.amount)}"
                        else "- ${IndianCurrencyFormatter.format(transaction.amount)}",
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Black,
                        color = if (isCredit) Color(0xFF16A34A) else Color(0xFFDC2626)
                    )
                    if (transaction.balance > 0) {
                        Text(
                            text = "Bal: ${IndianCurrencyFormatter.format(transaction.balance)}",
                            fontSize = 10.sp,
                            color = textMuted
                        )
                    }
                }

                if (!isTagged) {
                    Button(
                        onClick = onTagClick,
                        shape = RoundedCornerShape(8.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = primaryIndigo),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                        modifier = Modifier.height(32.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Link,
                            contentDescription = null,
                            modifier = Modifier.size(13.dp)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Tag Payment", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}
