package com.sbr.vrherebms.ui.screens.customer.bookkeeping.components

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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.models.MobileTransaction

@Composable
fun FinanceBox(title: String, value: String, icon: ImageVector, iconColor: Color, indicatorText: String, indicatorColor: Color, modifier: Modifier = Modifier) {
    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
        modifier = modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(title, fontSize = 9.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B), letterSpacing = 0.5.sp)
                Box(
                    modifier = Modifier.size(24.dp).background(iconColor.copy(alpha = 0.1f), CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(icon, contentDescription = null, tint = iconColor, modifier = Modifier.size(14.dp))
                }
            }
            Text(value, fontSize = 18.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
            Text(indicatorText, fontSize = 10.sp, fontWeight = FontWeight.SemiBold, color = indicatorColor)
        }
    }
}

@Composable
fun ComplianceRow(title: String, dueDate: String, status: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column {
            Text(title, fontSize = 11.5.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
            Text("Due: $dueDate", fontSize = 9.5.sp, color = Color.Gray)
        }
        Surface(
            shape = RoundedCornerShape(6.dp),
            color = when (status) {
                "FILED" -> Color(0xFFD1FAE5)
                "ACTIVE" -> Color(0xFFEFF6FF)
                else -> Color(0xFFFEF3C7)
            }
        ) {
            Text(
                status,
                color = when (status) {
                    "FILED" -> Color(0xFF065F46)
                    "ACTIVE" -> Color(0xFF1D4ED8)
                    else -> Color(0xFF92400E)
                },
                fontSize = 8.5.sp,
                fontWeight = FontWeight.Black,
                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
            )
        }
    }
}

@Composable
fun MobileTxCard(tx: MobileTransaction, onClick: () -> Unit) {
    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        modifier = Modifier.fillMaxWidth().clickable { onClick() }
    ) {
        Row(
            modifier = Modifier.padding(12.dp).fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(38.dp)
                    .background(
                        when (tx.type) {
                            "Sales" -> Color(0xFFDCFCE7)
                            "Purchase" -> Color(0xFFEFF6FF)
                            else -> Color(0xFFFFEDD5)
                        },
                        CircleShape
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = when (tx.type) {
                        "Sales" -> Icons.Default.Description
                        "Purchase" -> Icons.Default.ShoppingCart
                        else -> Icons.Default.TrendingDown
                    },
                    contentDescription = null,
                    tint = when (tx.type) {
                        "Sales" -> Color(0xFF16A34A)
                        "Purchase" -> Color(0xFF2563EB)
                        else -> Color(0xFFEA580C)
                    },
                    modifier = Modifier.size(18.dp)
                )
            }

            Column(modifier = Modifier.weight(1f)) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(tx.docNumber, fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                    Text("• ${tx.date}", fontSize = 10.sp, color = Color.Gray)
                }
                Text(tx.partyName, fontSize = 11.sp, color = Color(0xFF475569), maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    "₹${(tx.amount + tx.taxAmount).toInt()}",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Black,
                    color = if (tx.type == "Sales") Color(0xFF16A34A) else Color(0xFF0F172A)
                )
                Surface(
                    color = if (tx.status == "Paid") Color(0xFFDCFCE7) else Color(0xFFFEF3C7),
                    shape = RoundedCornerShape(4.dp)
                ) {
                    Text(
                        tx.status.uppercase(),
                        fontSize = 8.sp,
                        fontWeight = FontWeight.Black,
                        color = if (tx.status == "Paid") Color(0xFF166534) else Color(0xFFB45309),
                        modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp)
                    )
                }
            }
        }
    }
}

@Composable
fun ReportTile(title: String, desc: String, icon: ImageVector, onExport: () -> Unit) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        modifier = Modifier.fillMaxWidth().clickable { onExport() }
    ) {
        Row(
            modifier = Modifier.padding(14.dp).fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Box(
                modifier = Modifier.size(40.dp).background(Color(0xFFEEF2FF), RoundedCornerShape(10.dp)),
                contentAlignment = Alignment.Center
            ) {
                Icon(imageVector = icon, contentDescription = null, tint = Color(0xFF4F46E5), modifier = Modifier.size(20.dp))
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(title, fontWeight = FontWeight.Black, fontSize = 13.sp, color = Color(0xFF0F172A))
                Text(desc, fontSize = 10.5.sp, color = Color.Gray)
            }
            Icon(Icons.Default.Download, contentDescription = null, tint = Color(0xFF4F46E5), modifier = Modifier.size(20.dp))
        }
    }
}

@Composable
fun EmptyStateBox(message: String) {
    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Icon(Icons.Default.FolderOpen, contentDescription = null, tint = Color.LightGray, modifier = Modifier.size(40.dp))
            Text(message, fontSize = 12.sp, color = Color.Gray, textAlign = TextAlign.Center)
        }
    }
}
