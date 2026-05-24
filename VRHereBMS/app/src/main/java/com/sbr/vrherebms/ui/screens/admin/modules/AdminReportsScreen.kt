package com.sbr.vrherebms.ui.screens.admin.modules

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminReportsScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var isDownloading by remember { mutableStateOf(false) }
    var selectedCategory by remember { mutableStateOf("Revenue") }

    val categories = listOf("Revenue", "Workloads", "Popular Offerings")

    // Dynamic computations for total values from viewmodel
    val totalRevenueValue = adminViewModel.totalPipelineValue
    val paidValue = totalRevenueValue * 0.72 // Estimating 72% paid rate matching Web Q1 Summary
    val pendingValue = totalRevenueValue - paidValue

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF1F5F9))
    ) {
        // 1. Purple Command Header
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1B4B))
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text(
                    text = "BUSINESS INTELLIGENCE",
                    color = Color(0xFF38BDF8),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.ExtraBold,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Operational Analytics",
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Revenues inflow metrics, service category volumes, and employee work allocation reports.",
                    color = Color(0xFF94A3B8),
                    fontSize = 12.sp,
                    lineHeight = 16.sp
                )
            }
        }

        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Row 1: Finance Inflow Stats
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    listOf(
                        Triple("Base Billing", "Rs. %,.0f".format(totalRevenueValue), Color(0xFF3B82F6)),
                        Triple("Paid Collection", "Rs. %,.0f".format(paidValue), Color(0xFF10B981))
                    ).forEach { (title, stat, color) ->
                        Card(
                            modifier = Modifier.weight(1f),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            border = BorderStroke(1.dp, Color(0xFFEEF2F6)),
                            shape = RoundedCornerShape(16.dp)
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text(title, fontSize = 9.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Black)
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(stat, fontSize = 20.sp, color = Color(0xFF1E293B), fontWeight = FontWeight.Black)
                                Spacer(modifier = Modifier.height(4.dp))
                                Text("Q1 Growth Period", fontSize = 8.sp, color = color, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }

            // Canvas Graph Card
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFEEF2F6))
                ) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text("REVENUE TREND", fontSize = 10.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Black)
                                Text("Monthly Inflow Volume", fontSize = 14.sp, color = Color(0xFF1E293B), fontWeight = FontWeight.Bold)
                            }
                            Box(
                                modifier = Modifier
                                    .background(Color(0xFFECFDF5), RoundedCornerShape(6.dp))
                                    .padding(horizontal = 8.dp, vertical = 2.dp)
                            ) {
                                Text("+12.5%", color = Color(0xFF10B981), fontSize = 10.sp, fontWeight = FontWeight.Black)
                            }
                        }

                        Spacer(modifier = Modifier.height(20.dp))

                        // High-Fidelity Compose Canvas-drawn line chart!
                        Canvas(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(160.dp)
                        ) {
                            val width = size.width
                            val height = size.height

                            // Draw baseline grid lines
                            drawLine(Color(0xFFF1F5F9), Offset(0f, height * 0.25f), Offset(width, height * 0.25f), strokeWidth = 1.dp.toPx())
                            drawLine(Color(0xFFF1F5F9), Offset(0f, height * 0.5f), Offset(width, height * 0.5f), strokeWidth = 1.dp.toPx())
                            drawLine(Color(0xFFF1F5F9), Offset(0f, height * 0.75f), Offset(width, height * 0.75f), strokeWidth = 1.dp.toPx())

                            // Coordinates mapping (Jan: ₹4k, Feb: ₹8k, Mar: ₹11k, Apr: ₹14k, May: ₹25.3k)
                            val points = listOf(
                                Offset(width * 0.05f, height * 0.85f),
                                Offset(width * 0.25f, height * 0.70f),
                                Offset(width * 0.50f, height * 0.55f),
                                Offset(width * 0.75f, height * 0.40f),
                                Offset(width * 0.95f, height * 0.15f)
                            )

                            // 1. Draw gradient fill area under the line
                            val fillPath = Path().apply {
                                moveTo(points.first().x, height)
                                points.forEach { lineTo(it.x, it.y) }
                                lineTo(points.last().x, height)
                                close()
                            }
                            drawPath(
                                path = fillPath,
                                brush = Brush.verticalGradient(
                                    colors = listOf(Color(0xFF6366F1).copy(alpha = 0.3f), Color.Transparent)
                                )
                            )

                            // 2. Draw curved connecting path line
                            val strokePath = Path().apply {
                                moveTo(points.first().x, points.first().y)
                                for (i in 1 until points.size) {
                                    val prev = points[i - 1]
                                    val curr = points[i]
                                    val cp1 = Offset((prev.x + curr.x) / 2f, prev.y)
                                    val cp2 = Offset((prev.x + curr.x) / 2f, curr.y)
                                    cubicTo(cp1.x, cp1.y, cp2.x, cp2.y, curr.x, curr.y)
                                }
                            }
                            drawPath(
                                path = strokePath,
                                color = Color(0xFF6366F1),
                                style = Stroke(width = 3.dp.toPx())
                            )

                            // 3. Draw circle dot highlights
                            points.forEach { pt ->
                                drawCircle(Color.White, radius = 6.dp.toPx(), center = pt)
                                drawCircle(Color(0xFF6366F1), radius = 4.dp.toPx(), center = pt, style = Stroke(width = 2.dp.toPx()))
                            }
                        }

                        Spacer(modifier = Modifier.height(10.dp))

                        // X-axis label captions
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            listOf("Jan", "Feb", "Mar", "Apr", "May").forEach { m ->
                                Text(m, fontSize = 10.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }

            // Exporter reports ledger
            item {
                Text("Ready Statements Catalog", color = Color(0xFF1E293B), fontWeight = FontWeight.Bold, fontSize = 15.sp)
            }

            items(
                listOf(
                    "Q1 Revenue & Margin Profitability Ledger",
                    "Service Offerings Conversion & Popularity Index",
                    "Employee Workplace Attendance & Workload Audit"
                )
            ) { name ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    shape = RoundedCornerShape(16.dp),
                    border = BorderStroke(1.dp, Color(0xFFEEF2F6))
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.weight(1f)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(36.dp)
                                    .background(Color(0xFFEFF6FF), RoundedCornerShape(8.dp)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Default.Assessment, contentDescription = null, tint = Color(0xFF3B82F6), modifier = Modifier.size(18.dp))
                            }
                            Spacer(modifier = Modifier.width(16.dp))
                            Column {
                                Text(name, fontWeight = FontWeight.Bold, fontSize = 13.sp, color = Color(0xFF1E293B))
                                Text("Format: PDF Spreadsheet • Size: 2.1 MB", fontSize = 11.sp, color = Color(0xFF64748B))
                            }
                        }

                        IconButton(
                            onClick = {
                                Toast.makeText(context, "Exporting $name...", Toast.LENGTH_SHORT).show()
                            }
                        ) {
                            Icon(Icons.Default.Download, contentDescription = null, tint = Color(0xFF4F46E5))
                        }
                    }
                }
            }
        }
    }
}
