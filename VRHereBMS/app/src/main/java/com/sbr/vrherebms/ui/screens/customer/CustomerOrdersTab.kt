package com.sbr.vrherebms.ui.screens.customer

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.BusinessCenter
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.AccessTime
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.RadioButtonUnchecked
import androidx.compose.material.icons.filled.Receipt
import androidx.compose.ui.platform.LocalContext
import android.content.Intent
import android.net.Uri

@Composable
fun CustomerOrdersTab(
    viewModel: CustomerDashboardViewModel,
    selectedOrderId: String,
    onSelectOrderId: (String) -> Unit,
    onSelectTab: (String) -> Unit
) {
    val context = LocalContext.current
    if (selectedOrderId.isNotEmpty()) {
        val order = viewModel.orders.find { it.id == selectedOrderId }
        if (order != null) {
            // Filter payments for this order
            val orderPayments = viewModel.payments.filter { 
                it.order?.id == order.id || (it.serviceName == order.serviceName && it.packageName == order.packageName)
            }
            val totalPaid = orderPayments.filter { it.status == "Completed" }.sumOf { it.amount }
            val balance = maxOf(0.0, order.price - totalPaid)

            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp)
                    .verticalScroll(rememberScrollState())
                    .padding(top = 16.dp, bottom = 120.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .scaleOnPress()
                        .clickable { onSelectOrderId("") }
                ) {
                    Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color(0xFF6366F1))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Back to Subscriptions", color = Color(0xFF6366F1), fontWeight = FontWeight.Bold, fontSize = 13.sp)
                }

                // 1. Project Header & Milestone Card
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(order.serviceName, fontSize = 18.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                                Text(order.packageName, fontSize = 12.sp, color = Color(0xFF64748B), modifier = Modifier.padding(top = 2.dp))
                            }
                            StatusBadgeWidget(status = order.status)
                        }

                        HorizontalDivider(modifier = Modifier.padding(vertical = 16.dp), color = Color(0xFFF1F5F9))

                        val completeness = getStatusProgress(order.status)
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("PROJECT COMPLETENESS", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                            Text("$completeness%", fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFF6366F1))
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        LinearProgressIndicator(
                            progress = completeness / 100f,
                            color = Color(0xFF6366F1),
                            trackColor = Color(0xFFEEF2F6),
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(8.dp)
                                .clip(CircleShape)
                        )

                        Spacer(modifier = Modifier.height(20.dp))
                        Text("Milestone Tracking Status", fontWeight = FontWeight.Black, fontSize = 14.sp, color = Color(0xFF1E293B))
                        Spacer(modifier = Modifier.height(12.dp))

                        // Timeline steps
                        val milestones = listOf("Pending Documents", "Documents Verified", "Processing at Portal", "Waiting for Clarification", "Completed")
                        val currentMilestoneIndex = milestones.indexOf(order.status)

                        milestones.forEachIndexed { index, milestone ->
                            val isCompleted = index < currentMilestoneIndex
                            val isActive = index == currentMilestoneIndex

                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.padding(vertical = 6.dp)
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(18.dp)
                                        .background(
                                            color = when {
                                                isActive -> Color(0xFF6366F1)
                                                isCompleted -> Color(0xFF10B981)
                                                else -> Color(0xFFCBD5E1)
                                            },
                                            shape = CircleShape
                                        ),
                                    contentAlignment = Alignment.Center
                                ) {
                                    if (isCompleted) {
                                        Icon(Icons.Default.Check, contentDescription = null, tint = Color.White, modifier = Modifier.size(10.dp))
                                    }
                                }
                                Spacer(modifier = Modifier.width(12.dp))
                                Text(
                                    text = milestone,
                                    color = when {
                                        isActive -> Color(0xFF6366F1)
                                        isCompleted -> Color(0xFF10B981)
                                        else -> Color(0xFF64748B)
                                    },
                                    fontWeight = if (isActive) FontWeight.Black else FontWeight.Bold,
                                    fontSize = 13.sp
                                )
                            }
                        }
                    }
                }

                // 2. Latest Updates & Tasks Timeline
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Text("Latest Updates & Tasks", fontSize = 15.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                        Spacer(modifier = Modifier.height(14.dp))

                        if (order.tasks.isEmpty()) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.Center,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(Icons.Default.Info, contentDescription = null, tint = Color(0xFF94A3B8), modifier = Modifier.size(20.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("No tasks or updates available yet.", fontSize = 12.sp, color = Color(0xFF64748B))
                            }
                        } else {
                            order.tasks.forEach { task ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 8.dp),
                                    verticalAlignment = Alignment.Top
                                ) {
                                    Icon(
                                        imageVector = when (task.status) {
                                            "Completed" -> Icons.Default.CheckCircle
                                            "In Progress" -> Icons.Default.AccessTime
                                            else -> Icons.Default.RadioButtonUnchecked
                                        },
                                        contentDescription = null,
                                        tint = when (task.status) {
                                            "Completed" -> Color(0xFF10B981)
                                            "In Progress" -> Color(0xFF6366F1)
                                            else -> Color(0xFF94A3B8)
                                        },
                                        modifier = Modifier.size(20.dp)
                                    )
                                    Spacer(modifier = Modifier.width(12.dp))
                                    Column {
                                        Text(
                                            text = task.title,
                                            fontWeight = FontWeight.Black,
                                            fontSize = 13.sp,
                                            color = if (task.status == "Completed") Color(0xFF64748B) else Color(0xFF1E293B)
                                        )
                                        if (task.description.isNotEmpty()) {
                                            Text(
                                                text = task.description,
                                                fontSize = 11.sp,
                                                color = Color(0xFF64748B),
                                                modifier = Modifier.padding(top = 2.dp)
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // 3. Vault Requirements (Custom requirements)
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Text("Vault Requirements", fontSize = 15.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                        Spacer(modifier = Modifier.height(10.dp))

                        if (order.customerRequirements.isEmpty()) {
                            Text("No custom requirements requested for this order.", fontSize = 12.sp, color = Color(0xFF64748B))
                        } else {
                            order.customerRequirements.forEach { req ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 8.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(req.title, fontWeight = FontWeight.Black, fontSize = 12.sp, color = Color(0xFF334155))
                                        Text(req.description, fontSize = 10.sp, color = Color(0xFF64748B))
                                    }
                                    Box(
                                        modifier = Modifier
                                            .background(
                                                color = if (req.status == "Verified") Color(0xFFD1FAE5) else Color(0xFFFEF3C7),
                                                shape = RoundedCornerShape(6.dp)
                                            )
                                            .padding(horizontal = 8.dp, vertical = 4.dp)
                                    ) {
                                        Text(
                                            text = req.status,
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Black,
                                            color = if (req.status == "Verified") Color(0xFF065F46) else Color(0xFF92400E)
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                // 4. Documents Summary Card
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("Documents Summary", fontSize = 15.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                            Text(
                                text = "Open Vault",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFF6366F1),
                                modifier = Modifier
                                    .clickable { onSelectTab("Vault") }
                                    .padding(4.dp)
                            )
                        }
                        Spacer(modifier = Modifier.height(14.dp))

                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            // Client uploads
                            Column(
                                modifier = Modifier
                                    .weight(1f)
                                    .background(Color(0xFFF8FAFC), RoundedCornerShape(16.dp))
                                    .padding(14.dp)
                            ) {
                                Text("MY UPLOADS", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B))
                                Spacer(modifier = Modifier.height(8.dp))
                                if (order.clientDocuments.isEmpty()) {
                                    Text("No files uploaded", fontSize = 11.sp, color = Color(0xFF94A3B8))
                                } else {
                                    order.clientDocuments.take(3).forEach { doc ->
                                        Text("• ${doc.name}", fontSize = 11.sp, color = Color(0xFF334155), maxLines = 1)
                                    }
                                    if (order.clientDocuments.size > 3) {
                                        Text("+${order.clientDocuments.size - 3} more...", fontSize = 9.sp, color = Color(0xFF6366F1), fontWeight = FontWeight.Bold)
                                    }
                                }
                            }
                            // Admin uploads
                            Column(
                                modifier = Modifier
                                    .weight(1f)
                                    .background(Color(0xFFF8FAFC), RoundedCornerShape(16.dp))
                                    .padding(14.dp)
                            ) {
                                Text("ADMIN DOCS", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B))
                                Spacer(modifier = Modifier.height(8.dp))
                                if (order.adminDocuments.isEmpty()) {
                                    Text("No certificates yet", fontSize = 11.sp, color = Color(0xFF94A3B8))
                                } else {
                                    order.adminDocuments.take(3).forEach { doc ->
                                        Text("• ${doc.name}", fontSize = 11.sp, color = Color(0xFF334155), maxLines = 1)
                                    }
                                    if (order.adminDocuments.size > 3) {
                                        Text("+${order.adminDocuments.size - 3} more...", fontSize = 9.sp, color = Color(0xFF6366F1), fontWeight = FontWeight.Bold)
                                    }
                                }
                            }
                        }
                    }
                }

                // 5. Assigned Expert Card
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Text("Assigned Expert", fontSize = 15.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                        Spacer(modifier = Modifier.height(14.dp))

                        val expert = order.assignedEmployee
                        if (expert != null) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(44.dp)
                                        .background(Color(0xFFEEF2F6), CircleShape),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(Icons.Default.Person, contentDescription = null, tint = Color(0xFF6366F1))
                                }
                                Spacer(modifier = Modifier.width(12.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(expert.name.ifEmpty { "Compliance Expert" }, fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                                    Text(expert.role.ifEmpty { "Assigned Expert" }.uppercase(), fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                                }
                            }
                            Spacer(modifier = Modifier.height(14.dp))
                            HorizontalDivider(color = Color(0xFFF1F5F9))
                            Spacer(modifier = Modifier.height(12.dp))

                            if (expert.email.isNotEmpty()) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            try {
                                                val intent = Intent(Intent.ACTION_SENDTO).apply {
                                                    data = Uri.parse("mailto:${expert.email}")
                                                }
                                                context.startActivity(intent)
                                            } catch (e: Exception) {}
                                        }
                                        .padding(vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(Icons.Default.Email, contentDescription = null, tint = Color(0xFF64748B), modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(expert.email, fontSize = 12.sp, color = Color(0xFF475569))
                                }
                            }
                            // Call Action (we can trigger if employee has phone - employee response has ID/name/email/role. Let's make it display general support phone if empty)
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        try {
                                            val intent = Intent(Intent.ACTION_DIAL).apply {
                                                data = Uri.parse("tel:918008530606")
                                            }
                                            context.startActivity(intent)
                                        } catch (e: Exception) {}
                                    }
                                    .padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(Icons.Default.Phone, contentDescription = null, tint = Color(0xFF64748B), modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("+91 80085 30606", fontSize = 12.sp, color = Color(0xFF475569))
                            }
                        } else {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.Center,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(Icons.Default.Person, contentDescription = null, tint = Color(0xFF94A3B8), modifier = Modifier.size(20.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Expert assignment pending.", fontSize = 12.sp, color = Color(0xFF64748B))
                            }
                        }
                    }
                }

                // 6. Financial Summary Card
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFECFDF5)),
                    border = BorderStroke(1.dp, Color(0xFFA7F3D0))
                ) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Receipt, contentDescription = null, tint = Color(0xFF047857), modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Financial Summary", fontSize = 15.sp, fontWeight = FontWeight.Black, color = Color(0xFF064E3B))
                        }
                        Spacer(modifier = Modifier.height(14.dp))

                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text("Total Price", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF065F46))
                                Text("₹${order.price.toInt()}", fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF064E3B))
                            }
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text("Amount Paid", fontSize = 13.sp, color = Color(0xFF047857))
                                Text("₹${totalPaid.toInt()}", fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF064E3B))
                            }
                            HorizontalDivider(color = Color(0xFFA7F3D0), modifier = Modifier.padding(vertical = 4.dp))
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text("Balance Due", fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF064E3B))
                                Text("₹${balance.toInt()}", fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF064E3B))
                            }
                        }

                        if (orderPayments.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(16.dp))
                            Text("RECENT INVOICES", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF047857), letterSpacing = 0.5.sp)
                            Spacer(modifier = Modifier.height(6.dp))
                            orderPayments.forEach { p ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 4.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(
                                        text = if (p.createdAt.length >= 10) p.createdAt.substring(0, 10) else "Recent",
                                        fontSize = 11.sp,
                                        color = Color(0xFF047857)
                                    )
                                    Text(
                                        text = "₹${p.amount.toInt()} (${p.status})",
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFF064E3B)
                                    )
                                }
                            }
                        }
                    }
                }
            }
        } else {
            onSelectOrderId("")
        }
    } else {
        var selectedCategory by remember { mutableStateOf("All") }
        val categories = listOf("All", "Active", "Completed", "Action Required")

        val filteredOrders = remember(selectedCategory, viewModel.orders) {
            when (selectedCategory) {
                "Active" -> viewModel.orders.filter { it.status != "Completed" }
                "Completed" -> viewModel.orders.filter { it.status == "Completed" }
                "Action Required" -> viewModel.orders.filter {
                    it.status == "Pending Documents" || it.status == "Waiting for Clarification"
                }
                else -> viewModel.orders
            }
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            contentPadding = PaddingValues(top = 16.dp, bottom = 120.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                Column {
                    Text("Your Orders", fontSize = 22.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                    Text("Track the progress of your active requests.", fontSize = 13.sp, color = Color(0xFF64748B), modifier = Modifier.padding(top = 2.dp))
                }
            }

            item {
                LazyRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(categories) { category ->
                        val isSelected = selectedCategory == category
                        Box(
                            modifier = Modifier
                                .background(
                                    color = if (isSelected) Color(0xFF6366F1) else Color(0xFFEEF2F6),
                                    shape = RoundedCornerShape(12.dp)
                                )
                                .clickable { selectedCategory = category }
                                .padding(horizontal = 16.dp, vertical = 8.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = category,
                                color = if (isSelected) Color.White else Color(0xFF475569),
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }

            if (filteredOrders.isEmpty()) {
                item {
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 16.dp),
                        shape = RoundedCornerShape(24.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFCBD5E1).copy(alpha = 0.5f))
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(32.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(64.dp)
                                    .background(Color(0xFFEEF2F6), CircleShape),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Default.FolderOpen,
                                    contentDescription = null,
                                    tint = Color(0xFF94A3B8),
                                    modifier = Modifier.size(28.dp)
                                )
                            }
                            Spacer(modifier = Modifier.height(16.dp))
                            Text(
                                text = "No Orders Found",
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFF1E293B)
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "Looks like you haven't started any projects yet.",
                                fontSize = 12.sp,
                                color = Color(0xFF64748B),
                                textAlign = androidx.compose.ui.text.style.TextAlign.Center
                            )
                            Spacer(modifier = Modifier.height(24.dp))
                            Button(
                                onClick = { onSelectTab("Services") },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6366F1)),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.scaleOnPress()
                            ) {
                                Text(
                                    "Browse Services",
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color.White
                                )
                            }
                        }
                    }
                }
            } else {
                items(filteredOrders) { order ->
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .scaleOnPress()
                            .clickable { onSelectOrderId(order.id) },
                        shape = RoundedCornerShape(24.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFF1F5F9))
                    ) {
                        Column(modifier = Modifier.padding(20.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(44.dp)
                                        .background(Color(0xFFEEF2F6), RoundedCornerShape(12.dp)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(Icons.Default.BusinessCenter, contentDescription = null, tint = Color(0xFF6366F1))
                                }
                                Spacer(modifier = Modifier.width(12.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        order.serviceName,
                                        fontSize = 14.sp,
                                        fontWeight = FontWeight.Black,
                                        color = Color(0xFF1E293B)
                                    )
                                    Text(
                                        order.packageName,
                                        fontSize = 11.sp,
                                        color = Color(0xFF64748B)
                                    )
                                }
                                StatusBadgeWidget(status = order.status)
                            }

                            Spacer(modifier = Modifier.height(16.dp))

                            val completeness = getStatusProgress(order.status)
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    "COMPLETENESS",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF94A3B8),
                                    letterSpacing = 0.5.sp
                                )
                                Text(
                                    "$completeness%",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF6366F1)
                                )
                            }
                            Spacer(modifier = Modifier.height(6.dp))
                            LinearProgressIndicator(
                                progress = completeness / 100f,
                                color = Color(0xFF6366F1),
                                trackColor = Color(0xFFEEF2F6),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(6.dp)
                                    .clip(CircleShape)
                            )
                        }
                    }
                }
            }
        }
    }
}
