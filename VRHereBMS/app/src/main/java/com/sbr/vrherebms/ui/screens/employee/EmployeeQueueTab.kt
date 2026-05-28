package com.sbr.vrherebms.ui.screens.employee

import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.OrderResponse
import com.sbr.vrherebms.data.model.TodoResponse
import com.sbr.vrherebms.viewmodel.EmployeeDashboardViewModel
import java.text.NumberFormat
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EmployeeQueueTab(
    viewModel: EmployeeDashboardViewModel,
    selectedOrder: OrderResponse?,
    onSelectOrder: (OrderResponse?) -> Unit
) {
    val context = LocalContext.current
    val isClockedIn = viewModel.isClockedIn
    val orders = viewModel.assignedOrders
    val todos = viewModel.assignedTodos

    // Picker for uploading final certificate
    val documentPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null && selectedOrder != null) {
            viewModel.uploadFinalCertificate(selectedOrder.id, uri, context)
        }
    }

    if (selectedOrder != null) {
        // --- ORDER DETAILED PROCESSING VIEW ---
        var detailTab by remember { mutableStateOf("Overview") }
        var subTab by remember { mutableStateOf("Details") }
        
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.clickable { onSelectOrder(null) }
                ) {
                    Icon(Icons.Default.ArrowBack, contentDescription = null, tint = Color(0xFF6366F1))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Back to Work Queue",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF6366F1)
                    )
                }
            }

            // Order Header Snapshot Card
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.Top
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = selectedOrder.serviceName,
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF1E293B)
                                )
                                Text(
                                    text = "Client: ${selectedOrder.clientName}",
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF64748B),
                                    modifier = Modifier.padding(top = 2.dp)
                                )
                            }
                            
                            Box(
                                modifier = Modifier
                                    .background(Color(0xFFE0E7FF), RoundedCornerShape(8.dp))
                                    .padding(horizontal = 8.dp, vertical = 4.dp)
                            ) {
                                Text(
                                    text = selectedOrder.status,
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF3730A3)
                                )
                            }
                        }

                        Divider(color = Color(0xFFF1F5F9))

                        // Controls: Update status dropdown
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text(
                                text = "Modify Milestone Status",
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF94A3B8)
                            )
                            
                            var statusExpanded by remember { mutableStateOf(false) }
                            val statuses = listOf(
                                "Pending Documents",
                                "Documents Verified",
                                "Processing at Portal",
                                "Waiting for Clarification",
                                "Completed"
                            )

                            Box {
                                OutlinedButton(
                                    onClick = { statusExpanded = true },
                                    shape = RoundedCornerShape(12.dp),
                                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFF475569)),
                                    border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(selectedOrder.status, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                                        Icon(Icons.Default.ArrowDropDown, contentDescription = null)
                                    }
                                }
                                
                                DropdownMenu(
                                    expanded = statusExpanded,
                                    onDismissRequest = { statusExpanded = false }
                                ) {
                                    statuses.forEach { item ->
                                        DropdownMenuItem(
                                            text = { Text(item, fontSize = 13.sp, fontWeight = FontWeight.Bold) },
                                            onClick = {
                                                statusExpanded = false
                                                viewModel.updateOrderStatus(selectedOrder.id, item)
                                            }
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Finish & Deliver Certificate Card
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFECFDF5)),
                    border = BorderStroke(1.dp, Color(0xFFA7F3D0))
                ) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = Color(0xFF10B981))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "Finish & Deliver",
                                fontWeight = FontWeight.Black,
                                fontSize = 14.sp,
                                color = Color(0xFF065F46)
                            )
                        }
                        
                        if (selectedOrder.finalCertificateUrl != null) {
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(Color.White, RoundedCornerShape(12.dp))
                                    .border(1.dp, Color(0xFFD1FAE5), RoundedCornerShape(12.dp))
                                    .padding(12.dp)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = "Certificate Delivered",
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 12.sp,
                                        color = Color(0xFF047857)
                                    )
                                    Icon(
                                        Icons.Default.TaskAlt,
                                        contentDescription = null,
                                        tint = Color(0xFF10B981)
                                    )
                                }
                            }
                        } else {
                            Button(
                                onClick = {
                                    if (!isClockedIn) {
                                        Toast.makeText(context, "Please clock in first.", Toast.LENGTH_SHORT).show()
                                    } else {
                                        documentPickerLauncher.launch("application/pdf")
                                    }
                                },
                                shape = RoundedCornerShape(12.dp),
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981)),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Icon(Icons.Default.UploadFile, contentDescription = null)
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Upload Final Certificate", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }

            // Horizontal Tab Controls
            item {
                val tabList = listOf("Overview", "Tasks", "Requirements", "Invoices", "ToDo", "Transactions", "Activities", "Docs")
                ScrollableTabRow(
                    selectedTabIndex = tabList.indexOf(detailTab),
                    edgePadding = 0.dp,
                    containerColor = Color.Transparent,
                    divider = {},
                    indicator = { tabPositions ->
                        Box(
                            Modifier
                                .tabIndicatorOffset(tabPositions[tabList.indexOf(detailTab)])
                                .height(3.dp)
                                .background(Color(0xFF6366F1), RoundedCornerShape(1.5.dp))
                        )
                    }
                ) {
                    tabList.forEach { tab ->
                        Tab(
                            selected = detailTab == tab,
                            onClick = { detailTab = tab },
                            text = {
                                Text(
                                    text = tab,
                                    fontSize = 13.sp,
                                    fontWeight = if (detailTab == tab) FontWeight.Black else FontWeight.Bold,
                                    color = if (detailTab == tab) Color(0xFF6366F1) else Color(0xFF94A3B8)
                                )
                            }
                        )
                    }
                }
            }

            // Tab contents
            when (detailTab) {
                "Tasks" -> {
                    val assignedTasks = selectedOrder.tasks
                    val linkedTodos = todos.filter { it.orderId?.id == selectedOrder.id }

                    if (assignedTasks.isEmpty() && linkedTodos.isEmpty()) {
                        item {
                            Text("No operational steps assigned yet.", fontSize = 12.sp, color = Color(0xFF64748B))
                        }
                    } else {
                        // Operational tasks checklist
                        if (assignedTasks.isNotEmpty()) {
                            item {
                                Text(
                                    text = "Workflow Assignments",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF94A3B8),
                                    modifier = Modifier.padding(top = 4.dp)
                                )
                            }
                            
                            items(assignedTasks) { task ->
                                Card(
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(16.dp),
                                    colors = CardDefaults.cardColors(containerColor = Color.White),
                                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                                ) {
                                    Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Text(
                                                text = task.title,
                                                fontWeight = FontWeight.Black,
                                                fontSize = 13.sp,
                                                color = Color(0xFF1E293B),
                                                modifier = Modifier.weight(1f)
                                            )
                                            
                                            Row(
                                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                                                verticalAlignment = Alignment.CenterVertically
                                            ) {
                                                Box(
                                                    modifier = Modifier
                                                        .background(
                                                            color = when (task.status) {
                                                                "Completed" -> Color(0xFFD1FAE5)
                                                                "In Progress" -> Color(0xFFFEF3C7)
                                                                else -> Color(0xFFEEF2F6)
                                                            },
                                                            shape = RoundedCornerShape(6.dp)
                                                        )
                                                        .padding(horizontal = 6.dp, vertical = 2.dp)
                                                ) {
                                                    Text(
                                                        text = task.status,
                                                        fontSize = 8.sp,
                                                        fontWeight = FontWeight.Black,
                                                        color = when (task.status) {
                                                            "Completed" -> Color(0xFF065F46)
                                                            "In Progress" -> Color(0xFF92400E)
                                                            else -> Color(0xFF64748B)
                                                        }
                                                    )
                                                }
                                                
                                                if (task.status == "Pending") {
                                                    IconButton(
                                                        onClick = {
                                                            if (!isClockedIn) Toast.makeText(context, "Please clock in first.", Toast.LENGTH_SHORT).show()
                                                            else viewModel.updateTaskStatus(selectedOrder.id, task.id ?: "", "In Progress")
                                                        },
                                                        modifier = Modifier.size(24.dp)
                                                    ) {
                                                        Icon(Icons.Default.PlayArrow, contentDescription = null, tint = Color(0xFF6366F1))
                                                    }
                                                }
                                                
                                                if (task.status != "Completed") {
                                                    IconButton(
                                                        onClick = {
                                                            if (!isClockedIn) Toast.makeText(context, "Please clock in first.", Toast.LENGTH_SHORT).show()
                                                            else viewModel.updateTaskStatus(selectedOrder.id, task.id ?: "", "Completed")
                                                        },
                                                        modifier = Modifier.size(24.dp)
                                                    ) {
                                                        Icon(Icons.Default.Check, contentDescription = null, tint = Color(0xFF10B981))
                                                    }
                                                }
                                            }
                                        }

                                        if (task.description.isNotEmpty()) {
                                            Text(
                                                text = task.description,
                                                fontSize = 11.sp,
                                                color = Color(0xFF64748B)
                                            )
                                        }

                                        // Subtasks list
                                        if (task.subtasks.isNotEmpty()) {
                                            Divider(color = Color(0xFFF1F5F9))
                                            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                                task.subtasks.forEach { subtask ->
                                                    Row(
                                                        modifier = Modifier
                                                            .fillMaxWidth()
                                                            .background(Color(0xFFF8FAFC), RoundedCornerShape(8.dp))
                                                            .padding(8.dp),
                                                        horizontalArrangement = Arrangement.SpaceBetween,
                                                        verticalAlignment = Alignment.CenterVertically
                                                    ) {
                                                        Text(
                                                            text = "• ${subtask.title}",
                                                            fontSize = 11.sp,
                                                            color = Color(0xFF475569),
                                                            modifier = Modifier.weight(1f)
                                                        )
                                                        
                                                        Row(
                                                            horizontalArrangement = Arrangement.spacedBy(4.dp),
                                                            verticalAlignment = Alignment.CenterVertically
                                                        ) {
                                                            Box(
                                                                modifier = Modifier
                                                                    .background(
                                                                        color = if (subtask.isCompleted) Color(0xFFD1FAE5) else Color(0xFFEEF2F6),
                                                                        shape = RoundedCornerShape(6.dp)
                                                                    )
                                                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                                                            ) {
                                                                Text(
                                                                    text = if (subtask.isCompleted) "Completed" else "Pending",
                                                                    fontSize = 8.sp,
                                                                    fontWeight = FontWeight.Bold,
                                                                    color = if (subtask.isCompleted) Color(0xFF065F46) else Color(0xFF64748B)
                                                                )
                                                            }
                                                            
                                                            if (!subtask.isCompleted) {
                                                                IconButton(
                                                                    onClick = {
                                                                        if (!isClockedIn) Toast.makeText(context, "Please clock in first.", Toast.LENGTH_SHORT).show()
                                                                        else viewModel.updateSubtaskStatus(
                                                                            selectedOrder.id,
                                                                            task.id ?: "",
                                                                            subtask.id ?: "",
                                                                            true,
                                                                            "Completed"
                                                                        )
                                                                    },
                                                                    modifier = Modifier.size(20.dp)
                                                                ) {
                                                                    Icon(Icons.Default.CheckCircle, contentDescription = null, tint = Color(0xFF10B981), modifier = Modifier.size(16.dp))
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Linked Todos list
                        if (linkedTodos.isNotEmpty()) {
                            item {
                                Text(
                                    text = "Linked Standalone Tasks (TODOs)",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF6366F1),
                                    modifier = Modifier.padding(top = 8.dp)
                                )
                            }

                            items(linkedTodos) { todo ->
                                Card(
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(16.dp),
                                    colors = CardDefaults.cardColors(containerColor = Color.White),
                                    border = BorderStroke(1.dp, Color(0xFFEEF2F6))
                                ) {
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(12.dp),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Row(verticalAlignment = Alignment.CenterVertically) {
                                                Box(
                                                    modifier = Modifier
                                                        .background(
                                                            color = when (todo.priority) {
                                                                "Urgent" -> Color(0xFFFEE2E2)
                                                                "High" -> Color(0xFFFEF3C7)
                                                                else -> Color(0xFFE0E7FF)
                                                            },
                                                            shape = RoundedCornerShape(4.dp)
                                                        )
                                                        .padding(horizontal = 4.dp, vertical = 2.dp)
                                                ) {
                                                    Text(
                                                        text = todo.priority,
                                                        fontSize = 7.sp,
                                                        fontWeight = FontWeight.Black,
                                                        color = when (todo.priority) {
                                                            "Urgent" -> Color(0xFF991B1B)
                                                            "High" -> Color(0xFF92400E)
                                                            else -> Color(0xFF3730A3)
                                                        }
                                                    )
                                                }
                                                Spacer(modifier = Modifier.width(6.dp))
                                                Text(
                                                    text = todo.title,
                                                    fontWeight = FontWeight.Bold,
                                                    fontSize = 12.sp,
                                                    color = Color(0xFF1E293B)
                                                )
                                            }
                                            if (todo.description?.isNotEmpty() == true) {
                                                Text(
                                                    text = todo.description,
                                                    fontSize = 10.sp,
                                                    color = Color(0xFF64748B),
                                                    modifier = Modifier.padding(top = 2.dp)
                                                )
                                            }
                                        }

                                        Row(
                                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Box(
                                                modifier = Modifier
                                                    .background(
                                                        color = when (todo.status) {
                                                            "Completed" -> Color(0xFFD1FAE5)
                                                            "In Progress" -> Color(0xFFFEF3C7)
                                                            else -> Color(0xFFEEF2F6)
                                                        },
                                                        shape = RoundedCornerShape(6.dp)
                                                    )
                                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                                            ) {
                                                Text(
                                                    text = todo.status,
                                                    fontSize = 8.sp,
                                                    fontWeight = FontWeight.Bold,
                                                    color = when (todo.status) {
                                                        "Completed" -> Color(0xFF065F46)
                                                        "In Progress" -> Color(0xFF92400E)
                                                        else -> Color(0xFF64748B)
                                                    }
                                                )
                                            }
                                            
                                            if (todo.status == "Pending") {
                                                IconButton(
                                                    onClick = {
                                                        if (!isClockedIn) Toast.makeText(context, "Please clock in first.", Toast.LENGTH_SHORT).show()
                                                        else viewModel.updateTodoStatus(todo.id, "In Progress")
                                                    },
                                                    modifier = Modifier.size(24.dp)
                                                ) {
                                                    Icon(Icons.Default.PlayArrow, contentDescription = null, tint = Color(0xFF6366F1))
                                                }
                                            }
                                            
                                            if (todo.status != "Completed") {
                                                IconButton(
                                                    onClick = {
                                                        if (!isClockedIn) Toast.makeText(context, "Please clock in first.", Toast.LENGTH_SHORT).show()
                                                        else viewModel.updateTodoStatus(todo.id, "Completed")
                                                    },
                                                    modifier = Modifier.size(24.dp)
                                                ) {
                                                    Icon(Icons.Default.Check, contentDescription = null, tint = Color(0xFF10B981))
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                "Requirements" -> {
                    val requirements = selectedOrder.customerRequirements
                    
                    item {
                        // Sub Tab pills
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            listOf("Details", "Uploads", "Additional").forEach { rTab ->
                                val active = subTab == rTab
                                Box(
                                    modifier = Modifier
                                        .background(
                                            color = if (active) Color(0xFFEEF2F6) else Color.Transparent,
                                            shape = RoundedCornerShape(8.dp)
                                        )
                                        .clickable { subTab = rTab }
                                        .padding(horizontal = 10.dp, vertical = 6.dp)
                                ) {
                                    Text(
                                        text = rTab,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = if (active) Color(0xFF6366F1) else Color(0xFF64748B)
                                    )
                                }
                            }
                        }
                    }

                    // Query/Requirement Creation form in Additional Tab
                    if (subTab == "Additional") {
                        item {
                            var textInput by remember { mutableStateOf("") }
                            var typeInput by remember { mutableStateOf("Detail") } // 'Detail', 'Document'
                            
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(16.dp),
                                colors = CardDefaults.cardColors(containerColor = Color(0xFFFEF2F2)),
                                border = BorderStroke(1.dp, Color(0xFFFECACA))
                            ) {
                                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                    Text("Raise Query / Custom Requirement", fontSize = 11.sp, fontWeight = FontWeight.Black, color = Color(0xFF991B1B))
                                    
                                    OutlinedTextField(
                                        value = textInput,
                                        onValueChange = { textInput = it },
                                        placeholder = { Text("E.g. Upload clearer PAN card scan") },
                                        shape = RoundedCornerShape(10.dp),
                                        colors = OutlinedTextFieldDefaults.colors(
                                            focusedBorderColor = Color(0xFFEF4444)
                                        ),
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            FilterChip(
                                                selected = typeInput == "Detail",
                                                onClick = { typeInput = "Detail" },
                                                label = { Text("Text query", fontSize = 10.sp) }
                                            )
                                            FilterChip(
                                                selected = typeInput == "Document",
                                                onClick = { typeInput = "Document" },
                                                label = { Text("Require File", fontSize = 10.sp) }
                                            )
                                        }
                                        
                                        Button(
                                            onClick = {
                                                if (textInput.isNotBlank()) {
                                                    viewModel.raiseRequirement(selectedOrder.id, textInput, typeInput)
                                                    textInput = ""
                                                }
                                            },
                                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFEF4444)),
                                            shape = RoundedCornerShape(8.dp)
                                        ) {
                                            Text("Raise", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Requirements list matching subTab
                    val filteredReqs = when (subTab) {
                        "Details" -> requirements.filter { it.type == "Detail" && !it.isClientCompleted }
                        "Uploads" -> requirements.filter { it.type == "Document" && !it.isClientCompleted }
                        else -> requirements.filter { it.isClientCompleted || it.status != "Pending" }
                    }

                    if (filteredReqs.isEmpty()) {
                        item {
                            Text("No requirements registered.", fontSize = 12.sp, color = Color(0xFF94A3B8))
                        }
                    } else {
                        items(filteredReqs) { req ->
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(14.dp),
                                colors = CardDefaults.cardColors(containerColor = Color.White),
                                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                            ) {
                                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            text = req.title,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 12.sp,
                                            color = Color(0xFF1E293B),
                                            modifier = Modifier.weight(1f)
                                        )
                                        
                                        // Dropdown status editor
                                        var reqExpanded by remember { mutableStateOf(false) }
                                        Box {
                                            OutlinedButton(
                                                onClick = { reqExpanded = true },
                                                shape = RoundedCornerShape(8.dp),
                                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
                                                modifier = Modifier.height(28.dp)
                                            ) {
                                                Text(req.status, fontSize = 10.sp, fontWeight = FontWeight.Black)
                                                Icon(Icons.Default.ArrowDropDown, contentDescription = null, modifier = Modifier.size(12.dp))
                                            }
                                            DropdownMenu(
                                                expanded = reqExpanded,
                                                onDismissRequest = { reqExpanded = false }
                                            ) {
                                                listOf("Pending", "Received", "Verified", "Rejected").forEach { opt ->
                                                    DropdownMenuItem(
                                                        text = { Text(opt, fontSize = 12.sp) },
                                                        onClick = {
                                                            reqExpanded = false
                                                            viewModel.updateRequirementStatus(selectedOrder.id, req.id ?: "", opt)
                                                        }
                                                    )
                                                }
                                            }
                                        }
                                    }

                                    if (req.description.isNotEmpty()) {
                                        Text(req.description, fontSize = 10.sp, color = Color(0xFF64748B))
                                    }

                                    if (req.clientValue.isNotEmpty() || req.value.isNotEmpty()) {
                                        Text(
                                            text = "Client value: ${req.clientValue.ifEmpty { req.value }}",
                                            fontSize = 11.sp,
                                            color = Color(0xFF6366F1),
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
                
                "Overview" -> {
                    val formattedPrice = NumberFormat.getCurrencyInstance(Locale("en", "IN")).format(selectedOrder.price)
                    item {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(20.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                        ) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Text("Operational Overview", fontWeight = FontWeight.Black, fontSize = 14.sp, color = Color(0xFF1E293B))
                                Divider(color = Color(0xFFEEF2F6))
                                CommercialItemRow("Service Name", selectedOrder.serviceName)
                                CommercialItemRow("Target Package", selectedOrder.packageName.ifEmpty { "Basic Plan" })
                                CommercialItemRow("Quoted Value", formattedPrice)
                                CommercialItemRow("Workflow Milestone", selectedOrder.status)
                                CommercialItemRow("Deliverable Certificate", if (selectedOrder.finalCertificateUrl != null) "Ready & Uploaded" else "In Progress")
                                
                                if (selectedOrder.finalCertificateUrl != null) {
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text(
                                        text = "Delivered Certificate is available inside the Docs vault.",
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFF10B981)
                                    )
                                }
                            }
                        }
                    }
                }

                "Invoices" -> {
                    val invoices = selectedOrder.invoices
                    if (invoices.isEmpty()) {
                        item {
                            Text("No invoices mapped to this order.", fontSize = 12.sp, color = Color(0xFF64748B))
                        }
                    } else {
                        items(invoices) { invoice ->
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(16.dp),
                                colors = CardDefaults.cardColors(containerColor = Color.White),
                                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(14.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column {
                                        Text(
                                            text = invoice.invoiceNumber,
                                            fontWeight = FontWeight.Black,
                                            fontSize = 13.sp,
                                            color = Color(0xFF1E293B)
                                        )
                                        Text(
                                            text = NumberFormat.getCurrencyInstance(Locale("en", "IN")).format(invoice.amount),
                                            fontSize = 11.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = Color(0xFF6366F1),
                                            modifier = Modifier.padding(top = 2.dp)
                                        )
                                    }
                                    
                                    Box(
                                        modifier = Modifier
                                            .background(
                                                color = when (invoice.status) {
                                                    "Paid" -> Color(0xFFD1FAE5)
                                                    "Sent" -> Color(0xFFE0E7FF)
                                                    "Overdue" -> Color(0xFFFEE2E2)
                                                    else -> Color(0xFFEEF2F6)
                                                },
                                                shape = RoundedCornerShape(8.dp)
                                            )
                                            .padding(horizontal = 8.dp, vertical = 4.dp)
                                    ) {
                                        Text(
                                            text = invoice.status,
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Black,
                                            color = when (invoice.status) {
                                                "Paid" -> Color(0xFF065F46)
                                                "Sent" -> Color(0xFF3730A3)
                                                "Overdue" -> Color(0xFF991B1B)
                                                else -> Color(0xFF475569)
                                            }
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                "ToDo" -> {
                    val linkedTodos = todos.filter { it.orderId?.id == selectedOrder.id }
                    if (linkedTodos.isEmpty()) {
                        item {
                            Text("No operational standalone TODO tasks.", fontSize = 12.sp, color = Color(0xFF64748B))
                        }
                    } else {
                        items(linkedTodos) { todo ->
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(16.dp),
                                colors = CardDefaults.cardColors(containerColor = Color.White),
                                border = BorderStroke(1.dp, Color(0xFFEEF2F6))
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Box(
                                                modifier = Modifier
                                                    .background(
                                                        color = when (todo.priority) {
                                                            "Urgent" -> Color(0xFFFEE2E2)
                                                            "High" -> Color(0xFFFEF3C7)
                                                            else -> Color(0xFFE0E7FF)
                                                        },
                                                        shape = RoundedCornerShape(4.dp)
                                                    )
                                                    .padding(horizontal = 4.dp, vertical = 2.dp)
                                            ) {
                                                Text(
                                                    text = todo.priority,
                                                    fontSize = 7.sp,
                                                    fontWeight = FontWeight.Black,
                                                    color = when (todo.priority) {
                                                        "Urgent" -> Color(0xFF991B1B)
                                                        "High" -> Color(0xFF92400E)
                                                        else -> Color(0xFF3730A3)
                                                    }
                                                )
                                            }
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Text(
                                                text = todo.title,
                                                fontWeight = FontWeight.Bold,
                                                fontSize = 12.sp,
                                                color = Color(0xFF1E293B)
                                            )
                                        }
                                        if (todo.description?.isNotEmpty() == true) {
                                            Text(
                                                text = todo.description,
                                                fontSize = 10.sp,
                                                color = Color(0xFF64748B),
                                                modifier = Modifier.padding(top = 2.dp)
                                            )
                                        }
                                    }

                                    Row(
                                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Box(
                                            modifier = Modifier
                                                .background(
                                                    color = when (todo.status) {
                                                        "Completed" -> Color(0xFFD1FAE5)
                                                        "In Progress" -> Color(0xFFFEF3C7)
                                                        else -> Color(0xFFEEF2F6)
                                                    },
                                                    shape = RoundedCornerShape(6.dp)
                                                )
                                                .padding(horizontal = 6.dp, vertical = 2.dp)
                                        ) {
                                            Text(
                                                text = todo.status,
                                                fontSize = 8.sp,
                                                fontWeight = FontWeight.Bold,
                                                color = when (todo.status) {
                                                    "Completed" -> Color(0xFF065F46)
                                                    "In Progress" -> Color(0xFF92400E)
                                                    else -> Color(0xFF64748B)
                                                }
                                            )
                                        }
                                        
                                        if (todo.status == "Pending") {
                                            IconButton(
                                                onClick = {
                                                    if (!isClockedIn) Toast.makeText(context, "Please clock in first.", Toast.LENGTH_SHORT).show()
                                                    else viewModel.updateTodoStatus(todo.id, "In Progress")
                                                },
                                                modifier = Modifier.size(24.dp)
                                            ) {
                                                Icon(Icons.Default.PlayArrow, contentDescription = null, tint = Color(0xFF6366F1))
                                            }
                                        }
                                        
                                        if (todo.status != "Completed") {
                                            IconButton(
                                                onClick = {
                                                    if (!isClockedIn) Toast.makeText(context, "Please clock in first.", Toast.LENGTH_SHORT).show()
                                                    else viewModel.updateTodoStatus(todo.id, "Completed")
                                                },
                                                modifier = Modifier.size(24.dp)
                                            ) {
                                                Icon(Icons.Default.Check, contentDescription = null, tint = Color(0xFF10B981))
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                "Transactions" -> {
                    val formattedPrice = NumberFormat.getCurrencyInstance(Locale("en", "IN")).format(selectedOrder.price)
                    item {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(20.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                        ) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                Text(
                                    text = "Payments Snapshot",
                                    fontWeight = FontWeight.Black,
                                    fontSize = 15.sp,
                                    color = Color(0xFF1E293B)
                                )
                                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                    CommercialItemRow("Base Budget", formattedPrice)
                                    CommercialItemRow("Payment Status", selectedOrder.paymentStatus)
                                    CommercialItemRow("Razorpay Order ID", selectedOrder.razorpayOrderId.ifEmpty { "N/A" })
                                    CommercialItemRow("System Gateway Reference", selectedOrder.paymentId.ifEmpty { "N/A" })
                                }
                            }
                        }
                    }
                }

                "Activities" -> {
                    val logs = selectedOrder.activityHistory
                    if (logs.isEmpty()) {
                        item {
                            Text("No activities recorded yet.", fontSize = 12.sp, color = Color(0xFF64748B))
                        }
                    } else {
                        items(logs) { log ->
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(14.dp),
                                colors = CardDefaults.cardColors(containerColor = Color.White),
                                border = BorderStroke(1.dp, Color(0xFFEEF2F6))
                            ) {
                                Column(modifier = Modifier.padding(12.dp)) {
                                    Text(
                                        text = log.action.uppercase(),
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Black,
                                        color = Color(0xFF6366F1)
                                    )
                                    Text(
                                        text = log.description,
                                        fontSize = 12.sp,
                                        color = Color(0xFF1E293B),
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(top = 2.dp)
                                    )
                                    Text(
                                        text = log.createdAt,
                                        fontSize = 9.sp,
                                        color = Color(0xFF94A3B8),
                                        modifier = Modifier.padding(top = 4.dp)
                                    )
                                }
                            }
                        }
                    }
                }

                "Docs" -> {
                    val clientDocs = selectedOrder.clientDocuments
                    item {
                        Text("Operational Deliverables", fontSize = 11.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B))
                    }
                    if (selectedOrder.finalCertificateUrl != null) {
                        item {
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(14.dp),
                                colors = CardDefaults.cardColors(containerColor = Color(0xFFECFDF5)),
                                border = BorderStroke(1.dp, Color(0xFFA7F3D0))
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(Icons.Default.VerifiedUser, contentDescription = null, tint = Color(0xFF10B981))
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Column {
                                            Text("Final Deliverable Certificate", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF065F46))
                                            Text("Delivered to Client", fontSize = 10.sp, color = Color(0xFF047857))
                                        }
                                    }
                                    IconButton(onClick = {
                                        Toast.makeText(context, "Opening delivered document...", Toast.LENGTH_SHORT).show()
                                    }) {
                                        Icon(Icons.Default.OpenInNew, contentDescription = null, tint = Color(0xFF047857))
                                    }
                                }
                            }
                        }
                    } else {
                        item {
                            Text("No operational certificates delivered yet.", fontSize = 11.sp, color = Color(0xFF64748B))
                        }
                    }

                    item {
                        Text("Client Uploaded Documents", fontSize = 11.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B), modifier = Modifier.padding(top = 10.dp))
                    }

                    if (clientDocs.isEmpty()) {
                        item {
                            Text("No documents uploaded by client yet.", fontSize = 11.sp, color = Color(0xFF64748B))
                        }
                    } else {
                        items(clientDocs) { doc ->
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(14.dp),
                                colors = CardDefaults.cardColors(containerColor = Color.White),
                                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        modifier = Modifier.weight(1f)
                                    ) {
                                        Icon(Icons.Default.Description, contentDescription = null, tint = Color(0xFF64748B))
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Text(
                                            text = doc.name,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 12.sp,
                                            color = Color(0xFF1E293B)
                                        )
                                    }
                                    Box(
                                        modifier = Modifier
                                            .background(Color(0xFFECFDF5), RoundedCornerShape(8.dp))
                                            .padding(horizontal = 8.dp, vertical = 4.dp)
                                    ) {
                                        Text(
                                            text = "Uploaded",
                                            color = Color(0xFF065F46),
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Black
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }

            item {
                Spacer(modifier = Modifier.height(80.dp))
            }
        }
    } else {
        // --- QUEUE LIST VIEW ---
        var queueView by remember { mutableStateOf("orders") } // 'orders' or 'tasks'
        var queryText by remember { mutableStateOf("") }
        var selectedStatus by remember { mutableStateOf("All") }

        // Filter computations
        val filteredOrders = remember(orders, queryText, selectedStatus) {
            orders.filter {
                val textMatch = it.serviceName.contains(queryText, ignoreCase = true) ||
                        it.clientName.contains(queryText, ignoreCase = true) ||
                        it.packageName.contains(queryText, ignoreCase = true)
                val statusMatch = selectedStatus == "All" || it.status == selectedStatus
                textMatch && statusMatch
            }
        }

        val filteredTodos = remember(todos, queryText, selectedStatus) {
            todos.filter {
                val textMatch = it.title.contains(queryText, ignoreCase = true) ||
                        (it.description?.contains(queryText, ignoreCase = true) ?: false)
                val statusMatch = selectedStatus == "All" || it.status == selectedStatus
                textMatch && statusMatch
            }
        }

        val statuses = remember(queueView, orders, todos) {
            val src = if (queueView == "orders") orders.map { it.status } else todos.map { it.status }
            listOf("All") + src.distinct().filter { it.isNotEmpty() }
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        text = "Operations Work Queue",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF1E293B)
                    )
                    Text(
                        text = "Track and process your daily filings, projects, and todo tasks.",
                        fontSize = 12.sp,
                        color = Color(0xFF64748B)
                    )
                }
            }

            // Tab toggler: Orders vs Standalone Todos
            item {
                Row(
                    modifier = Modifier
                        .background(Color(0xFFEEF2F6), RoundedCornerShape(16.dp))
                        .padding(4.dp)
                        .fillMaxWidth()
                ) {
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .clip(RoundedCornerShape(12.dp))
                            .background(if (queueView == "orders") Color.White else Color.Transparent)
                            .clickable {
                                queueView = "orders"
                                selectedStatus = "All"
                            }
                            .padding(vertical = 10.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "Orders (${orders.size})",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Black,
                            color = if (queueView == "orders") Color(0xFF1E293B) else Color(0xFF64748B)
                        )
                    }
                    
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .clip(RoundedCornerShape(12.dp))
                            .background(if (queueView == "tasks") Color.White else Color.Transparent)
                            .clickable {
                                queueView = "tasks"
                                selectedStatus = "All"
                            }
                            .padding(vertical = 10.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "Tasks & TODOs (${todos.size})",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Black,
                            color = if (queueView == "tasks") Color(0xFF1E293B) else Color(0xFF64748B)
                        )
                    }
                }
            }

            // Search Bar & Filter dropdown
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = queryText,
                        onValueChange = { queryText = it },
                        placeholder = { Text("Search list...") },
                        leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = Color(0xFF94A3B8)) },
                        shape = RoundedCornerShape(14.dp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Color(0xFF6366F1),
                            unfocusedBorderColor = Color(0xFFE2E8F0)
                        ),
                        modifier = Modifier.weight(1f)
                    )

                    var statusFilterExpanded by remember { mutableStateOf(false) }
                    Box {
                        OutlinedButton(
                            onClick = { statusFilterExpanded = true },
                            shape = RoundedCornerShape(14.dp),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFF475569)),
                            modifier = Modifier.height(56.dp)
                        ) {
                            Text(selectedStatus, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            Icon(Icons.Default.FilterList, contentDescription = null, modifier = Modifier.padding(start = 4.dp))
                        }
                        DropdownMenu(
                            expanded = statusFilterExpanded,
                            onDismissRequest = { statusFilterExpanded = false }
                        ) {
                            statuses.forEach { item ->
                                DropdownMenuItem(
                                    text = { Text(item, fontSize = 12.sp) },
                                    onClick = {
                                        statusFilterExpanded = false
                                        selectedStatus = item
                                    }
                                )
                            }
                        }
                    }
                }
            }

            // Render Queue List
            if (queueView == "orders") {
                if (filteredOrders.isEmpty()) {
                    item {
                        Text("No orders matched the filters.", fontSize = 12.sp, color = Color(0xFF64748B))
                    }
                } else {
                    items(filteredOrders) { order ->
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onSelectOrder(order) },
                            shape = RoundedCornerShape(20.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                        ) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column {
                                        Text(
                                            text = order.clientName,
                                            fontWeight = FontWeight.Black,
                                            fontSize = 15.sp,
                                            color = Color(0xFF1E293B)
                                        )
                                        Text(
                                            text = order.serviceName,
                                            fontSize = 11.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = Color(0xFF64748B),
                                            modifier = Modifier.padding(top = 2.dp)
                                        )
                                    }
                                    
                                    Box(
                                        modifier = Modifier
                                            .background(Color(0xFFE0E7FF), RoundedCornerShape(8.dp))
                                            .padding(horizontal = 8.dp, vertical = 4.dp)
                                    ) {
                                        Text(
                                            text = "Manage",
                                            color = Color(0xFF3730A3),
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Black
                                        )
                                    }
                                }
                                
                                Divider(color = Color(0xFFF1F5F9))
                                
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = "Status: ${order.status}",
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFF0EA5E9)
                                    )
                                    
                                    Text(
                                        text = order.packageName.ifEmpty { "Default" },
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFF94A3B8)
                                    )
                                }
                            }
                        }
                    }
                }
            } else {
                if (filteredTodos.isEmpty()) {
                    item {
                        Text("No tasks found.", fontSize = 12.sp, color = Color(0xFF64748B))
                    }
                } else {
                    items(filteredTodos) { todo ->
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(20.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                        ) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.Top
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Box(
                                                modifier = Modifier
                                                    .background(
                                                        color = when (todo.priority) {
                                                            "Urgent" -> Color(0xFFFEE2E2)
                                                            "High" -> Color(0xFFFEF3C7)
                                                            else -> Color(0xFFE0E7FF)
                                                        },
                                                        shape = RoundedCornerShape(4.dp)
                                                    )
                                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                                            ) {
                                                Text(
                                                    text = todo.priority,
                                                    fontSize = 8.sp,
                                                    fontWeight = FontWeight.Black,
                                                    color = when (todo.priority) {
                                                        "Urgent" -> Color(0xFF991B1B)
                                                        "High" -> Color(0xFF92400E)
                                                        else -> Color(0xFF3730A3)
                                                    }
                                                )
                                            }
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Text(
                                                text = todo.title,
                                                fontWeight = FontWeight.Black,
                                                fontSize = 13.sp,
                                                color = Color(0xFF1E293B)
                                            )
                                        }
                                        
                                        if (todo.description?.isNotEmpty() == true) {
                                            Text(
                                                text = todo.description,
                                                fontSize = 11.sp,
                                                color = Color(0xFF64748B),
                                                modifier = Modifier.padding(top = 4.dp)
                                            )
                                        }
                                    }

                                    Box(
                                        modifier = Modifier
                                            .background(
                                                color = when (todo.status) {
                                                    "Completed" -> Color(0xFFD1FAE5)
                                                    "In Progress" -> Color(0xFFFEF3C7)
                                                    else -> Color(0xFFEEF2F6)
                                                },
                                                shape = RoundedCornerShape(8.dp)
                                            )
                                            .padding(horizontal = 8.dp, vertical = 4.dp)
                                    ) {
                                        Text(
                                            text = todo.status,
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Black,
                                            color = when (todo.status) {
                                                "Completed" -> Color(0xFF065F46)
                                                "In Progress" -> Color(0xFF92400E)
                                                else -> Color(0xFF64748B)
                                            }
                                        )
                                    }
                                }
                                
                                Divider(color = Color(0xFFF1F5F9))
                                
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    if (todo.orderId != null) {
                                        Text(
                                            text = "Linked Order: ${todo.orderId.serviceName}",
                                            fontSize = 10.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = Color(0xFF6366F1)
                                        )
                                    } else {
                                        Text(
                                            text = "Standalone Task",
                                            fontSize = 10.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = Color(0xFF94A3B8)
                                        )
                                    }
                                    
                                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                        if (todo.status == "Pending") {
                                            IconButton(
                                                onClick = {
                                                    if (!isClockedIn) Toast.makeText(context, "Please clock in first.", Toast.LENGTH_SHORT).show()
                                                    else viewModel.updateTodoStatus(todo.id, "In Progress")
                                                },
                                                modifier = Modifier.size(24.dp)
                                            ) {
                                                Icon(Icons.Default.PlayArrow, contentDescription = null, tint = Color(0xFF6366F1))
                                            }
                                        }
                                        if (todo.status != "Completed") {
                                            IconButton(
                                                onClick = {
                                                    if (!isClockedIn) Toast.makeText(context, "Please clock in first.", Toast.LENGTH_SHORT).show()
                                                    else viewModel.updateTodoStatus(todo.id, "Completed")
                                                },
                                                modifier = Modifier.size(24.dp)
                                            ) {
                                                Icon(Icons.Default.Check, contentDescription = null, tint = Color(0xFF10B981))
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            item {
                Spacer(modifier = Modifier.height(80.dp))
            }
        }
    }
}

@Composable
fun CommercialItemRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFFF8FAFC), RoundedCornerShape(10.dp))
            .padding(horizontal = 12.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(text = label, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
        Text(text = value, fontSize = 11.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
    }
}
