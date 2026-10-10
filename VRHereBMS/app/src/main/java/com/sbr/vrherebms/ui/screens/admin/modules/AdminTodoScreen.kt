package com.sbr.vrherebms.ui.screens.admin.modules

import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.sbr.vrherebms.data.model.CreateTodoRequest
import com.sbr.vrherebms.data.model.TodoResponse
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminTodoScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var searchQuery by remember { mutableStateOf("") }
    var selectedStatusFilter by remember { mutableStateOf("All") }
    var selectedPriorityFilter by remember { mutableStateOf("All") }
    var showCreateModal by remember { mutableStateOf(false) }

    val statuses = listOf("All", "Pending", "In Progress", "Completed")
    val priorities = listOf("All", "High", "Medium", "Low")

    // Filter todos dynamically
    val filteredTodos = adminViewModel.todos.filter { todo ->
        val q = searchQuery.trim().lowercase()
        val matchesSearch = q.isEmpty() ||
                todo.title.lowercase().contains(q) ||
                (todo.description?.lowercase()?.contains(q) == true) ||
                (todo.assignedTo?.name?.lowercase()?.contains(q) == true)

        val matchesStatus = when (selectedStatusFilter) {
            "All" -> true
            "Completed" -> todo.status.equals("Completed", ignoreCase = true)
            "In Progress" -> todo.status.equals("In Progress", ignoreCase = true)
            "Pending" -> !todo.status.equals("Completed", ignoreCase = true) && !todo.status.equals("In Progress", ignoreCase = true)
            else -> todo.status.equals(selectedStatusFilter, ignoreCase = true)
        }

        val matchesPriority = if (selectedPriorityFilter == "All") true else todo.priority.equals(selectedPriorityFilter, ignoreCase = true)

        matchesSearch && matchesStatus && matchesPriority
    }

    val totalCount = adminViewModel.todos.size
    val completedCount = adminViewModel.todos.count { it.status.equals("Completed", ignoreCase = true) }
    val pendingCount = totalCount - completedCount

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF1F5F9))
            .padding(horizontal = 16.dp, vertical = 12.dp)
    ) {
        // 1. Header Banner with Metrics & Quick Add
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A))
        ) {
            Column(modifier = Modifier.padding(18.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "TASK COMMAND CENTER",
                            color = Color(0xFF38BDF8),
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Black,
                            letterSpacing = 1.sp
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = "Tasks & Operations",
                            color = Color.White,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Black
                        )
                    }

                    Button(
                        onClick = { showCreateModal = true },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                        shape = RoundedCornerShape(12.dp),
                        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 8.dp)
                    ) {
                        Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(16.dp), tint = Color.White)
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Add Task", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color.White)
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                // Metrics Row
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    MetricMiniCard(title = "TOTAL", count = "$totalCount", color = Color(0xFF94A3B8), modifier = Modifier.weight(1f))
                    MetricMiniCard(title = "PENDING", count = "$pendingCount", color = Color(0xFFF59E0B), modifier = Modifier.weight(1f))
                    MetricMiniCard(title = "COMPLETED", count = "$completedCount", color = Color(0xFF10B981), modifier = Modifier.weight(1f))
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // 2. Search Box
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            placeholder = { Text("Search task lists or assignees...", fontSize = 13.sp, color = Color(0xFF94A3B8)) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = "Search", tint = Color(0xFF64748B)) },
            trailingIcon = {
                if (searchQuery.isNotEmpty()) {
                    IconButton(onClick = { searchQuery = "" }) {
                        Icon(Icons.Default.Close, contentDescription = "Clear", tint = Color(0xFF94A3B8))
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedContainerColor = Color.White,
                unfocusedContainerColor = Color.White,
                focusedBorderColor = Color(0xFF6366F1),
                unfocusedBorderColor = Color(0xFFE2E8F0)
            ),
            singleLine = true
        )

        Spacer(modifier = Modifier.height(10.dp))

        // 3. Status Filters (Horizontally Scrollable)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            statuses.forEach { st ->
                val isSelected = selectedStatusFilter == st
                val bg = if (isSelected) Color(0xFF0F172A) else Color.White
                val textColor = if (isSelected) Color.White else Color(0xFF475569)
                val border = if (isSelected) Color.Transparent else Color(0xFFE2E8F0)

                Box(
                    modifier = Modifier
                        .background(bg, RoundedCornerShape(20.dp))
                        .clickable { selectedStatusFilter = st }
                        .border(1.dp, border, RoundedCornerShape(20.dp))
                        .padding(horizontal = 14.dp, vertical = 7.dp)
                ) {
                    Text(
                        text = st,
                        color = textColor,
                        fontSize = 11.sp,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // 4. Priority Filters (Horizontally Scrollable)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            priorities.forEach { level ->
                val isSelected = selectedPriorityFilter == level
                val bg = if (isSelected) Color(0xFF6366F1) else Color.White
                val textColor = if (isSelected) Color.White else Color(0xFF475569)
                val border = if (isSelected) Color.Transparent else Color(0xFFE2E8F0)

                Box(
                    modifier = Modifier
                        .background(bg, RoundedCornerShape(20.dp))
                        .clickable { selectedPriorityFilter = level }
                        .border(1.dp, border, RoundedCornerShape(20.dp))
                        .padding(horizontal = 14.dp, vertical = 7.dp)
                ) {
                    Text(
                        text = if (level == "All") "All Priority" else "$level Priority",
                        color = textColor,
                        fontSize = 11.sp,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // 5. To-Do Cards List
        if (filteredTodos.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.PlaylistAddCheck,
                        contentDescription = null,
                        tint = Color(0xFF94A3B8),
                        modifier = Modifier.size(56.dp)
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text("No tasks found matching filter.", color = Color(0xFF1E293B), fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    Text("Try adjusting the search query or priority filter.", color = Color(0xFF64748B), fontSize = 12.sp)
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(filteredTodos, key = { it.id }) { todo ->
                    val isDone = todo.status.equals("Completed", ignoreCase = true)

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, if (isDone) Color(0xFFE2E8F0) else Color(0xFFE2E8F0).copy(alpha = 0.8f)),
                        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                verticalAlignment = Alignment.Top,
                                horizontalArrangement = Arrangement.spacedBy(12.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                // Status Checkbox that persists
                                IconButton(
                                    onClick = {
                                        val newStatus = if (isDone) "Pending" else "Completed"
                                        adminViewModel.updateTodoStatus(todo.id, newStatus)
                                    },
                                    modifier = Modifier.size(28.dp)
                                ) {
                                    Icon(
                                        imageVector = if (isDone) Icons.Default.CheckCircle else Icons.Default.RadioButtonUnchecked,
                                        contentDescription = null,
                                        tint = if (isDone) Color(0xFF10B981) else Color(0xFF94A3B8),
                                        modifier = Modifier.size(24.dp)
                                    )
                                }

                                // Task Details
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = todo.title,
                                        fontSize = 14.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = if (isDone) Color(0xFF94A3B8) else Color(0xFF1E293B),
                                        textDecoration = if (isDone) TextDecoration.LineThrough else TextDecoration.None
                                    )

                                    if (!todo.description.isNullOrBlank()) {
                                        Spacer(modifier = Modifier.height(4.dp))
                                        Text(
                                            text = todo.description,
                                            fontSize = 12.sp,
                                            color = Color(0xFF64748B),
                                            maxLines = 2,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }

                                    // Linked Order Pill
                                    todo.orderId?.id?.let { orderRef ->
                                        if (orderRef.isNotBlank()) {
                                            Spacer(modifier = Modifier.height(6.dp))
                                            Surface(
                                                color = Color(0xFF6366F1).copy(alpha = 0.08f),
                                                shape = RoundedCornerShape(6.dp)
                                            ) {
                                                Row(
                                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                                    verticalAlignment = Alignment.CenterVertically,
                                                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                                                ) {
                                                    Icon(Icons.Default.Layers, contentDescription = null, tint = Color(0xFF6366F1), modifier = Modifier.size(10.dp))
                                                    Text("Order #${orderRef.takeLast(6)}", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFF6366F1))
                                                }
                                            }
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(10.dp))

                                    // Bottom row with Assignee, Priority Pill, Status & Delete
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        // Assignee
                                        val assigneeName = todo.assignedTo?.name ?: "General Team"
                                        Row(
                                            verticalAlignment = Alignment.CenterVertically,
                                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                                        ) {
                                            Icon(
                                                Icons.Default.AccountCircle,
                                                contentDescription = null,
                                                tint = Color(0xFF64748B),
                                                modifier = Modifier.size(14.dp)
                                            )
                                            Text(
                                                text = assigneeName,
                                                color = Color(0xFF64748B),
                                                fontSize = 11.sp,
                                                fontWeight = FontWeight.Medium,
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis
                                            )
                                        }

                                        // Badges row
                                        Row(
                                            verticalAlignment = Alignment.CenterVertically,
                                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                                        ) {
                                            // Priority Pill
                                            val (pillBg, pillColor) = when (todo.priority.lowercase()) {
                                                "high" -> Pair(Color(0xFFFEE2E2), Color(0xFFDC2626))
                                                "medium" -> Pair(Color(0xFFFEF3C7), Color(0xFFD97706))
                                                else -> Pair(Color(0xFFECFDF5), Color(0xFF16A34A))
                                            }
                                            Box(
                                                modifier = Modifier
                                                    .background(pillBg, RoundedCornerShape(6.dp))
                                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                                            ) {
                                                Text(
                                                    text = todo.priority.uppercase(),
                                                    color = pillColor,
                                                    fontSize = 9.sp,
                                                    fontWeight = FontWeight.ExtraBold
                                                )
                                            }

                                            // Delete Task
                                            IconButton(
                                                onClick = { adminViewModel.deleteTodo(todo.id) },
                                                modifier = Modifier.size(24.dp)
                                            ) {
                                                Icon(
                                                    Icons.Default.DeleteOutline,
                                                    contentDescription = "Delete",
                                                    tint = Color(0xFF94A3B8),
                                                    modifier = Modifier.size(16.dp)
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Bottom spacer to clear bottom navigation dock and floating elements
                item {
                    Spacer(modifier = Modifier.height(90.dp))
                }
            }
        }
    }

    // Create Task Modal Dialog
    if (showCreateModal) {
        CreateTaskDialog(
            adminViewModel = adminViewModel,
            onDismiss = { showCreateModal = false }
        )
    }
}

@Composable
private fun MetricMiniCard(
    title: String,
    count: String,
    color: Color,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier,
        color = Color.White.copy(alpha = 0.08f),
        shape = RoundedCornerShape(10.dp)
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(text = title, fontSize = 9.sp, fontWeight = FontWeight.Bold, color = Color(0xFF94A3B8))
            Text(text = count, fontSize = 16.sp, fontWeight = FontWeight.Black, color = color)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun CreateTaskDialog(
    adminViewModel: AdminDashboardViewModel,
    onDismiss: () -> Unit
) {
    var title by remember { mutableStateOf("") }
    var description by remember { mutableStateOf("") }
    var selectedPriority by remember { mutableStateOf("Medium") }
    var selectedAssigneeId by remember { mutableStateOf("") }
    var selectedOrderId by remember { mutableStateOf("") }
    var isSubmitting by remember { mutableStateOf(false) }

    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(8.dp),
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White)
        ) {
            Column(
                modifier = Modifier
                    .padding(20.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Create New Task", fontSize = 17.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = "Close", tint = Color(0xFF64748B))
                    }
                }

                // Title
                OutlinedTextField(
                    value = title,
                    onValueChange = { title = it },
                    label = { Text("Task Title *") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    singleLine = true
                )

                // Description
                OutlinedTextField(
                    value = description,
                    onValueChange = { description = it },
                    label = { Text("Description (Optional)") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    minLines = 2,
                    maxLines = 4
                )

                // Priority Selection
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Priority", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF475569))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        listOf("Low", "Medium", "High").forEach { p ->
                            val isSelected = selectedPriority == p
                            val (bg, textColor) = when {
                                isSelected && p == "High" -> Pair(Color(0xFFDC2626), Color.White)
                                isSelected && p == "Medium" -> Pair(Color(0xFFD97706), Color.White)
                                isSelected && p == "Low" -> Pair(Color(0xFF16A34A), Color.White)
                                else -> Pair(Color(0xFFF1F5F9), Color(0xFF475569))
                            }
                            Box(
                                modifier = Modifier
                                    .weight(1f)
                                    .background(bg, RoundedCornerShape(10.dp))
                                    .clickable { selectedPriority = p }
                                    .padding(vertical = 10.dp),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(p, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = textColor)
                            }
                        }
                    }
                }

                // Submit Button
                Button(
                    onClick = {
                        if (title.isBlank()) return@Button
                        isSubmitting = true
                        val req = CreateTodoRequest(
                            title = title.trim(),
                            description = if (description.isBlank()) null else description.trim(),
                            priority = selectedPriority,
                            assignedTo = if (selectedAssigneeId.isBlank()) null else selectedAssigneeId,
                            orderId = if (selectedOrderId.isBlank()) null else selectedOrderId
                        )
                        adminViewModel.createTodo(req) { success ->
                            isSubmitting = false
                            if (success) onDismiss()
                        }
                    },
                    enabled = title.isNotBlank() && !isSubmitting,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                    shape = RoundedCornerShape(12.dp),
                    contentPadding = PaddingValues(vertical = 14.dp)
                ) {
                    if (isSubmitting) {
                        CircularProgressIndicator(color = Color.White, modifier = Modifier.size(18.dp))
                    } else {
                        Text("Create Task", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = Color.White)
                    }
                }
            }
        }
    }
}
