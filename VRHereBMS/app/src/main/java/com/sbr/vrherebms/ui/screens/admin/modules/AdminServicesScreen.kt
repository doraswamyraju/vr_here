package com.sbr.vrherebms.ui.screens.admin.modules

import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog

data class AdminServiceItem(
    val id: String,
    val name: String,
    val category: String,
    var price: Double,
    var isActive: Boolean = true,
    val packageName: String = "Standard Plan"
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminServicesScreen(
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var searchQuery by remember { mutableStateOf("") }
    var selectedCategoryFilter by remember { mutableStateOf("All") }
    var showAddServiceDialog by remember { mutableStateOf(false) }

    // Hardcoded initial list of services based on Customer Services Tab
    var servicesList by remember {
        mutableStateOf(
            listOf(
                AdminServiceItem("1", "Private Limited Company Registration", "Registrations", 6999.0),
                AdminServiceItem("2", "GST Registration", "Registrations", 1499.0),
                AdminServiceItem("3", "MSME / Udyam Registration", "Registrations", 999.0),
                AdminServiceItem("4", "Trademark Registration", "Registrations", 4499.0),
                AdminServiceItem("5", "GST Return Filing (Monthly/Quarterly)", "Taxation", 999.0),
                AdminServiceItem("6", "Income Tax Return Filing", "Taxation", 1999.0),
                AdminServiceItem("7", "Company Annual Compliances", "Taxation", 14999.0),
                AdminServiceItem("8", "ISO 9001:2015 Certification", "Quality Certs", 3499.0),
                AdminServiceItem("9", "ISO 27001:2022 Certification", "Quality Certs", 12999.0),
                AdminServiceItem("10", "FSSAI License (Food Safety)", "Licensing", 2999.0),
                AdminServiceItem("11", "IEC (Import Export Code)", "Licensing", 1999.0),
                AdminServiceItem("12", "APEDA Registration", "Licensing", 7999.0)
            )
        )
    }

    val categories = listOf("All", "Registrations", "Taxation", "Quality Certs", "Licensing")

    // Filter services dynamically
    val filteredServices = servicesList.filter { s ->
        val matchesSearch = s.name.contains(searchQuery, ignoreCase = true)
        val matchesCategory = if (selectedCategoryFilter == "All") true else s.category == selectedCategoryFilter
        matchesSearch && matchesCategory
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF1F5F9))
            .padding(16.dp)
    ) {
        // 1. Top Search and Add Row
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text("Search services master...", fontSize = 13.sp) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = Color(0xFF64748B), modifier = Modifier.size(16.dp)) },
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(10.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = Color(0xFF4F46E5),
                    unfocusedBorderColor = Color(0xFFE2E8F0)
                ),
                singleLine = true
            )

            Button(
                onClick = { showAddServiceDialog = true },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                shape = RoundedCornerShape(10.dp),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 10.dp)
            ) {
                Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(4.dp))
                Text("Service", fontSize = 12.sp, fontWeight = FontWeight.Bold)
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // 2. Category Tabs scrollable chip row
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            categories.forEach { cat ->
                val isSelected = selectedCategoryFilter == cat
                val bg = if (isSelected) Color(0xFF4F46E5) else Color.White
                val textColor = if (isSelected) Color.White else Color(0xFF64748B)

                Box(
                    modifier = Modifier
                        .background(bg, RoundedCornerShape(20.dp))
                        .clickable { selectedCategoryFilter = cat }
                        .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(20.dp))
                        .padding(horizontal = 12.dp, vertical = 8.dp)
                ) {
                    Text(cat, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = textColor)
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 3. List of Services
        if (filteredServices.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.ProductionQuantityLimits,
                        contentDescription = null,
                        tint = Color(0xFF94A3B8),
                        modifier = Modifier.size(64.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text("No services configured under this category.", color = Color(0xFF64748B), fontSize = 14.sp)
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(filteredServices) { service ->
                    var isEditingPrice by remember { mutableStateOf(false) }
                    var editedPriceText by remember { mutableStateOf(service.price.toInt().toString()) }

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFEEF2F6))
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            // Category Badge & Active Toggle Switch
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Box(
                                    modifier = Modifier
                                        .background(Color(0xFFEEF2F6), RoundedCornerShape(6.dp))
                                        .padding(horizontal = 8.dp, vertical = 2.dp)
                                ) {
                                    Text(
                                        text = service.category.uppercase(),
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.ExtraBold,
                                        color = Color(0xFF64748B)
                                    )
                                }

                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    Text(
                                        text = if (service.isActive) "ACTIVE" else "DISABLED",
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Black,
                                        color = if (service.isActive) Color(0xFF10B981) else Color(0xFFEF4444)
                                    )
                                    Switch(
                                        checked = service.isActive,
                                        onCheckedChange = { checked ->
                                            servicesList = servicesList.map {
                                                if (it.id == service.id) it.copy(isActive = checked) else it
                                            }
                                            Toast.makeText(context, "${service.name} status updated!", Toast.LENGTH_SHORT).show()
                                        },
                                        modifier = Modifier.scale(0.6f)
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(8.dp))

                            // Service Name
                            Text(
                                text = service.name,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF1E293B)
                            )

                            Spacer(modifier = Modifier.height(10.dp))
                            Divider(color = Color(0xFFF1F5F9))
                            Spacer(modifier = Modifier.height(10.dp))

                            // Pricing & Price Editor Form
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                if (isEditingPrice) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        OutlinedTextField(
                                            value = editedPriceText,
                                            onValueChange = { editedPriceText = it },
                                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                            modifier = Modifier.width(100.dp),
                                            singleLine = true,
                                            textStyle = androidx.compose.ui.text.TextStyle(fontSize = 12.sp)
                                        )
                                        IconButton(onClick = {
                                            val newPrice = editedPriceText.toDoubleOrNull()
                                            if (newPrice != null) {
                                                servicesList = servicesList.map {
                                                    if (it.id == service.id) it.copy(price = newPrice) else it
                                                }
                                                isEditingPrice = false
                                                Toast.makeText(context, "Price updated successfully!", Toast.LENGTH_SHORT).show()
                                            } else {
                                                Toast.makeText(context, "Please enter a valid price.", Toast.LENGTH_SHORT).show()
                                            }
                                        }) {
                                            Icon(Icons.Default.Check, contentDescription = null, tint = Color(0xFF10B981))
                                        }
                                    }
                                } else {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                                    ) {
                                        Text(
                                            text = "Rs. %,.0f".format(service.price),
                                            fontWeight = FontWeight.Black,
                                            fontSize = 15.sp,
                                            color = Color(0xFF4F46E5)
                                        )
                                        IconButton(onClick = { isEditingPrice = true }) {
                                            Icon(Icons.Default.Edit, contentDescription = null, tint = Color(0xFF94A3B8), modifier = Modifier.size(16.dp))
                                        }
                                    }
                                }

                                Row(
                                    modifier = Modifier.clickable {
                                        servicesList = servicesList.filter { it.id != service.id }
                                        Toast.makeText(context, "${service.name} deleted from master catalog.", Toast.LENGTH_SHORT).show()
                                    },
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    Icon(Icons.Default.Delete, contentDescription = null, tint = Color(0xFFEF4444), modifier = Modifier.size(14.dp))
                                    Text("Remove", color = Color(0xFFEF4444), fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 4. Add Service Dialog
    if (showAddServiceDialog) {
        var newName by remember { mutableStateOf("") }
        var newCategory by remember { mutableStateOf("Registrations") }
        var newPriceText by remember { mutableStateOf("") }
        var expandedCat by remember { mutableStateOf(false) }

        Dialog(onDismissRequest = { showAddServiceDialog = false }) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(8.dp),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    Text("Add Master Service", fontSize = 18.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))

                    OutlinedTextField(
                        value = newName,
                        onValueChange = { newName = it },
                        label = { Text("Service Description/Name") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp)
                    )

                    // Category Dropdown
                    Box(modifier = Modifier.fillMaxWidth()) {
                        OutlinedTextField(
                            value = newCategory,
                            onValueChange = {},
                            readOnly = true,
                            label = { Text("Service Group") },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(10.dp),
                            trailingIcon = {
                                IconButton(onClick = { expandedCat = true }) {
                                    Icon(Icons.Default.ArrowDropDown, contentDescription = null)
                                }
                            }
                        )
                        DropdownMenu(
                            expanded = expandedCat,
                            onDismissRequest = { expandedCat = false }
                        ) {
                            categories.filter { it != "All" }.forEach { cat ->
                                DropdownMenuItem(
                                    text = { Text(cat) },
                                    onClick = {
                                        newCategory = cat
                                        expandedCat = false
                                    }
                                )
                            }
                        }
                    }

                    OutlinedTextField(
                        value = newPriceText,
                        onValueChange = { newPriceText = it },
                        label = { Text("Service Price (INR)") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        TextButton(onClick = { showAddServiceDialog = false }) {
                            Text("Cancel", color = Color(0xFF64748B))
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Button(
                            onClick = {
                                val priceVal = newPriceText.toDoubleOrNull()
                                if (newName.isBlank() || priceVal == null) {
                                    Toast.makeText(context, "Please fill all fields with correct pricing", Toast.LENGTH_SHORT).show()
                                    return@Button
                                }
                                val newId = (servicesList.size + 1).toString()
                                val newService = AdminServiceItem(newId, newName, newCategory, priceVal)
                                servicesList = servicesList + newService
                                showAddServiceDialog = false
                                Toast.makeText(context, "New master service configured successfully!", Toast.LENGTH_LONG).show()
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981)),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text("Add Config", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }
    }
}

// Extension extension for Compose Switch scaling
@Composable
private fun Modifier.scale(scale: Float): Modifier = this.then(
    Modifier.graphicsLayer(scaleX = scale, scaleY = scale)
)
