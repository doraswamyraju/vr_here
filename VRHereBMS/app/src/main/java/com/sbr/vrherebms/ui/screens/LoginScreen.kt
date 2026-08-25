package com.sbr.vrherebms.ui.screens

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.AuthState
import com.sbr.vrherebms.viewmodel.AuthViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LoginScreen(
    viewModel: AuthViewModel,
    onNavigateToRegister: () -> Unit,
    onLoginSuccess: (role: String) -> Unit
) {
    val context = LocalContext.current
    var passwordVisible by remember { mutableStateOf(false) }

    // Colors matching React Web view exactly
    val primaryRed = Color(0xFFC82323)
    val textDark = Color(0xFF1E293B)
    val textMuted = Color(0xFF64748B)
    val inputBackground = Color(0xFFEEF2F6)

    LaunchedEffect(key1 = viewModel.authState) {
        if (viewModel.authState is AuthState.Success) {
            val role = (viewModel.authState as AuthState.Success).role
            onLoginSuccess(role)
        }
    }

    LaunchedEffect(key1 = true) {
        viewModel.eventFlow.collect { event ->
            when (event) {
                is AuthViewModel.UiEvent.ShowToast -> {
                    Toast.makeText(context, event.message, Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.White)
            .padding(horizontal = 24.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding(),
            horizontalAlignment = Alignment.Start
        ) {
            Spacer(modifier = Modifier.height(40.dp))

            // 1. "VR HERE" Branding Header
            Column(
                modifier = Modifier.padding(vertical = 12.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "VR",
                        color = primaryRed,
                        fontSize = 24.sp,
                        fontWeight = FontWeight.Black
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = "HERE",
                        color = textDark,
                        fontSize = 24.sp,
                        fontWeight = FontWeight.Black
                    )
                }
                Text(
                    text = "Business Management Solutions",
                    color = textMuted,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 2.dp)
                )
            }

            Spacer(modifier = Modifier.height(44.dp))

            // 2. "Sign In" Title & Subtitle
            Text(
                text = "Sign In",
                fontSize = 36.sp,
                fontWeight = FontWeight.Bold,
                color = textDark
            )
            
            Spacer(modifier = Modifier.height(8.dp))
            
            Text(
                text = "Please enter your details to continue.",
                fontSize = 15.sp,
                color = textMuted
            )

            Spacer(modifier = Modifier.height(40.dp))

            // 3. Email Input
            Text(
                text = "Email Address",
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold,
                color = textDark,
                modifier = Modifier.padding(bottom = 8.dp)
            )
            TextField(
                value = viewModel.emailInput,
                onValueChange = { viewModel.emailInput = it },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Default.Email,
                        contentDescription = null,
                        tint = textMuted
                    )
                },
                placeholder = { Text("Email Address", color = textMuted) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
                shape = RoundedCornerShape(12.dp),
                colors = TextFieldDefaults.colors(
                    focusedContainerColor = inputBackground,
                    unfocusedContainerColor = inputBackground,
                    focusedIndicatorColor = Color.Transparent,
                    unfocusedIndicatorColor = Color.Transparent,
                    disabledIndicatorColor = Color.Transparent,
                    focusedTextColor = textDark,
                    unfocusedTextColor = textDark
                ),
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(20.dp))

            // 4. Password Input
            Text(
                text = "Password",
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold,
                color = textDark,
                modifier = Modifier.padding(bottom = 8.dp)
            )
            TextField(
                value = viewModel.passwordInput,
                onValueChange = { viewModel.passwordInput = it },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Default.Lock,
                        contentDescription = null,
                        tint = textMuted
                    )
                },
                placeholder = { Text("Password", color = textMuted) },
                trailingIcon = {
                    val image = if (passwordVisible) Icons.Default.Visibility else Icons.Default.VisibilityOff
                    IconButton(onClick = { passwordVisible = !passwordVisible }) {
                        Icon(image, contentDescription = null, tint = textMuted)
                    }
                },
                singleLine = true,
                visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                shape = RoundedCornerShape(12.dp),
                colors = TextFieldDefaults.colors(
                    focusedContainerColor = inputBackground,
                    unfocusedContainerColor = inputBackground,
                    focusedIndicatorColor = Color.Transparent,
                    unfocusedIndicatorColor = Color.Transparent,
                    disabledIndicatorColor = Color.Transparent,
                    focusedTextColor = textDark,
                    unfocusedTextColor = textDark
                ),
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(16.dp))

            // 5. Forgot Password
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End
            ) {
                Text(
                    text = "Forgot Password?",
                    color = primaryRed,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.clickable {
                        Toast.makeText(context, "Password reset link sent to your registered email.", Toast.LENGTH_SHORT).show()
                    }
                )
            }

            Spacer(modifier = Modifier.height(32.dp))

            // 6. Sign In Capsule Button
            Button(
                onClick = { viewModel.login() },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(54.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = primaryRed)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center,
                    modifier = Modifier.fillMaxSize()
                ) {
                    if (viewModel.authState is AuthState.Loading) {
                        CircularProgressIndicator(color = Color.White, modifier = Modifier.size(24.dp))
                    } else {
                        Text(
                            text = "Sign In",
                            color = Color.White,
                            fontWeight = FontWeight.Bold,
                            fontSize = 16.sp
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Divider OR
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp)
            ) {
                HorizontalDivider(modifier = Modifier.weight(1f), color = inputBackground)
                Text(
                    text = "  OR  ",
                    color = textMuted,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold
                )
                HorizontalDivider(modifier = Modifier.weight(1f), color = inputBackground)
            }

            Spacer(modifier = Modifier.height(16.dp))

            val webClientId = "167766774028-lrhfc69ubgv0po3kp9gup09cfvd82jlu.apps.googleusercontent.com"
            val googleSignInLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
                contract = androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()
            ) { result ->
                val task = com.google.android.gms.auth.api.signin.GoogleSignIn.getSignedInAccountFromIntent(result.data)
                try {
                    val account = task.getResult(com.google.android.gms.common.api.ApiException::class.java)
                    account?.idToken?.let { token ->
                        viewModel.googleLogin(token)
                    }
                } catch (e: Exception) {
                    Toast.makeText(context, "Google Sign-In: ${e.localizedMessage ?: "Failed"}", Toast.LENGTH_SHORT).show()
                }
            }

            OutlinedButton(
                onClick = {
                    val gso = com.google.android.gms.auth.api.signin.GoogleSignInOptions.Builder(
                        com.google.android.gms.auth.api.signin.GoogleSignInOptions.DEFAULT_SIGN_IN
                    )
                        .requestIdToken(webClientId)
                        .requestEmail()
                        .build()
                    val googleSignInClient = com.google.android.gms.auth.api.signin.GoogleSignIn.getClient(context, gso)
                    googleSignInLauncher.launch(googleSignInClient.signInIntent)
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(54.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = textDark),
                border = androidx.compose.foundation.BorderStroke(1.dp, inputBackground)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center
                ) {
                    Text(
                        text = "G ",
                        color = primaryRed,
                        fontWeight = FontWeight.Black,
                        fontSize = 20.sp
                    )
                    Text(
                        text = "Continue with Google",
                        color = textDark,
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp
                    )
                }
            }

            Spacer(modifier = Modifier.weight(1f))

            // 7. Footer: Sign Up
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 24.dp),
                horizontalArrangement = Arrangement.Center,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Don't have an account? ",
                    color = textMuted,
                    fontSize = 14.sp
                )
                Text(
                    text = "Sign Up",
                    color = primaryRed,
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp,
                    modifier = Modifier.clickable { onNavigateToRegister() }
                )
            }
        }
    }
}
