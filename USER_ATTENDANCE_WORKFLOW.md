# Admin Users and Attendance Workflow

## Overview
This module adds:
- Admin-managed user lifecycle
- Password setup email onboarding
- Server-side attendance (clock in/out)
- Admin time analytics (worked vs task-tracked time)

## User Management (Admin)

### New APIs
- `POST /api/auth/users`
  - Create user (`name`, `email`, `phone`, `role`)
  - Generates temporary password internally
  - Sends password setup link by email
- `PUT /api/auth/users/:id`
  - Update `name`, `email`, `phone`, `role`, `isActive`
- `PATCH /api/auth/users/:id/toggle-active`
  - Activate/deactivate user (soft toggle)
- `POST /api/auth/users/:id/send-password-link`
  - Resend set/reset password email

### Existing list APIs
- `GET /api/auth/users`
- `GET /api/auth/employees`
  - Default now returns active employees (for assignment dropdowns)
  - `?includeInactive=true` supported

## Password Setup Email Flow

1. Admin creates user
2. Backend generates reset token (`resetPasswordToken`, `resetPasswordExpire`)
3. Email sent with link:
   - `${FRONTEND_URL}/reset-password/:token`
4. User sets password
5. Account becomes active for login

Config:
- `FRONTEND_URL` (fallback: `https://vrhere.in`)
- SMTP vars already used by `sendEmail`

## User Schema Changes (`backend/models/User.js`)
- Added `isActive: Boolean (default true)`

Login now blocks inactive accounts with clear error.

## Attendance Tracking

### Model (`backend/models/Attendance.js`)
- `employee` (User ref)
- `clockInAt`
- `clockOutAt`
- `totalSeconds`
- `dateKey`
- `source`
- `notes`

### APIs (`/api/attendance`)
- `POST /clock-in`
- `POST /clock-out`
- `GET /my-status`
- `GET /my-logs`
- `GET /admin/summary` (admin only)

## Admin Time Analytics Logic

`GET /api/attendance/admin/summary` returns per-employee:
- `workedSeconds` (attendance sessions)
- `trackedMinutes` (sum of `Order.tasks.timeLogs`)
- `untrackedMinutes = workedMinutes - trackedMinutes`
- `productivityPercent = tracked/worked`
- `trackedByOrder` map

## Frontend Modular Structure

### Admin Users Modules
- `frontend/components/admin/users/AddUserForm.jsx`
- `frontend/components/admin/users/UsersTable.jsx`
- `frontend/components/admin/users/WorkloadPanel.jsx`
- `frontend/components/admin/users/AssignmentPreview.jsx`
- `frontend/components/admin/users/UsersModule.jsx`

### Employee dashboard attendance sync
- `frontend/employee.jsx`
  - Clock in/out now persisted via backend APIs
  - Shift timer hydrates from `/api/attendance/my-status`

## Assignment and Staffing Behavior
- Only active employees are used for new assignment dropdowns.
- Deactivation does not erase historical assignments.
- Assignment preview in Admin Users shows order/task mapping for selected employee.
