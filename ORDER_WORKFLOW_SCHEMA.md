# Order Workflow Schema and Import Formats

## Purpose
This document defines the current order-flow data model and import payload formats used by:
- Admin dashboard
- Employee dashboard
- Customer dashboard

It is updated for:
- Maker/Checker assignment model
- Parent task + sub task import
- Two-sheet requirement import (details + documents)
- Partial client save and requirement-level document upload

## Core Mongo Schema (`backend/models/Order.js`)

### Order-level assignment fields
- `assignedEmployee` (`ObjectId -> User`)
- `assignedMaker` (`ObjectId -> User`)
- `assignedChecker` (`ObjectId -> User`)

These assignments are visible in admin, and used by employee filtering in `GET /api/orders`.

### Tasks (`order.tasks[]`)
- `taskCode` (string)
- `title` (string)
- `description` (string)
- `status` (`Pending | In Progress | Completed`)
- `ownerRole` (string)
- `startTrigger` (string)
- `assignedTo` (`ObjectId -> User`)
- `assignedMaker` (`ObjectId -> User`)
- `assignedChecker` (`ObjectId -> User`)
- `sortOrder` (number)
- `subtasks[]`
  - `subTaskCode` (string)
  - `title` (string)
  - `status` (`Pending | In Progress | Completed`)
  - `isCompleted` (boolean)
  - `makerRole` (string)
  - `checkerRole` (string)
  - `assignedToMaker` (`ObjectId -> User`)
  - `assignedToChecker` (`ObjectId -> User`)
  - `duration` (string)
  - `dependency` (string)
  - `output` (string)
- `timeLogs[]` and `totalMinutes` for task-wise effort

### Customer Requirements (`order.customerRequirements[]`)
- `title` (string)
- `sheetName` (string)
- `category` (`Detail | Document`)
- `type` (`Detail | Document`)
- `itemCode` (string)
- `inputType` (string; e.g. `text`, `file`)
- `placeholder` (string)
- `options` (string[])
- `required` (boolean)
- `status` (`Pending | Received | Verified`)
- `description` (string)
- `value` (string)
- `clientValue` (string)
- `clientNotes` (string)
- `documentUrl` (string)
- `uploadedDocumentUrl` (string)
- `uploadedDocumentName` (string)
- `isClientCompleted` (boolean)
- `lastSavedAt` (Date)

## API Surface

### Order actions
- `PUT /api/orders/:id` (admin) update core order fields
- `DELETE /api/orders/:id` (admin) delete order
- `PUT /api/orders/:id/status` update status
- `PUT /api/orders/:id/assign` assign owner/maker/checker at order level

### Task and Subtask flow
- `POST /api/orders/:id/tasks/import`
  - Accepts structured payload:
    - `parentTasks[]`
    - `subTasks[]`
    - `replaceExisting` (boolean)
  - Also supports text fallback via `tasksText`
- `PUT /api/orders/:id/tasks/:taskId` update task status/details
- `PUT /api/orders/:id/tasks/:taskId/assign` assign task owner/maker/checker
- `PUT /api/orders/:id/tasks/:taskId/subtasks/:subtaskId` update subtask status/completion/assignment
- `POST /api/orders/:id/tasks/:taskId/time-log` write task time log entries

### Requirement flow
- `POST /api/orders/:id/requirements/import`
  - Structured payload:
    - `detailRows[]`
    - `documentRows[]`
    - `replaceExisting` (boolean)
  - Text fallback via `requirementsText`
- `PUT /api/orders/:id/requirements/:requirementId`
  - Client partial save:
    - `clientValue`, `clientNotes`, `isClientCompleted`
  - Admin/employee update:
    - `status`, `value`, `description`, etc.

### Requirement-specific file upload
- `POST /api/orders/:id/documents` with multipart:
  - `document` file
  - `requirementId` (optional)
- If `requirementId` is present, requirement is updated with:
  - `uploadedDocumentUrl`
  - `uploadedDocumentName`
  - `status = Received`
  - `isClientCompleted = true`

## Excel Import Formats

### Tasks Workbook
Expected sheets:
1. `Parent Tasks`
2. `Sub Tasks`

#### Parent Tasks columns
- `Task Code`
- `Main Task`
- `Description`
- `Owner (Checker)`
- `Start Trigger`
- `Status`

#### Sub Tasks columns
- `Task Code` (must map to parent)
- `Sub Task Code`
- `Sub Task Name`
- `Maker Role`
- `Checker Role`
- `Duration`
- `Dependency`
- `Output`

### Requirements Workbook
Expected: 2 sheets (sheet names flexible)

#### Sheet 1 (Client details)
Suggested columns:
- `Code`
- `Field Name`
- `Description`
- `Input Type`
- `Placeholder`
- `Required`
- `Options`

#### Sheet 2 (Documents)
Suggested columns:
- `Code`
- `Document Name`
- `Description`
- `Placeholder`
- `Required`

## Dashboard Sync Behavior
- Admin imports tasks/requirements -> persisted in `Order` document
- Employee dashboard reads same `Order` document and sees:
  - order/task/subtask assignments
  - requirement values/docs uploaded by client
- Customer dashboard reads same `Order` document and can:
  - partially save details
  - upload requirement documents
- Changes become visible across dashboards on next refresh/API fetch.
