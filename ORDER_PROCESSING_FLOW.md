# 3-Tier Role-Based Order Processing & Quality Audit Flow

## 1. 3-Tier Role Hierarchy & Permissions
1. **Project Manager (PM)**:
   - Primary operational contact for the order.
   - Imports and sets up checklists, documents, and customer requirements.
   - Assigns/reassigns Maker & Checker.
   - Has full visibility into invoices, financials, and has override capabilities.
2. **Maker (Work Execution)**:
   - Executes workflow tasks and sub-tasks once requirements & checklists are ready.
   - Submits completed work to the Checker for quality audit.
   - **Financial Isolation**: Has NO access to `Invoices`, `Transactions`, financial pricing, or payment/invoice logs under `Activities`.
3. **Checker (Quality Audit & Compliance)**:
   - Reviews and audits Maker's submission (`Approved` or `Changes Requested`).
   - If changes are requested, provides actionable notes for Maker to revise and re-submit.
   - **Financial Isolation**: Has NO access to `Invoices`, `Transactions`, financial pricing, or payment/invoice logs under `Activities`.
4. **Admin (Master Oversight)**:
   - Full access to assign PM/Maker/Checker, manage pricing/invoicing, review audit history, and perform overrides.

## 2. Order Processing Stages
1. **Intake & Conversion**: Order created with service package and assigned to PM.
2. **Setup (PM)**: PM imports customer requirements, checklists, and assigns Maker & Checker.
3. **Customer Submission**: Customer uploads requested documents into vault.
4. **Execution (Maker)**: Maker completes tasks and submits work for quality review.
5. **Quality Audit (Checker)**: Checker reviews deliverables $\rightarrow$ Marks `Approved` or `Changes Requested`.
6. **Finish & Deliver (Maker / PM)**: Once audit is `Approved by Checker` (or PM override), final certificate is uploaded and order moves to `Completed`.

