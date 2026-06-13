import Razorpay from 'razorpay';
import sendEmail from './sendEmail.js';
import { logOrderActivity } from './activityLogger.js';
import User from '../models/User.js';

/**
 * Helper to generate an invoice, calculate adjustments/splits, generate Razorpay links, and notify client + admins.
 */
export const generateAndEmailInvoice = async (order, baseAmount, options = {}) => {
    const {
        invoiceNumber,
        adjustConsultation = false,
        adjustPreviousAmount = false,
        splitPercentage = null,
        dueDate = null,
        notes = '',
        status = null,
        actorId = null
    } = options;

    let finalAmount = Number(baseAmount);
    if (!Number.isFinite(finalAmount) || finalAmount < 0) {
        throw new Error('Amount must be a positive number');
    }

    // 1. Consultation 499 adjustment
    if (adjustConsultation) {
        if (order.consultationAdjusted) {
            throw new Error('Consultation adjustment has already been applied to this order');
        }
        finalAmount = Math.max(0, finalAmount - 499);
        order.consultationAdjusted = true;
    }

    // 2. Adjust previous invoices
    if (adjustPreviousAmount) {
        const previousInvoicesTotal = (order.invoices || []).reduce((sum, inv) => sum + Number(inv.amount || 0), 0);
        finalAmount = Math.max(0, finalAmount - previousInvoicesTotal);
    }

    // 3. Handle split payments
    const isSplit = splitPercentage && Number(splitPercentage) > 0 && Number(splitPercentage) < 100;
    const splitPercentVal = isSplit ? Number(splitPercentage) : 100;
    const firstInvoiceAmount = isSplit ? Math.round(finalAmount * (splitPercentVal / 100)) : finalAmount;
    const secondInvoiceAmount = finalAmount - firstInvoiceAmount;

    const finalInvoiceNumber = invoiceNumber || `INV_${Date.now()}`;
    const invoiceStatus = status || 'Sent';

    let paymentLinkUrl = '';

    // Generate Razorpay Link if unpaid
    if (invoiceStatus !== 'Paid' && firstInvoiceAmount > 0) {
        const keyId = process.env.RAZORPAY_KEY_ID;
        const keySecret = process.env.RAZORPAY_KEY_SECRET;
        if (keyId && keySecret) {
            try {
                const razorpay = new Razorpay({
                    key_id: keyId,
                    key_secret: keySecret
                });
                const linkPayload = {
                    amount: Math.round(firstInvoiceAmount * 100),
                    currency: 'INR',
                    accept_partial: false,
                    description: `Payment for Service: ${order.serviceName} (${order.packageName})${isSplit ? ` - Milestone 1 (${splitPercentVal}%)` : ''}`,
                    customer: {
                        name: order.clientName || 'Customer',
                        email: order.email || 'customer@vrhere.in',
                        contact: order.phone || '9999999999'
                    },
                    notify: {
                        sms: false,
                        email: false
                    },
                    notes: {
                        orderId: order._id.toString(),
                        invoiceNumber: finalInvoiceNumber,
                        adjustConsultation: String(adjustConsultation)
                    }
                };
                const paymentLink = await razorpay.paymentLink.create(linkPayload);
                paymentLinkUrl = paymentLink.short_url;
            } catch (razorpayError) {
                console.error('Error creating Razorpay Payment Link in helper:', razorpayError.message);
                // Fallback rather than crashing if credentials are dummy
            }
        }
    }

    const newInvoice = {
        invoiceNumber: finalInvoiceNumber,
        amount: firstInvoiceAmount,
        status: invoiceStatus,
        url: paymentLinkUrl,
        dueDate: dueDate ? new Date(dueDate) : null,
        notes: notes || (isSplit 
            ? `Milestone 1 (${splitPercentVal}%): Adjusted invoice.` 
            : (adjustConsultation ? 'Adjusted consultation payment of 499 INR applied.' : '')),
        sentAt: new Date(),
        createdAt: new Date()
    };

    order.invoices.push(newInvoice);

    if (isSplit && secondInvoiceAmount > 0) {
        const remainingInvoice = {
            invoiceNumber: `${finalInvoiceNumber}_BAL`,
            amount: secondInvoiceAmount,
            status: 'Draft',
            url: '',
            dueDate: null,
            notes: `Milestone 2 (Remaining ${100 - splitPercentVal}%): Raised on additional requirements upload.`,
            createdAt: new Date()
        };
        order.invoices.push(remainingInvoice);
    }

    await order.save();

    // Log Activity
    const logActor = actorId || order.user || order._id;
    await logOrderActivity(
        order._id,
        logActor,
        'INVOICE_CREATE',
        `Invoice ${finalInvoiceNumber} created for INR ${firstInvoiceAmount} (Status: ${invoiceStatus})`,
        { invoiceNumber: finalInvoiceNumber, amount: firstInvoiceAmount, status: invoiceStatus }
    );

    // Send Email to Client and Admins
    const emailSubject = `Invoice ${finalInvoiceNumber} from VR Here Business Management Solutions`;
    const emailHtml = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
            <h2 style="color: #4f46e5; text-align: center;">VR Here Invoice Generated</h2>
            <p>Hello ${order.clientName || 'Customer'},</p>
            <p>An invoice has been generated for your service: <strong>${order.serviceName}</strong>.</p>
            <div style="background-color: #f8fafc; padding: 15px; border-radius: 8px; margin: 20px 0;">
                <p style="margin: 5px 0;"><strong>Invoice Number:</strong> ${finalInvoiceNumber}</p>
                <p style="margin: 5px 0;"><strong>Package:</strong> ${order.packageName}</p>
                <p style="margin: 5px 0;"><strong>Amount Due:</strong> INR ${Number(firstInvoiceAmount).toLocaleString('en-IN')}</p>
                <p style="margin: 5px 0;"><strong>Status:</strong> ${invoiceStatus}</p>
                ${adjustConsultation ? '<p style="margin: 5px 0; color: #16a34a;"><strong>Discount Applied:</strong> INR 499 (Consultation adjusted)</p>' : ''}
                ${dueDate ? `<p style="margin: 5px 0;"><strong>Due Date:</strong> ${new Date(dueDate).toLocaleDateString()}</p>` : ''}
            </div>
            ${order.serviceName?.toLowerCase().includes('income tax') || order.packageName?.toLowerCase().includes('itr') ? `
            <div style="background-color: #fffbeb; border: 1px solid #fef3c7; padding: 15px; border-radius: 12px; margin: 20px 0; color: #b45309;">
                <p style="margin: 0; font-weight: bold; font-size: 14px;">Action Required: ITR Assessment Checklist</p>
                <p style="margin: 5px 0 0 0; font-size: 12px; line-height: 1.5; color: #d97706;">Please complete your interactive income tax checklist. This helps our expert CAs review your deductions, assets, and tax profiles correctly: <a href="https://vrhere.in/income-tax-assessment?orderId=${order._id}" style="color: #4f46e5; text-decoration: underline; font-weight: bold;">Fill ITR Checklist Now</a>.</p>
            </div>
            ` : ''}
            ${paymentLinkUrl ? `
            <div style="text-align: center; margin: 30px 0;">
                <a href="${paymentLinkUrl}" style="background-color: #4f46e5; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">Pay Invoice Now</a>
            </div>
            <p style="font-size: 12px; color: #64748b; text-align: center;">If the button above does not work, copy and paste this link into your browser:<br/><a href="${paymentLinkUrl}">${paymentLinkUrl}</a></p>
            ` : ''}
            <div style="margin-top: 25px; border-top: 1px solid #f1f5f9; padding-top: 15px;">
                <p style="font-size: 13px; color: #475569; line-height: 1.5; margin: 0;">
                    <strong>GST Invoice PDF:</strong> You can view, print, or download your formal GST Invoice PDF directly from your <a href="https://vrhere.in/" style="color: #4f46e5; text-decoration: underline; font-weight: bold;">Client Dashboard</a> under the <strong>Invoices</strong> section.
                </p>
            </div>
            <p style="margin-top: 20px; font-size: 14px; color: #475569;">Thank you for choosing VR Here Business Management Solutions.</p>
        </div>
    `;

    // 1. Send to Client
    if (order.email) {
        try {
            await sendEmail({
                email: order.email,
                subject: emailSubject,
                message: emailHtml
            });
        } catch (err) {
            console.error(`Client invoice email send failed: ${err.message}`);
        }
    }

    // 2. Send to Admin(s)
    try {
        const admins = await User.find({ role: 'admin', isActive: true });
        for (const admin of admins) {
            if (admin.email) {
                await sendEmail({
                    email: admin.email,
                    subject: `[Copy] ${emailSubject}`,
                    message: emailHtml
                });
            }
        }
    } catch (err) {
        console.error(`Admin invoice copy email send failed: ${err.message}`);
    }

    return order;
};
