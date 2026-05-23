/**
 * Collection of beautifully styled HTML email templates for VR HERE system alerts.
 */

const baseEmailStyle = (content) => `
    <div style="font-family: 'Inter', Arial, sans-serif; line-height: 1.6; color: #1e293b; max-width: 600px; margin: 0 auto; padding: 30px; border: 1px solid #f1f5f9; border-radius: 16px; background-color: #ffffff; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.05);">
        <!-- Header -->
        <div style="text-align: center; margin-bottom: 30px; border-bottom: 2px solid #f8fafc; padding-bottom: 20px;">
            <div style="display: inline-block; padding: 10px 24px; background: linear-gradient(135deg, #4f46e5 0%, #6d28d9 100%); color: #ffffff; border-radius: 12px; font-weight: 900; font-size: 18px; letter-spacing: 0.5px; box-shadow: 0 4px 12px rgba(99, 102, 241, 0.25);">
                VR HERE
            </div>
            <p style="font-size: 11px; font-weight: 800; text-transform: uppercase; color: #64748b; letter-spacing: 1px; margin-top: 10px; margin-bottom: 0;">Business Solutions</p>
        </div>
        
        <!-- Content -->
        ${content}
        
        <!-- Footer -->
        <div style="margin-top: 35px; border-top: 1px solid #f1f5f9; padding-top: 20px; text-align: center;">
            <p style="font-size: 12px; font-weight: bold; color: #475569; margin-bottom: 4px;">VR HERE Business Solutions</p>
            <p style="font-size: 11px; color: #94a3b8; margin-top: 0; line-height: 1.4;">
                This email was sent by the automated compliance platform.<br/>
                For support, raise a ticket in your client dashboard or reply to this email.
            </p>
        </div>
    </div>
`;

export const getOrderPlacedTemplate = ({ clientName, serviceName, packageName, price, paymentId }) => {
    return baseEmailStyle(`
        <h2 style="color: #0f172a; font-size: 20px; font-weight: 800; margin-bottom: 10px; text-align: center;">Order Confirmed!</h2>
        <p style="font-size: 14px; color: #475569; text-align: center; margin-top: 0; margin-bottom: 20px;">We have received your payment and registered your compliance order.</p>
        
        <p style="font-size: 14px; color: #475569;">Hi ${clientName},</p>
        <p style="font-size: 14px; color: #475569;">Thank you for placing your order with VR HERE. Our specialist team has been assigned and your order processing has begun.</p>
        
        <div style="background-color: #f8fafc; border-radius: 12px; border: 1px solid #f1f5f9; padding: 20px; margin: 25px 0;">
            <h3 style="font-size: 12px; font-weight: 900; color: #4f46e5; text-transform: uppercase; margin-top: 0; margin-bottom: 15px; letter-spacing: 0.5px;">Order Summary</h3>
            <table style="width: 100%; font-size: 13px; border-collapse: collapse;">
                <tr>
                    <td style="padding: 6px 0; color: #64748b; font-weight: bold;">Service Name:</td>
                    <td style="padding: 6px 0; color: #0f172a; font-weight: bold; text-align: right;">${serviceName}</td>
                </tr>
                <tr>
                    <td style="padding: 6px 0; color: #64748b; font-weight: bold;">Package:</td>
                    <td style="padding: 6px 0; color: #0f172a; text-align: right;">${packageName}</td>
                </tr>
                <tr>
                    <td style="padding: 6px 0; color: #64748b; font-weight: bold;">Amount Paid:</td>
                    <td style="padding: 6px 0; color: #0f172a; font-weight: bold; text-align: right;">INR ${Number(price).toLocaleString('en-IN')}</td>
                </tr>
                <tr style="border-top: 1px solid #e2e8f0;">
                    <td style="padding: 10px 0 0 0; color: #64748b; font-weight: bold;">Transaction ID:</td>
                    <td style="padding: 10px 0 0 0; color: #475569; font-family: monospace; font-size: 12px; text-align: right;">${paymentId}</td>
                </tr>
            </table>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://vrhere.in/" style="display: inline-block; padding: 12px 30px; background-color: #4f46e5; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 14px; box-shadow: 0 4px 6px rgba(79, 70, 229, 0.15);">
                Access Client Dashboard
            </a>
        </div>
        
        <p style="font-size: 13px; color: #64748b; background-color: #fffbeb; border-left: 4px solid #f59e0b; padding: 12px; border-radius: 4px; margin-top: 25px;">
            <strong>Next Step:</strong> Please log in to your dashboard, upload any pending documents required for this service, and fill in the details form under your project's checklist workspace.
        </p>
    `);
};

export const getOrderStatusUpdateTemplate = ({ clientName, serviceName, packageName, status }) => {
    let stepDescription = '';
    if (status === 'Pending Documents') {
        stepDescription = 'We are waiting for you to upload the necessary documents to commence work.';
    } else if (status === 'Under Review') {
        stepDescription = 'Our execution experts are validating your submitted information and compiling requirements.';
    } else if (status === 'Completed') {
        stepDescription = 'All compliance activities are complete! Your final deliverables and certificates are ready for download.';
    } else {
        stepDescription = 'We have transitioned your project to the next operational phase successfully.';
    }

    return baseEmailStyle(`
        <h2 style="color: #0f172a; font-size: 20px; font-weight: 800; margin-bottom: 10px; text-align: center;">Project Progress Update</h2>
        <p style="font-size: 14px; color: #475569; text-align: center; margin-top: 0; margin-bottom: 20px;">Your project's compliance workflow status has been updated.</p>
        
        <p style="font-size: 14px; color: #475569;">Hi ${clientName},</p>
        <p style="font-size: 14px; color: #475569;">The team has progressed work on your order for <strong>${serviceName} (${packageName})</strong>.</p>
        
        <div style="background-color: #f8fafc; border-radius: 12px; border: 1px solid #f1f5f9; padding: 20px; margin: 25px 0; text-align: center;">
            <p style="font-size: 11px; font-weight: 800; color: #64748b; uppercase tracking-wider margin-top: 0; margin-bottom: 8px;">New Workflow Status</p>
            <span style="display: inline-block; padding: 8px 18px; background-color: #eff6ff; color: #2563eb; font-weight: bold; border-radius: 20px; border: 1px dashed #bfdbfe; font-size: 14px;">
                ${status}
            </span>
            <p style="font-size: 13px; color: #475569; margin-top: 15px; margin-bottom: 0; line-height: 1.5;">${stepDescription}</p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://vrhere.in/" style="display: inline-block; padding: 12px 30px; background-color: #4f46e5; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 14px;">
                Track Project Live
            </a>
        </div>
    `);
};

export const getTicketMessageTemplate = ({ clientName, subject, message, senderName }) => {
    return baseEmailStyle(`
        <h2 style="color: #0f172a; font-size: 20px; font-weight: 800; margin-bottom: 10px; text-align: center;">New Reply on Support Ticket</h2>
        <p style="font-size: 14px; color: #475569; text-align: center; margin-top: 0; margin-bottom: 20px;">You received a message response regarding: "${subject}"</p>
        
        <p style="font-size: 14px; color: #475569;">Hi ${clientName},</p>
        <p style="font-size: 14px; color: #475569;">There is an update on your support inquiry on our platform.</p>
        
        <div style="background-color: #f8fafc; border-radius: 12px; border: 1px solid #f1f5f9; padding: 20px; margin: 25px 0;">
            <p style="font-size: 12px; font-weight: 800; color: #64748b; text-transform: uppercase; margin-top: 0; margin-bottom: 10px; letter-spacing: 0.5px;">Message from ${senderName || 'Support Specialist'}</p>
            <p style="font-size: 13px; color: #334155; font-style: italic; margin-top: 0; white-space: pre-wrap;">"${message}"</p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://vrhere.in/" style="display: inline-block; padding: 12px 30px; background-color: #4f46e5; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 14px;">
                Open Support Inbox
            </a>
        </div>
    `);
};

export const getClientSubmissionTemplate = ({ staffName, clientName, serviceName }) => {
    return baseEmailStyle(`
        <h2 style="color: #0f172a; font-size: 18px; font-weight: 800; margin-bottom: 10px;">Client Submission Logged</h2>
        <p style="font-size: 13px; color: #64748b; margin-top: 0; margin-bottom: 20px;">Client action logged on order workspace.</p>
        
        <p style="font-size: 14px; color: #475569;">Hi ${staffName},</p>
        <p style="font-size: 14px; color: #475569;">Client <strong>${clientName}</strong> has uploaded a document or submitted a checklist requirement for service <strong>${serviceName}</strong>.</p>
        
        <div style="background-color: #f0fdf4; border-radius: 12px; border: 1px solid #dcfce7; padding: 15px; margin: 20px 0; color: #166534; font-size: 13px; font-weight: bold;">
            Action Needed: Please log into the Admin / Staff Dashboard to review the documents and mark as verified or request clarification.
        </div>
        
        <div style="text-align: center; margin: 25px 0;">
            <a href="https://vrhere.in/" style="display: inline-block; padding: 10px 24px; background-color: #15803d; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 13px;">
                Review in Admin Dashboard
            </a>
        </div>
    `);
};

export const getAdditionalRequirementTemplate = ({ clientName, serviceName, requirementTitle, requirementDescription, type }) => {
    const actionText = type === 'Document' ? 'upload the requested file' : 'provide the requested details';
    return baseEmailStyle(`
        <h2 style="color: #0f172a; font-size: 20px; font-weight: 800; margin-bottom: 10px; text-align: center;">Action Required: Additional Information Requested</h2>
        <p style="font-size: 14px; color: #475569; text-align: center; margin-top: 0; margin-bottom: 20px;">We require additional input from you to progress work on your project.</p>
        
        <p style="font-size: 14px; color: #475569;">Hi ${clientName},</p>
        <p style="font-size: 14px; color: #475569;">Our execution experts are currently processing your order for <strong>${serviceName}</strong>. To move to the next phase, we need you to ${actionText} for the following requirement:</p>
        
        <div style="background-color: #fffbeb; border-radius: 12px; border: 1px solid #fef3c7; padding: 20px; margin: 25px 0;">
            <h3 style="font-size: 13px; font-weight: 900; color: #b45309; text-transform: uppercase; margin-top: 0; margin-bottom: 10px; letter-spacing: 0.5px;">
                Requested ${type}: ${requirementTitle}
            </h3>
            <p style="font-size: 13px; color: #334155; margin: 0; line-height: 1.5; white-space: pre-wrap;">${requirementDescription || 'No detailed instructions provided.'}</p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://vrhere.in/" style="display: inline-block; padding: 12px 30px; background-color: #4f46e5; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 14px;">
                Submit Requested Information
            </a>
        </div>
    `);
};

