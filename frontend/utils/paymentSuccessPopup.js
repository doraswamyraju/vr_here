export const showPaymentSuccessPopup = ({
  serviceName,
  paymentId,
  requiresEmailLogin
}) => {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.style.position = 'fixed';
    overlay.style.inset = '0';
    overlay.style.background = 'rgba(2, 6, 23, 0.65)';
    overlay.style.backdropFilter = 'blur(4px)';
    overlay.style.zIndex = '9999';
    overlay.style.display = 'flex';
    overlay.style.alignItems = 'center';
    overlay.style.justifyContent = 'center';
    overlay.style.padding = '16px';

    const card = document.createElement('div');
    card.style.width = '100%';
    card.style.maxWidth = '420px';
    card.style.background = '#ffffff';
    card.style.borderRadius = '16px';
    card.style.boxShadow = '0 20px 45px rgba(2, 6, 23, 0.28)';
    card.style.border = '1px solid #e2e8f0';
    card.style.overflow = 'hidden';

    const header = document.createElement('div');
    header.style.background = 'linear-gradient(135deg, #111827, #1e293b)';
    header.style.color = '#ffffff';
    header.style.padding = '16px 18px';
    header.innerHTML = '<div style="font-size:16px;font-weight:700;">Payment Successful</div>';

    const body = document.createElement('div');
    body.style.padding = '16px 18px';
    body.style.color = '#0f172a';
    body.style.fontSize = '14px';
    body.style.lineHeight = '1.55';

    const safeServiceName = serviceName || 'your selected service';
    const intro = document.createElement('p');
    intro.style.margin = '0 0 10px 0';
    intro.innerHTML = `Thank you for choosing <strong>${safeServiceName}</strong>.`;

    const instruction = document.createElement('p');
    instruction.style.margin = '0 0 10px 0';
    instruction.textContent = requiresEmailLogin
      ? 'We sent an email with login details and a secure password setup link. Please login using that email link.'
      : 'Your booking is confirmed. You can continue to your dashboard now.';

    const paymentText = document.createElement('p');
    paymentText.style.margin = '0';
    paymentText.style.color = '#475569';
    paymentText.style.fontSize = '12px';
    paymentText.textContent = paymentId ? `Payment ID: ${paymentId}` : '';

    body.appendChild(intro);
    body.appendChild(instruction);
    if (paymentId) body.appendChild(paymentText);

    const footer = document.createElement('div');
    footer.style.padding = '0 18px 18px';
    footer.style.display = 'flex';
    footer.style.justifyContent = 'flex-end';

    const button = document.createElement('button');
    button.textContent = requiresEmailLogin ? 'Go To Login' : 'Go To Dashboard';
    button.style.background = '#dc2626';
    button.style.color = '#ffffff';
    button.style.border = 'none';
    button.style.borderRadius = '10px';
    button.style.padding = '10px 16px';
    button.style.fontWeight = '700';
    button.style.cursor = 'pointer';
    button.style.fontSize = '13px';

    button.addEventListener('click', () => {
      if (overlay.parentNode) {
        overlay.parentNode.removeChild(overlay);
      }
      resolve();
    });

    footer.appendChild(button);
    card.appendChild(header);
    card.appendChild(body);
    card.appendChild(footer);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
  });
};

