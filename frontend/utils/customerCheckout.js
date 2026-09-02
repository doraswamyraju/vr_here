import axios from 'axios';

/**
 * Ensures Razorpay SDK is available in the window.
 */
const ensureRazorpayLoaded = () => {
  return new Promise((resolve) => {
    if (typeof window !== 'undefined' && window.Razorpay) {
      return resolve(true);
    }

    const existingScript = document.querySelector('script[src*="checkout.razorpay.com"]');
    if (existingScript) {
      let checks = 0;
      const interval = setInterval(() => {
        checks++;
        if (typeof window !== 'undefined' && window.Razorpay) {
          clearInterval(interval);
          resolve(true);
        } else if (checks > 30) { // 3 seconds timeout
          clearInterval(interval);
          try { existingScript.remove(); } catch (e) {}
          injectScript();
        }
      }, 100);
      return;
    }

    injectScript();

    function injectScript() {
      const script = document.createElement('script');
      script.src = 'https://checkout.razorpay.com/v1/checkout.js';
      script.async = true;
      script.onload = () => resolve(!!(typeof window !== 'undefined' && window.Razorpay));
      script.onerror = () => {
        console.error('[Customer Checkout] Razorpay SDK failed to load');
        resolve(false);
      };
      document.head.appendChild(script);

      setTimeout(() => {
        resolve(!!(typeof window !== 'undefined' && window.Razorpay));
      }, 5000);
    }
  });
};

/**
 * Dedicated Customer Panel Checkout.
 * Designed exclusively for authenticated sessions in the customer portal.
 */
export const launchCustomerCheckout = async ({
  serviceName,
  selectedPlan,
  userInfo,
  onSubmittingChange,
  onSuccess,
  onFailure
}) => {
  try {
    if (onSubmittingChange) onSubmittingChange(true);

    if (!userInfo || !userInfo.token) {
      throw new Error('Active session expired. Please refresh your dashboard.');
    }

    const isLoaded = await ensureRazorpayLoaded();
    if (!isLoaded || typeof window === 'undefined' || !window.Razorpay) {
      throw new Error('Payment gateway script could not be loaded. Please ensure no ad-blockers are blocking checkout.razorpay.com and try again.');
    }

    const rawPrice = selectedPlan?.price ?? selectedPlan?.amount ?? 0;
    const cleanAmount = typeof rawPrice === 'string'
      ? Number(rawPrice.replace(/[^0-9]/g, '')) || 0
      : Number(rawPrice) || 0;

    if (cleanAmount <= 0) {
      throw new Error('Please select a valid package price.');
    }

    const cleanServiceName = serviceName || selectedPlan?.name || 'Business Legal Service';
    const cleanPackageName = selectedPlan?.name || 'Standard Package';
    const customerName = userInfo.name || 'VR HERE Client';
    const email = userInfo.email || 'client@vrhere.in';
    const phone = userInfo.phone || '';

    const authHeaders = {
      headers: {
        Authorization: `Bearer ${userInfo.token}`
      }
    };

    const checkoutPayload = {
      serviceName: cleanServiceName,
      packageName: cleanPackageName,
      amount: cleanAmount,
      customerName,
      email,
      phone,
      referralCode: ''
    };

    console.log('[Customer Checkout] Initiating order for authenticated user:', checkoutPayload);

    // 1. Create order on backend
    const { data: checkoutOrder } = await axios.post(
      '/api/payments/checkout-order',
      checkoutPayload,
      authHeaders
    );

    if (!checkoutOrder?.key || !checkoutOrder?.orderId) {
      throw new Error(checkoutOrder?.message || 'Failed to initialize payment gateway order from server.');
    }

    // 2. Configure Razorpay modal
    const options = {
      key: checkoutOrder.key,
      amount: checkoutOrder.amount,
      currency: checkoutOrder.currency || 'INR',
      name: 'VR HERE Business Solutions',
      description: `Payment for ${cleanPackageName}`,
      order_id: checkoutOrder.orderId,
      prefill: {
        name: customerName,
        email: email,
        contact: phone
      },
      notes: {
        serviceName: cleanServiceName,
        packageName: cleanPackageName,
        customerId: userInfo._id || ''
      },
      theme: {
        color: '#DC2626'
      },
      modal: {
        ondismiss: function () {
          console.log('[Customer Checkout] Razorpay checkout modal closed by user');
          if (onSubmittingChange) onSubmittingChange(false);
        }
      },
      handler: async function (response) {
        try {
          console.log('[Customer Checkout] Payment authorized, verifying signature:', response);

          // 3. Verify payment on backend with user session token
          const { data } = await axios.post(
            '/api/payments/verify',
            {
              ...checkoutPayload,
              razorpay_order_id: response.razorpay_order_id,
              razorpay_payment_id: response.razorpay_payment_id,
              razorpay_signature: response.razorpay_signature
            },
            authHeaders
          );

          if (onSubmittingChange) onSubmittingChange(false);
          if (onSuccess) {
            await onSuccess(data);
          }
        } catch (verifyErr) {
          console.error('[Customer Checkout] Payment verification failed:', verifyErr);
          if (onSubmittingChange) onSubmittingChange(false);
          if (onFailure) {
            onFailure(verifyErr);
          }
        }
      }
    };

    const rzp = new window.Razorpay(options);
    rzp.on('payment.failed', function (resp) {
      console.error('[Customer Checkout] Payment failed:', resp);
      if (onSubmittingChange) onSubmittingChange(false);
      if (onFailure) {
        onFailure(resp.error || new Error('Payment was declined or cancelled.'));
      }
    });

    rzp.open();

    // Safety timeout to re-enable button state
    setTimeout(() => {
      if (onSubmittingChange) onSubmittingChange(false);
    }, 2000);

  } catch (err) {
    console.error('[Customer Checkout] Error:', err);
    if (onSubmittingChange) onSubmittingChange(false);
    if (onFailure) {
      onFailure(err);
    }
  }
};
