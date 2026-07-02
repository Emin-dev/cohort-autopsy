// Payment integration point — TEST MODE ONLY. No real Stripe/payment
// account is connected. This module exists so that wiring a real payment
// provider later is a one-function change, not a rebuild. See the Studio
// hub's RULES.md: creating a real payment account and flipping this live
// is a decision for the human owner, not something this code does itself.

export const PAYMENT_MODE = 'sandbox'; // flip to 'live' only after a real provider is wired in

export function buyFullReport(summary) {
    if (PAYMENT_MODE === 'sandbox') {
        return {
            ok: true,
            mode: 'sandbox',
            message: 'This is a demo checkout — no real payment was charged. ' +
                'Wiring a real payment provider (Stripe/LemonSqueezy) here turns this into a real purchase.'
        };
    }
    // Real integration point for later: redirect to a real Stripe Checkout
    // Session created server-side, or a LemonSqueezy/Gumroad checkout link.
    throw new Error('Live payment mode is not configured.');
}
