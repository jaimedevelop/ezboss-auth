/** HTTPS delivery only. No recipient, URL/token or provider response is logged. */
export function createMailDelivery(env, request = fetch) {
    return async ({ to, url, kind }) => {
        const target = new URL(url);
        if (target.origin !== env.baseURL && target.origin !== env.appOrigin)
            throw new Error('Invalid mail link origin');
        const response = await request('https://api.resend.com/emails', {
            method: 'POST', redirect: 'error', signal: AbortSignal.timeout(8000),
            headers: { Authorization: `Bearer ${env.MAIL_API_KEY}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ from: env.MAIL_FROM, to: [to],
                subject: kind === 'verification' ? 'Verify your EzBoss email' : 'Reset your EzBoss password',
                text: `${kind === 'verification' ? 'Verify your email' : 'Reset your password'} using this one-time link:\n${url}\n\nIf you did not request this, you can ignore this email.` }),
        });
        if (!response.ok)
            throw new Error('Authentication email delivery unavailable');
    };
}
