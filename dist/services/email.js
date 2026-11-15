const mailgunHosts = {
    us: 'api.mailgun.net',
    eu: 'api.eu.mailgun.net',
    au: 'api.au.mailgun.net',
};
/** HTTPS delivery only. No recipient, URL/token or provider response is logged. */
export function createMailDelivery(env, request = fetch) {
    const endpoint = `https://${mailgunHosts[env.MAILGUN_REGION]}/v3/${encodeURIComponent(env.MAILGUN_DOMAIN)}/messages`;
    const authorization = `Basic ${Buffer.from(`api:${env.MAILGUN_API_KEY}`).toString('base64')}`;
    return async (mail) => {
        const { to, kind } = mail;
        if (kind !== 'merge') {
            const target = new URL(mail.url);
            if (target.origin !== env.baseURL && target.origin !== env.appOrigin)
                throw new Error('Invalid mail link origin');
        }
        const subjects = {
            verification: 'Verify your EzBoss email',
            merge: 'Confirm your EzBoss account merge',
            reset: 'Reset your EzBoss password',
            'first-password': 'Create an EzBoss password',
        };
        const action = kind === 'verification' ? 'Verify your email' : 'Reset your password';
        const body = new FormData();
        body.set('from', env.MAILGUN_FROM);
        body.set('to', to);
        body.set('subject', subjects[kind]);
        body.set('text', kind === 'merge'
            ? `Your EzBoss account merge code is ${mail.code}. It expires in 5 minutes. If you did not request this, ignore this email.`
            : kind === 'first-password'
                ? `Someone tried to sign in to your EzBoss account with a password. If that was you, verify your Google sign-in and create an EzBoss password here:\n${mail.url}\n\nIf you did not request this, ignore this email.`
                : `${action} using this one-time link:\n${mail.url}\n\nIf you did not request this, you can ignore this email.`);
        body.set('o:tracking', 'no');
        body.set('o:tracking-clicks', 'no');
        body.set('o:tracking-opens', 'no');
        const response = await request(endpoint, {
            method: 'POST', redirect: 'error', signal: AbortSignal.timeout(8000),
            headers: { Authorization: authorization },
            body,
        }).catch(() => { throw new Error('Authentication email delivery unavailable'); });
        if (!response.ok)
            throw new Error('Authentication email delivery unavailable');
    };
}
