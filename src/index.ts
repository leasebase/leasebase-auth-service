import { createApp, startApp } from '@leasebase/service-common';
import { authRouter } from './routes/auth';

const app = createApp();

// Trust X-Forwarded-* headers from ALB / reverse proxy so req.ip
// reflects the real client IP instead of the load-balancer's IP.
app.set('trust proxy', true);

app.use('/internal/auth', authRouter);

startApp(app);
