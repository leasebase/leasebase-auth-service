import { createApp, startApp } from '@leasebase/service-common';
import { authRouter } from './routes/auth';
import { profileRouter } from './routes/profile';

const app = createApp();

// Trust X-Forwarded-* headers from ALB / reverse proxy so req.ip
// reflects the real client IP instead of the load-balancer's IP.
app.set('trust proxy', true);

app.use('/internal/auth', authRouter);

// Profile routes — proxied via BFF:
//   GET|PUT  /api/profile       → base user profile (all personas)
//   GET|PUT  /api/profile/owner → owner branding / billing
app.use('/internal/profile', profileRouter);

startApp(app);
