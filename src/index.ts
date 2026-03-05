import { createApp, startApp } from '@leasebase/service-common';
import { authRouter } from './routes/auth';

const app = createApp();

app.use('/internal/auth', authRouter);

startApp(app);
