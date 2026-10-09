import { config } from './config/index.js';
import { logger } from '@security-lab/logger';
import { buildApp } from './app/index.js';
import { closeDatabase, verifyDatabaseConnection } from './services/db.js';

// Security Lab Controller Server
async function startServer(): Promise<void> {
  logger.info(
    {
      nodeEnv: config.NODE_ENV,
      port: config.PORT,
      host: config.HOST,
    },
    'Starting Security Lab Controller service...',
  );

  // Verify database connectivity
  try {
    await verifyDatabaseConnection();
  } catch (err) {
    if (config.NODE_ENV === 'production') {
      logger.fatal({ err }, 'Aborting startup due to database connectivity failure in production');
      process.exit(1);
    } else {
      logger.warn({ err }, 'Continuing startup in non-production mode despite initial database connectivity check failure');
    }
  }

  const app = buildApp();


  // Graceful shutdown handler
  let isShuttingDown = false;
  const gracefulShutdown = async (signal: string) => {
    if (isShuttingDown) return;
    isShuttingDown = true;

    logger.info({ signal }, 'Received shutdown signal. Commencing graceful shutdown...');

    try {
      // 1. Stop accepting new HTTP requests and finish in-flight requests
      await app.close();
      logger.info('HTTP server closed successfully.');

      // 2. Close database connection pool
      await closeDatabase();

      logger.info('Graceful shutdown completed.');
      process.exit(0);
    } catch (err) {
      logger.error({ err }, 'Error during graceful shutdown');
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  try {
    await app.listen({
      port: config.PORT,
      host: config.HOST,
    });

    logger.info(
      {
        url: `http://${config.HOST}:${config.PORT}`,
        healthEndpoint: `http://${config.HOST}:${config.PORT}/health`,
      },
      'Security Lab Controller is ready and listening',
    );
  } catch (err) {
    logger.fatal({ err }, 'Failed to start Security Lab Controller');
    process.exit(1);
  }
}

startServer();
