const fs = require('fs');
const path = require('path');
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');

const LOG_DIR = path.join(__dirname, '..', 'logs');

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

ensureDir(LOG_DIR);

function makeLogger(filenamePrefix, { level = 'info' } = {}) {
  const fileTransport = new DailyRotateFile({
    dirname: LOG_DIR,
    filename: `${filenamePrefix}-%DATE%.log`,
    datePattern: 'YYYY-MM-DD',
    zippedArchive: true,
    maxSize: '10m',
    maxFiles: '14d'
  });

  return winston.createLogger({
    level,
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json()
    ),
    transports: [
      fileTransport,
      new winston.transports.Console({
        level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.timestamp(),
          winston.format.printf((info) => {
            const base = `${info.timestamp} ${info.level}: ${info.message}`;
            if (info.stack && process.env.NODE_ENV !== 'production') return `${base}\n${info.stack}`;
            return base;
          })
        )
      })
    ]
  });
}

const logger = makeLogger('app', { level: process.env.LOG_LEVEL || 'info' });
const auditLogger = makeLogger('audit', { level: process.env.AUDIT_LOG_LEVEL || 'info' });

function requestLogger(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - start;
    const user = req.session?.user;
    logger.info('request', {
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      ms,
      ip: req.ip,
      userId: user?.id || null,
      userEmail: user?.email || null
    });
  });
  next();
}

function audit(event, details = {}) {
  auditLogger.info(event, { ...details });
}

function tailFile(filePath, maxLines = 300) {
  const raw = fs.readFileSync(filePath, 'utf8');
  const lines = raw.split(/\r?\n/);
  return lines.slice(Math.max(0, lines.length - maxLines)).join('\n');
}

module.exports = {
  LOG_DIR,
  logger,
  auditLogger,
  requestLogger,
  audit,
  tailFile
};
