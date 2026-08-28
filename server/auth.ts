import { Request, Response, NextFunction } from 'express';

const VALID_KEYS = process.env.API_KEYS ? process.env.API_KEYS.split(',') : [];

export function requireApiKey(req: Request, res: Response, next: NextFunction) {
  const key = (req.header('x-api-key') || '') as string;
  if (!key && VALID_KEYS.length === 0) {
    // No keys configured - allow (development mode)
    return next();
  }
  if (VALID_KEYS.includes(key)) return next();
  return res.status(401).json({ error: 'Unauthorized: missing or invalid API key' });
}

export default requireApiKey;
