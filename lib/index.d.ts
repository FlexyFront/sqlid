import { Request, Response, NextFunction } from "express";

/**
 * SQL Injection Detection and Prevention Middleware
 *
 * This middleware function checks incoming requests for potential SQL injection attempts.
 * It examines request body, query parameters, and route parameters for suspicious patterns.
 * If a potential SQL injection is detected, the request is blocked and an appropriate response is sent.
 *
 * @param req - The Express request object
 * @param res - The Express response object
 * @param next - The next middleware function in the request-response cycle
 */
declare function sqlid(req: Request, res: Response, next: NextFunction): void;

export default sqlid;

/**
 * LRU Cache for storing attack data
 * This is used internally by the sqlid middleware
 */
declare class LRUCache<K, V> {
  constructor(options: { max: number; ttl: number });
  set(key: K, value: V, options?: { ttl: number }): void;
  get(key: K): V | undefined;
  has(key: K): boolean;
}

/**
 * SQL injection detection function
 * This is used internally by the sqlid middleware
 */
declare function detectSqlInjection(input: string): boolean;
