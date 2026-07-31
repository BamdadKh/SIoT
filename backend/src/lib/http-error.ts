/**
 * Fastify serialises a thrown error carrying `statusCode` into its standard
 * `{ statusCode, error, message }` body, so throwing one of these keeps handler
 * failures and schema-validation failures on the same wire shape without every
 * route having to declare an error response schema.
 */
export function httpError(statusCode: number, message: string): Error {
  const err = new Error(message) as Error & { statusCode: number };
  err.statusCode = statusCode;
  return err;
}

/** Postgres `unique_violation`. */
const UNIQUE_VIOLATION = '23505';

export function isUniqueViolation(err: unknown): boolean {
  return (err as { code?: string } | null)?.code === UNIQUE_VIOLATION;
}
