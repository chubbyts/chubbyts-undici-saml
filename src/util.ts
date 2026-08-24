// an absolute url with a http or https scheme and without embedded credentials (they would end up within logs, error
// messages or a browser redirect)
export const isHttpUrl = (value: unknown): value is string => {
  if (typeof value !== 'string' || !URL.canParse(value)) {
    return false;
  }

  const url = new URL(value);

  return ['http:', 'https:'].includes(url.protocol) && url.username === '' && url.password === '';
};

export const assertNonNegative = (name: string, value: number): void => {
  if (Number.isNaN(value) || value < 0) {
    throw new Error(`Invalid ${name} ${String(value)}: must be a non-negative number of seconds`);
  }
};

export const isObject = (value: unknown): value is Record<string, unknown> => {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
};
