/**
 * ECL instants: RFC 3339 UTC times with `Z`, whole seconds or one to nine fractional digits, on a
 * calendar day that exists (years 0001 to 9999). Instants compare as exact integers of
 * nanoseconds since the Unix epoch, so times that differ in the ninth digit still order exactly.
 */

const RFC3339_UTC = /^([0-9]{4})-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])(\.[0-9]{1,9})?Z$/;

/** A time that is not an ECL RFC 3339 UTC instant. */
export class InstantError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InstantError";
  }
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
    return leap ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

/** Days from 1970-01-01 to the given proleptic Gregorian date (Howard Hinnant's algorithm). */
function daysFromCivil(year: number, month: number, day: number): number {
  const y = month <= 2 ? year - 1 : year;
  const era = Math.floor(y / 400);
  const yearOfEra = y - era * 400;
  const shifted = month > 2 ? month - 3 : month + 9;
  const dayOfYear = Math.floor((153 * shifted + 2) / 5) + day - 1;
  const dayOfEra = yearOfEra * 365 + Math.floor(yearOfEra / 4) - Math.floor(yearOfEra / 100) + dayOfYear;
  return era * 146097 + dayOfEra - 719468;
}

interface Parts {
  seconds: bigint;
  fraction: string;
}

function parts(value: unknown): Parts {
  if (typeof value !== "string") {
    throw new InstantError("timestamp must be an ECL RFC 3339 UTC instant");
  }
  const match = RFC3339_UTC.exec(value);
  if (match === null) {
    throw new InstantError("timestamp must be an ECL RFC 3339 UTC instant");
  }
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fractionText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  if (year < 1 || day > daysInMonth(year, month)) {
    throw new InstantError("timestamp is not a calendar date that exists");
  }
  const days = daysFromCivil(year, month, day);
  const seconds = BigInt(days) * 86400n + BigInt(Number(hourText) * 3600 + Number(minuteText) * 60 + Number(secondText));
  return { seconds, fraction: fractionText === undefined ? "" : fractionText.slice(1) };
}

/** Whether `value` is an ECL RFC 3339 UTC instant (the `date-time` format of the schemas). */
export function isInstant(value: unknown): boolean {
  try {
    parts(value);
    return true;
  } catch {
    return false;
  }
}

/** Nanoseconds since 1970-01-01T00:00:00Z. Throws InstantError. */
export function instantNanoseconds(value: unknown): bigint {
  const { seconds, fraction } = parts(value);
  return seconds * 1_000_000_000n + BigInt(fraction.padEnd(9, "0"));
}

/**
 * Microseconds since the epoch, with any further digits dropped, as the reference's datetime
 * comparisons floor them. Throws InstantError.
 */
export function instantMicroseconds(value: unknown): bigint {
  const { seconds, fraction } = parts(value);
  return seconds * 1_000_000n + BigInt(fraction.slice(0, 6).padEnd(6, "0"));
}

/** The current time as an ECL instant with microseconds, for a caller that gives none. */
export function nowInstant(): string {
  const now = new Date();
  return now.toISOString().replace(/Z$/, "000Z");
}
