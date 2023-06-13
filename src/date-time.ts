/**
 * Return the current time in ISO format.
 */
export const generateInstant = (): string => {
  return new Date().toISOString();
};

/**
 * Convert a date string to a timestamp (in milliseconds).
 *
 * @param dateString A string representation of a date
 * @param label Descriptive name of the date being passed in, e.g. "NotOnOrAfter"
 * @throws Will throw an error if parsing `dateString` returns `NaN`
 * @returns {number} The timestamp (in milliseconds) representation of the given date
 */
export const dateStringToTimestamp = (dateString: string, label: string): number => {
  const dateMs = Date.parse(dateString);

  if (isNaN(dateMs)) {
    throw new Error(`Error parsing ${label}: '${dateString}' is not a valid date`);
  }

  return dateMs;
};
