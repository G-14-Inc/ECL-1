/**
 * The two formats the ECL schemas assert (INTEGRITY-ENVELOPE-1 IE1-038), checked exactly as the
 * reference checks them: `date-time` is an ECL RFC 3339 UTC instant, and `uri` is an absolute URI
 * of printable ASCII whose percent signs start escapes, with a scheme and a non-empty authority or
 * path as Python's `urllib.parse.urlsplit` divides it, and brackets only around an IP literal host.
 */

import { isInstant } from "../time.js";

const URI_CHARACTERS = /^[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]+$/;
const PERCENT_ESCAPE = /^%[0-9A-Fa-f]{2}/;
const SCHEME_CHARACTERS = /^[A-Za-z0-9+.-]$/;
const ASCII_LETTER = /^[A-Za-z]$/;

/** The `date-time` format: an ECL RFC 3339 UTC instant. Anything that is not a string fails. */
export function isDateTime(value: unknown): boolean {
  return isInstant(value);
}

/** The `uri` format. Anything that is not a string fails. */
export function isAbsoluteUri(value: unknown): boolean {
  if (typeof value !== "string") {
    return false;
  }
  for (const character of value) {
    const code = character.codePointAt(0) as number;
    if (code <= 0x20 || code >= 0x7f || character === "\\") {
      return false;
    }
  }
  if (!URI_CHARACTERS.test(value)) {
    return false;
  }
  for (let index = value.indexOf("%"); index >= 0; index = value.indexOf("%", index + 1)) {
    if (!PERCENT_ESCAPE.test(value.slice(index))) {
      return false;
    }
  }
  const parsed = urlsplit(value);
  if (parsed === undefined) {
    return false;
  }
  // IE1-038: brackets in an authority enclose its host. urlsplit checks a bracketed host, but
  // accepts brackets in the user information before a host that has none.
  const host = parsed.netloc.slice(parsed.netloc.lastIndexOf("@") + 1);
  if ((parsed.netloc.includes("[") || parsed.netloc.includes("]")) && !host.startsWith("[")) {
    return false;
  }
  return parsed.scheme !== "" && (parsed.netloc !== "" || parsed.path !== "");
}

/** The five parts of a URI as Python's `urllib.parse.urlsplit` divides it. */
export interface SplitResult {
  readonly scheme: string;
  readonly netloc: string;
  readonly path: string;
  readonly query: string;
  readonly fragment: string;
}

// The schemes that Python 3.12's urlunsplit writes with an empty authority (`uses_netloc`).
const USES_NETLOC = new Set([
  "",
  "ftp",
  "http",
  "gopher",
  "nntp",
  "telnet",
  "imap",
  "wais",
  "file",
  "mms",
  "https",
  "shttp",
  "snews",
  "prospero",
  "rtsp",
  "rtsps",
  "rtspu",
  "rsync",
  "svn",
  "svn+ssh",
  "sftp",
  "nfs",
  "git",
  "git+ssh",
  "ws",
  "wss",
  "itms-services",
]);

/** Python 3.12's urlunsplit: the URI that the five parts make. */
export function urlunsplit(scheme: string, netloc: string, path: string, query: string, fragment: string): string {
  let url = path;
  if (netloc !== "") {
    if (url !== "" && !url.startsWith("/")) {
      url = "/" + url;
    }
    url = "//" + netloc + url;
  } else if (url.startsWith("//")) {
    url = "//" + url;
  } else if (scheme !== "" && USES_NETLOC.has(scheme) && (url === "" || url.startsWith("/"))) {
    url = "//" + url;
  }
  if (scheme !== "") {
    url = scheme + ":" + url;
  }
  if (query !== "") {
    url = url + "?" + query;
  }
  if (fragment !== "") {
    url = url + "#" + fragment;
  }
  return url;
}

/**
 * Python 3.12's urlsplit for printable ASCII input (which it neither strips nor filters);
 * undefined where it raises ValueError.
 */
export function urlsplit(input: string): SplitResult | undefined {
  let url = input;
  let scheme = "";
  let netloc = "";
  const colon = url.indexOf(":");
  if (colon > 0 && ASCII_LETTER.test(url[0] as string)) {
    let allScheme = true;
    for (const character of url.slice(0, colon)) {
      if (!SCHEME_CHARACTERS.test(character)) {
        allScheme = false;
        break;
      }
    }
    if (allScheme) {
      scheme = url.slice(0, colon).toLowerCase();
      url = url.slice(colon + 1);
    }
  }
  if (url.startsWith("//")) {
    let delimiter = url.length;
    for (const character of "/?#") {
      const found = url.indexOf(character, 2);
      if (found >= 0) {
        delimiter = Math.min(delimiter, found);
      }
    }
    netloc = url.slice(2, delimiter);
    url = url.slice(delimiter);
    const open = netloc.includes("[");
    const close = netloc.includes("]");
    if (open !== close) {
      return undefined;
    }
    if (open && close && !bracketedNetlocValid(netloc)) {
      return undefined;
    }
  }
  let fragment = "";
  let query = "";
  const hash = url.indexOf("#");
  if (hash >= 0) {
    fragment = url.slice(hash + 1);
    url = url.slice(0, hash);
  }
  const question = url.indexOf("?");
  if (question >= 0) {
    query = url.slice(question + 1);
    url = url.slice(0, question);
  }
  return { scheme, netloc, path: url, query, fragment };
}

function partition(text: string, separator: string): [string, boolean, string] {
  const index = text.indexOf(separator);
  return index < 0 ? [text, false, ""] : [text.slice(0, index), true, text.slice(index + separator.length)];
}

function bracketedNetlocValid(netloc: string): boolean {
  const at = netloc.lastIndexOf("@");
  const hostAndPort = at < 0 ? netloc : netloc.slice(at + 1);
  const [before, hasOpen, bracketed] = partition(hostAndPort, "[");
  let hostname: string;
  if (hasOpen) {
    if (before !== "") {
      return false;
    }
    const [host, , port] = partition(bracketed, "]");
    if (port !== "" && !port.startsWith(":")) {
      return false;
    }
    hostname = host;
  } else {
    hostname = partition(hostAndPort, ":")[0];
  }
  if (hostname.startsWith("v")) {
    return /^v[a-fA-F0-9]+\..+$/.test(hostname);
  }
  // ipaddress.ip_address: an IPv4 address is refused in brackets, so only IPv6 passes.
  return !isIpv4(hostname) && isIpv6(hostname);
}

function isIpv4(text: string): boolean {
  if (text === "" || text.includes("/")) {
    return false;
  }
  const octets = text.split(".");
  if (octets.length !== 4) {
    return false;
  }
  return octets.every((octet) => {
    if (!/^[0-9]{1,3}$/.test(octet)) {
      return false;
    }
    if (octet !== "0" && octet.startsWith("0")) {
      return false;
    }
    return Number(octet) <= 255;
  });
}

function isIpv6(text: string): boolean {
  if (text.includes("/")) {
    return false;
  }
  const [address, hasScope, scope] = partition(text, "%");
  if (hasScope && (scope === "" || scope.includes("%"))) {
    return false;
  }
  if (address === "") {
    return false;
  }
  const parts = address.split(":");
  if (parts.length < 3) {
    return false;
  }
  if ((parts[parts.length - 1] as string).includes(".")) {
    const last = parts.pop() as string;
    if (!isIpv4(last)) {
      return false;
    }
    parts.push("0", "0");
  }
  if (parts.length > 9) {
    return false;
  }
  let skip: number | undefined;
  for (let index = 1; index < parts.length - 1; index += 1) {
    if (parts[index] === "") {
      if (skip !== undefined) {
        return false;
      }
      skip = index;
    }
  }
  let high: number;
  let low: number;
  if (skip !== undefined) {
    high = skip;
    low = parts.length - skip - 1;
    if (parts[0] === "") {
      high -= 1;
      if (high !== 0) {
        return false;
      }
    }
    if (parts[parts.length - 1] === "") {
      low -= 1;
      if (low !== 0) {
        return false;
      }
    }
    if (8 - (high + low) < 1) {
      return false;
    }
  } else {
    if (parts.length !== 8 || parts[0] === "" || parts[parts.length - 1] === "") {
      return false;
    }
    high = parts.length;
    low = 0;
  }
  const hextets = [...parts.slice(0, high), ...(low > 0 ? parts.slice(parts.length - low) : [])];
  return hextets.every((hextet) => /^[0-9a-fA-F]{1,4}$/.test(hextet));
}
