import { type LookupAddress, type LookupOptions, lookup } from "node:dns";
import { isIP, isIPv4 } from "node:net";
import { Agent, buildConnector, fetch } from "undici";
import type { Fetch } from "unauth/n";

const PRIVATE_V4: [base: string, bits: number][] = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
];

const connector = buildConnector({ lookup: publicLookup });

const agent = new Agent({
  connect: (options, callback) => {
    const host = options.hostname.replace(/^\[|\]$/g, "");
    if (isIP(host) && !isPublicAddress(host)) return callback(refused(host), null);
    connector(options, callback);
  },
});

export const publicFetch: Fetch = (input, init) =>
  fetch(input as string, { ...init, dispatcher: agent } as never) as unknown as Promise<Response>;

function publicLookup(
  hostname: string,
  options: LookupOptions,
  callback: (error: Error | null, address: string | LookupAddress[], family?: number) => void,
): void {
  lookup(hostname, { ...options, all: true }, (error, addresses) => {
    if (error) return callback(error, []);
    const [first] = addresses;
    if (!first || addresses.some(({ address }) => !isPublicAddress(address))) {
      return callback(refused(hostname), []);
    }
    if (options.all) return callback(null, addresses);
    callback(null, first.address, first.family);
  });
}

function isPublicAddress(address: string): boolean {
  if (isIPv4(address)) return !PRIVATE_V4.some(([base, bits]) => sameBits(address, base, bits));
  const words = ipv6Words(address);
  const [w0 = 0, w1 = 0, , , , w5 = 0, w6 = 0, w7 = 0] = words;
  const embedded = `${w6 >> 8}.${w6 & 255}.${w7 >> 8}.${w7 & 255}`;
  if (words.slice(0, 5).every((word) => word === 0) && (w5 === 0 || w5 === 0xffff)) {
    return isPublicAddress(embedded);
  }
  if (w0 === 0x64 && w1 === 0xff9b && words.slice(2, 6).every((word) => word === 0)) {
    return isPublicAddress(embedded);
  }
  if ((w0 & 0xfe00) === 0xfc00 || (w0 & 0xffc0) === 0xfe80 || (w0 & 0xff00) === 0xff00) {
    return false;
  }
  return !(w0 === 0x2001 && w1 === 0x0db8);
}

function ipv6Words(address: string): number[] {
  const words = (part: string) =>
    part === ""
      ? []
      : part.split(":").flatMap((word) => {
          if (!word.includes(".")) return [Number.parseInt(word, 16)];
          const [a = 0, b = 0, c = 0, d = 0] = word.split(".").map(Number);
          return [(a << 8) | b, (c << 8) | d];
        });
  const [head = "", tail] = address.toLowerCase().split("%", 1)[0].split("::");
  const left = words(head);
  const right = tail === undefined ? [] : words(tail);
  return [...left, ...Array.from({ length: 8 - left.length - right.length }, () => 0), ...right];
}

function sameBits(address: string, base: string, bits: number): boolean {
  const value = (ip: string) => ip.split(".").reduce((sum, octet) => sum * 256 + Number(octet), 0);
  const scale = 2 ** (32 - bits);
  return Math.floor(value(address) / scale) === Math.floor(value(base) / scale);
}

function refused(host: string): Error {
  return new Error(`Refused to connect to ${host}: not a public address.`);
}
