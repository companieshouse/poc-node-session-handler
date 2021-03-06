import * as crypto from "crypto";
import { CookieConstants } from "./CookieConstants";

export function generateSessionId(): string {
    return generateRandomBytesBase64(CookieConstants._idOctets);
}

export function generateRandomBytesBase64(numBytes: number): string {
    return crypto.randomBytes(numBytes).toString("base64");
}

export function generateSignature(id: string, secret: string): string {
    const adjustedId = extractSessionId(id);
    const value = crypto
        .createHash("sha1")
        .update(adjustedId + secret)
        .digest("base64");
    return value.substr(0, value.indexOf("="));
}

export function extractSessionId(sessionCookie: string): string {
    return sessionCookie.substring(0, CookieConstants._signatureStart);
}

export function extractSignature(sessionCookie: string): string {
    return sessionCookie.substring(CookieConstants._signatureStart);
}
