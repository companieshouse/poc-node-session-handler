import { NextFunction, Request, RequestHandler, Response } from "express";
import expressAsyncHandler from "express-async-handler";
import onHeaders from "on-headers"
import { CookieConfig } from "../config/CookieConfig";
import { loggerInstance } from "../Logger";
import { Cookie, validateCookieSignature } from "./model/Cookie";
import { Session } from "./model/Session";
import { SessionKey } from "./keys/SessionKey";
import { SessionStore } from "./store/SessionStore";
import crypto from "crypto"

const DEFAULT_COOKIE_SECURE_FLAG = true;
const DEFAULT_COOKIE_TIME_TO_LIVE_IN_SECONDS = 3600;

export function SessionMiddleware(config: CookieConfig, sessionStore: SessionStore, createSessionWhenNotFound: boolean = false): RequestHandler {
    if (!config.cookieName) {
        throw Error("Cookie name must be defined");
    }
    if (!config.cookieDomain) {
        throw Error("Cookie domain must be defined");
    }
    if (!config.cookieSecret || config.cookieSecret.length < 24) {
        throw Error("Cookie secret must be at least 24 chars long");
    }

    return expressAsyncHandler(sessionRequestHandler(config, sessionStore, createSessionWhenNotFound));
}

const sessionRequestHandler = (config: CookieConfig, sessionStore: SessionStore, createSessionWhenNotFound: boolean = false): RequestHandler => {
    async function loadSession (sessionCookie: string): Promise<Session | undefined> {
        let cookie: Cookie;
        try {
            validateCookieSignature(sessionCookie, config.cookieSecret);
            cookie = Cookie.createFrom(sessionCookie);
            const sessionData = await sessionStore.load(cookie);
            const session = new Session(sessionData);
            session.verify();

            loggerInstance().debug(`Session successfully loaded from cookie ${sessionCookie}`);
            return session;
        } catch (sessionLoadingError) {
            if (cookie) {
                try {
                    await sessionStore.delete(cookie);
                } catch (sessionDeletionError) {
                    loggerInstance().error(`Session deletion failed for cookie ${sessionCookie} due to error: ${sessionDeletionError}`);
                }
            }

            loggerInstance().info(`Session loading failed from cookie ${sessionCookie} due to error: ${sessionLoadingError}`);
            return undefined;
        }
    }

    return async (request: Request, response: Response, next: NextFunction): Promise<any> => {
        let sessionCookie: string = request.cookies[config.cookieName];
        let originalSessionHash: string;

        onHeaders(response, () => {
            if (request.session) {
                if (hash(request.session) !== originalSessionHash) {
                    response.cookie(config.cookieName, sessionCookie, {
                        domain: config.cookieDomain,
                        path: "/",
                        httpOnly: true,
                        secure: config.cookieSecureFlag != null ? config.cookieSecureFlag : DEFAULT_COOKIE_SECURE_FLAG,
                        maxAge: (config.cookieTimeToLiveInSeconds != null ? config.cookieTimeToLiveInSeconds
                            : DEFAULT_COOKIE_TIME_TO_LIVE_IN_SECONDS) * 1000,
                        encode: String
                    })
                }
            } else {
                if (sessionCookie) {
                    response.clearCookie(config.cookieName);
                }
            }
        });

        type MethodSignature = { (cb?: () => void): void; (chunk: any, cb?: () => void): void; (chunk: any, encoding: string, cb?: () => void): void }
        response.end = new Proxy(response.end, {
            async apply (target: MethodSignature, thisArg: any, argsArg?: any): Promise<any> {
                if (request.session != null && hash(request.session) !== originalSessionHash) {
                    try {
                        await sessionStore.store(Cookie.createFrom(sessionCookie), request.session.data,
                            config.cookieTimeToLiveInSeconds != null ? config.cookieTimeToLiveInSeconds : DEFAULT_COOKIE_TIME_TO_LIVE_IN_SECONDS)
                    } catch (err) {
                        loggerInstance().error(err.message)
                    }
                }
                return target.apply(thisArg, argsArg)
            }
        })

        if (sessionCookie) {
            loggerInstance().debugRequest(request, `Session cookie ${sessionCookie} found in request: ${request.url}`);
            request.session = await loadSession(sessionCookie);
            if (request.session != null) {
                originalSessionHash = hash(request.session)
            }
        } else {
            loggerInstance().debugRequest(request, `Session cookie not found in request ${request.url}`);
            delete request.session;
        }

        if (request.session == null && createSessionWhenNotFound) {
            const cookie = Cookie.createNew(config.cookieSecret)
            request.session = new Session({
                [SessionKey.Id]: cookie.sessionId
            });
            loggerInstance().debugRequest(request, `Session cookie ${(sessionCookie = cookie.value)} has been created for request: ${request.url}`);
        }

        next();
    };
}

const hash = (session: Session): string => {
    return crypto
        .createHash("sha1")
        .update(JSON.stringify(session.data), "utf8")
        .digest("hex")
}
