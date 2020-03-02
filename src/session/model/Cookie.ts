import { Either, Left, Right, Tuple } from "purify-ts";
import { Failure } from "../../error/FailureType";
import { VerifiedSession } from "./Session";
import { SessionKey } from "../keys/SessionKey";
import {
    generateSignature,
    generateSessionId,
    extractSignature,
    extractSessionId
} from "../../utils/CookieUtils";
import { SessionLengthError, SessionSecretNotSet, SignatureCheckError } from "../../error/ErrorFunctions";
import { CookieConstants } from "../../utils/CookieConstants";
import { Session } from "../..";

const validateCookieSignature = (cookieSecret: string) => (cookieString: string): Either<Failure, Tuple<string, string>> => {
    if (!cookieSecret) {
        return Left(Failure(SessionSecretNotSet));
    }

    const sig = extractSignature(cookieString);

    const expectedSig = generateSignature(cookieString, cookieSecret);

    if (sig !== expectedSig) {
        return Left(Failure(SignatureCheckError(expectedSig, sig)));
    }

    return Right(Tuple(extractSessionId(cookieString), sig));
};

const validateSessionCookieLength = (sessionCookie: string): Either<Failure, string> => {
    if (sessionCookie.length < CookieConstants._cookieValueLength) {
        return Left(Failure(SessionLengthError(CookieConstants._cookieValueLength, sessionCookie.length)));
    }
    return Right(sessionCookie);

};

export class Cookie {

    private constructor(public readonly sessionId: string, public readonly signature: string) {
        if (!sessionId) {
            throw new Error("Session ID is required");
        }
        if (!signature) {
            throw new Error("Signature is required");
        }
    }

    public get value(): string {
        return this.sessionId + this.signature;
    }

    public static create(cookieSecret: string): Cookie {
        const sessionId = generateSessionId();
        const signature = generateSignature(sessionId, cookieSecret);
        return new Cookie(sessionId, signature);
    }

    public static representationOf(session: Session, cookieSecret: string): Cookie {
        const id = session.data[SessionKey.Id];
        return new Cookie(id, generateSignature(id, cookieSecret));
    };

    public static validateCookieString = (cookieSecret: string) => (cookieString: string): Either<Failure, Cookie> => {
        return Either.of<Failure, string>(cookieString)
            .chain(validateSessionCookieLength)
            .chain(validateCookieSignature(cookieSecret))
            .map(tuple => new Cookie(tuple[0], tuple[1]));
    };

}