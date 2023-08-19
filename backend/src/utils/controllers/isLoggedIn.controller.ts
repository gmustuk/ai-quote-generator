import { NextFunction, Request, Response } from "express";
import { verify, VerifyErrors } from "jsonwebtoken";
import { IncomingHttpHeaders } from "http";
import { Status } from "../interfaces/Status";
import { Profile } from "../models/Profile";

export function isLoggedIn(request: Request, response: Response, next: NextFunction): any {
    const unverifiedJwtToken: string | undefined = getJwtTokenFromHeader(request.headers);

    if (unverifiedJwtToken) {
        const result: unknown = verify(
            unverifiedJwtToken,
            signature(request),
            { maxAge: '3hr' },
            (error: VerifyErrors | null): boolean => error == null
        ) as unknown;

        if (result as boolean && isSessionActive(sessionProfile(request))) {
            return next();
        }
    }


    return next();
}

// Helper functions
const sessionProfile = (request: Request): Profile | undefined => request.session?.profile ?? undefined;

const signature = (request: Request): string => request.session?.signature ?? 'no signature';

const isSessionActive = (isProfileActive: Profile | undefined): boolean => (isProfileActive !== undefined);

const getJwtTokenFromHeader = (headers: IncomingHttpHeaders): string | undefined => {
    return headers.authorization;
};
