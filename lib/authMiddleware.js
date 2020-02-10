"use strict";

const authMiddleware = function (routeRoles) {

    const checkRoles = routeRoles !== undefined;
    let roles = Array.isArray(routeRoles) ?
        routeRoles :
        [routeRoles];

    return function (request, response, next) {

        // Check roles if roles supplied, else just check if signed in.

        if (request.chSession.isSignedIn) { // And role
            
        } else {
            // Redirect to signin page with referer
        }

        return next();
    };
};