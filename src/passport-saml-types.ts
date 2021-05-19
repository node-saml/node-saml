import * as passport from "passport";

export interface AuthenticateOptions extends passport.AuthenticateOptions {
  samlFallback?: "login-request" | "logout-request";
  additionalParams?: Record<string, any>;
}

export interface AuthorizeOptions extends AuthenticateOptions {
  samlFallback?: "login-request" | "logout-request";
}
