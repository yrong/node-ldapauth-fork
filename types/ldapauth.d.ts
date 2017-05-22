/// <reference types="ldapjs"/>
/// <reference types="node"/>

import { EventEmitter } from "events";
import { ClientOptions, ErrorCallback } from 'ldapjs';

declare namespace LdapAuth {
    type Scope = 'base' | 'one' | 'sub';

    interface Callback {
        (error: Error|string, result?: any): void;
    }

    interface GroupSearchFilterFunction {
        /**
         * Construct a group search filter from user object
         *
         * @param user The user retrieved and authenticated from LDAP
         */
        (user: any): string;
    }

    interface Options extends ClientOptions {
        /**
         * The base DN from which to search for users by username.
         * E.g. 'ou=users,o=example.com'
         */
        searchBase: string;
        /**
         * LDAP search filter with which to find a user by username, e.g.
         * '(uid={{username}})'. Use the literal '{{username}}' to have the
         * given username be interpolated in for the LDAP search.
         */
        searchFilter: string;
        /**
         * Scope of the search. Default: 'sub'
         */
        searchScope?: Scope;
        /**
         * Array of attributes to fetch from LDAP server. Default: all
         */
        searchAttributes?: string[];

        /**
         * The base DN from which to search for groups. If defined,
         * also groupSearchFilter must be defined for the search to work.
         */
        groupSearchBase?: string;
        /**
         * LDAP search filter for groups. The following literals are
         * interpolated from the found user object: '{{dn}}' the property
         * configured with groupDnProperty. Optionally you can also assign a
         * function instead The found user is passed to the function and it
         * should return a valid search filter for the group search.
         */
        groupSearchFilter?: string | GroupSearchFilterFunction;
        /**
         * Scope of the search. Default: 'sub'
         */
        groupSearchScope?: Scope;
        /**
         * Array of attributes to fetch from LDAP server. Default: all
         */
        groupSearchAttributes?: string[];

        /**
         * Property of user to bind against client e.g. 'name', 'email'.
         * Default: 'dn'
         */
        bindProperty?: string;
        /**
         * The property of user object to use in '{{dn}}' interpolation of
         * groupSearchFilter. Default: 'dn'
         */
        groupDnProperty?: string;

        /**
         * Set to true to add property '_raw' containing the original buffers
         * to the returned user object. Useful when you need to handle binary
         * attributes
         */
        includeRaw?: boolean;

        /**
         * If true, then up to 100 credentials at a time will be cached for
         * 5 minutes.
         */
        cache?: boolean;
    }

    class LdapAuth extends EventEmitter {
        /**
         * @constructor
         * @param opts
         */
        constructor(opts: Options);

        /**
         * Authenticate against LDAP server with given credentials
         *
         * @param username Username
         * @param password Password
         * @param callback Standard callback
         */
        authenticate(username: string, password: string, callback: Callback): void;

        /**
         * Unbind both admin and client connections
         *
         * @param callback Error callback
         */
        close(callback: ErrorCallback): void;
    }
}

export = LdapAuth;
