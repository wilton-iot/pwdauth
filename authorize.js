/*
 * Copyright 2018, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

define([
    "lodash/isArray",
    "lodash/isEmpty",
    "lodash/isFunction",
    "lodash/isObject",
    "lodash/isString",
    "moment",
    "./authErrors",
    "./stringsEqual"
], function(isArray, isEmpty, isFunction, isObject, isString, moment, authErrors, stringsEqual) {
    "use strict";

    return function(loadUser, createTokenHash, token) {
        // check callbacks
        if (!isFunction(loadUser) || !isFunction(createTokenHash)) {
            return {
                error: authErrors.INVALID_CALLBACK
            };
        }

        // check token well-formed
        if (!isObject(token) || 
                !token.hasOwnProperty("userid") || !isString(token.userid) || isEmpty(token.userid) ||
                !token.hasOwnProperty("until") || !isString(token.until) || isEmpty(token.until) ||
                !token.hasOwnProperty("hash") || !isString(token.hash) || isEmpty(token.hash)) {
            return {
                error: authErrors.TOKEN_NOT_WELL_FORMED
            };
        }

        // check ISO 8601 date format
        var tokDate = moment(token.until, moment.ISO_8601, true);
        if (!tokDate.isValid()) {
            return {
                error: authErrors.INVALID_DATE_FORMAT
            };
        }

        // check expiry date
        if (moment().isAfter(tokDate)) {
            return {
                error: authErrors.TOKEN_EXPIRED
            };
        }

        // load user
        var user = loadUser(token.userid);
        if (!isObject(user)) {
            return {
                error: authErrors.USER_NOT_FOUND
            };
        }
        if (!user.hasOwnProperty("sessionKey") || !isString(user.sessionKey) || isEmpty(user.sessionKey) ||
                !user.hasOwnProperty("roles") || !isArray(user.roles)) {
            return {
                error: authErrors.INVALID_USER_LOADED,
                user: user
            };
        }

        // re-create token hash and compare it
        var localHash = createTokenHash(token.userid, user.sessionKey, tokDate);
        if (!stringsEqual(localHash, token.hash)) {
            return {
                error: authErrors.INVALID_TOKEN_HASH
            };
        }

        // return roles
        return user.roles;
    };
});
