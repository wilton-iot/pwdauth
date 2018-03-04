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
    "lodash/isEmpty",
    "lodash/isFunction",
    "lodash/isInteger",
    "lodash/isObject",
    "lodash/isString",
    "moment",
    "./authErrors",
    "./stringsEqual"
], function(isEmpty, isFunction, isInteger, isObject, isString, moment, authErrors, stringsEqual) {
    "use strict";

    return function(loadUser, createRequestHash, createTokenHash, request) {
        // check callbacks
        if (!isFunction(loadUser) || !isFunction(createRequestHash) || !isFunction(createTokenHash)) {
            return {
                error: authErrors.INVALID_CALLBACK
            };
        }

        // check request well-formed
        if (!isObject(request) || 
                !request.hasOwnProperty("userid") || !isString(request.userid) || isEmpty(request.userid) ||
                !request.hasOwnProperty("timestamp") || !isString(request.timestamp) || isEmpty(request.timestamp) ||
                !request.hasOwnProperty("hash") || !isString(request.hash) || isEmpty(request.hash)) {
            return {
                error: authErrors.REQUEST_NOT_WELL_FORMED
            };
        }

        // check ISO 8601 date format
        var reqDate = moment(request.timestamp, moment.ISO_8601, true);
        if (!reqDate.isValid()) {
            return {
                error: authErrors.INVALID_DATE_FORMAT
            };
        }

        // load user
        var user = loadUser(request.userid);
        if (!isObject(user)) {
            return {
                error: authErrors.USER_NOT_FOUND
            };
        }
        if (!user.hasOwnProperty("pwdHash") || !isString(user.pwdHash) || isEmpty(user.pwdHash) ||
                !user.hasOwnProperty("sessionKey") || !isString(user.sessionKey) || isEmpty(user.sessionKey) ||
                !user.hasOwnProperty("sessionDurationMinutes") || !isInteger(user.sessionDurationMinutes)) {
            return {
                error: authErrors.INVALID_USER_LOADED,
                user: user
            };
        }

        // re-create request hash and compare it
        var localHash = createRequestHash(request.userid, user.pwdHash, reqDate);
        if (!stringsEqual(localHash, request.hash)) {
            return {
                error: authErrors.INVALID_REQUEST_HASH
            };
        }

        // calculate effective start date and create auth token
        var now = moment();
        var effectiveDate = reqDate.isBefore(now) ? reqDate : now;
        var validUntil = moment(effectiveDate).add(user.sessionDurationMinutes, "minutes");
        return {
            userid: request.userid,
            until: validUntil.format(),
            hash: createTokenHash(request.userid, user.sessionKey, validUntil)
        };
    };
});
