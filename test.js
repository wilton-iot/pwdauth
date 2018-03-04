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
    // modules
    "assert",
    "moment",
    "lodash/isArray",
    "lodash/isNil",
    "lodash/isObject",
    // auth api
    "pwdauth/authErrors",
    "pwdauth/authenticate",
    "pwdauth/authorize",
    // auth callbacks
    "pwdauth/createPasswordHash",
    "pwdauth/createRequestHash",
    "pwdauth/createTokenHash"
], function(
        assert, moment, isArray, isNil, isObject, // modules
        authErrors, authenticate, authorize, // auth api
        createPasswordHash, createRequestHash, createTokenHash // auth callbacks
) {
    "use strict";

    print("test: pwdauth");

    // prepare env

    function loadUser(userId) {
        // DB access logic or cache lookup is implied here
        if ("foo" === userId){
            return {
                pwdHash: createPasswordHash("foo", "secret1"),
                sessionKey: "boo",
                sessionDurationMinutes: 42,
                roles: ["foo1", "bar1"]
            };
        }
        return null;
    }

    function myAuthenticate(request) {
        return authenticate(loadUser, createRequestHash, createTokenHash, request);
    }

    function myAuthorize(token) {
        return authorize(loadUser, createTokenHash, token);
    }


    // test success

    // process user input
    var userId = "foo";
    var pwdClear = "secret1";
    var pwdHash = createPasswordHash(userId, pwdClear);
    var timestamp = moment();

    // obtain token
    var token = myAuthenticate({
        userid: userId,
        timestamp: timestamp.format(),
        hash: createRequestHash(userId, pwdHash, timestamp)
    });

    assert(isObject(token));
    assert(isNil(token.error));

    // get roles
    var roles = myAuthorize(token);

    assert(isArray(roles));
    assert(isNil(roles.error));
    assert.equal(roles.length, 2);


    // test authenticate error messages

    assert.equal(authenticate({foo: "bar"}).error, authErrors.INVALID_CALLBACK);
    assert.equal(myAuthenticate(null).error, authErrors.REQUEST_NOT_WELL_FORMED);
    assert.equal(myAuthenticate("foo").error, authErrors.REQUEST_NOT_WELL_FORMED);
    assert.equal(myAuthenticate({foo: "bar"}).error, authErrors.REQUEST_NOT_WELL_FORMED);
    assert.equal(myAuthenticate({
        userid: userId,
        timestamp: timestamp.format("MM.DD.YYYY"),
        hash: "..."
    }).error, authErrors.INVALID_DATE_FORMAT);
    assert.equal(myAuthenticate({
        userid: "foo1",
        timestamp: timestamp.format(),
        hash: "..."
    }).error, authErrors.USER_NOT_FOUND);
    assert.equal(myAuthenticate({
        userid: "foo",
        timestamp: timestamp.format(),
        hash: "..."
    }).error, authErrors.INVALID_REQUEST_HASH);


    // test authorize error messages

    assert.equal(authorize({foo: "bar"}).error, authErrors.INVALID_CALLBACK);
    assert.equal(myAuthorize(null).error, authErrors.TOKEN_NOT_WELL_FORMED);
    assert.equal(myAuthorize("foo").error, authErrors.TOKEN_NOT_WELL_FORMED);
    assert.equal(myAuthorize({foo: "bar"}).error, authErrors.TOKEN_NOT_WELL_FORMED);
    assert.equal(myAuthorize({
        userid: userId,
        until: timestamp.format("MM.DD.YYYY"),
        hash: "..."
    }).error, authErrors.INVALID_DATE_FORMAT);
    assert.equal(myAuthorize({
        userid: userId,
        until: moment().add(-1, "minutes").format(),
        hash: "..."
    }).error, authErrors.TOKEN_EXPIRED);
    assert.equal(myAuthorize({
        userid: userId,
        until: moment().add(1, "minutes").format(),
        hash: "..."
    }).error, authErrors.INVALID_TOKEN_HASH);

    // no-op to run directly

    return {
        main: function() {
        }
    };
});
