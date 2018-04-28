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
    "lodash/isString",
    "./sha256"
], function(isEmpty, isString, hash) {
    "use strict";

    return function(pwdClear, userId) {
        if (!isString(userId) || isEmpty(userId)) {
            throw new Error("Invalid 'userId' parameter specified");
        }
        if (!isString(pwdClear) || isEmpty(pwdClear)) {
            throw new Error("Invalid 'pwdClear' parameter specified");
        }
        // https://security.stackexchange.com/a/39498/166297
        var salt = hash(userId);
        var joined = [pwdClear, salt].join("\n");
        return hash(joined);
    };
});
