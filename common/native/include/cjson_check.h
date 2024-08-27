/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMMON_NATIVE_INCLUDE_CJSON_CHECK_H
#define COMMON_NATIVE_INCLUDE_CJSON_CHECK_H
#include "edm_log.h"
#include "cJSON.h"

namespace OHOS {
namespace EDM {
#define CJSON_CREATE_OBJECT_AND_CHECK(obj, ret)  \
    do {                                         \
        (obj) = cJSON_CreateObject();            \
        if ((obj) == nullptr) {                  \
            EDMLOGE("cJSON_CreateObject error"); \
            return (ret);                        \
        }                                        \
    } while (0)

#define CJSON_CREATE_OBJECT_AND_CHECK_AND_CLEAR(obj, ret, root)  \
    do {                                                         \
        (obj) = cJSON_CreateObject();                            \
        if ((obj) == nullptr) {                                  \
            EDMLOGE("cJSON_CreateObject error");                 \
            cJSON_Delete((root));                                \
            return (ret);                                        \
        }                                                        \
    } while (0)

#define CJSON_CREATE_ARRAY_AND_CHECK(obj, ret)  \
    do {                                        \
        (obj) = cJSON_CreateArray();            \
        if ((obj) == nullptr) {                 \
            EDMLOGE("cJSON_CreateArray error"); \
            return (ret);                       \
        }                                       \
    } while (0)
} // namespace EDM
} // namespace OHOS
#endif // COMMON_NATIVE_INCLUDE_CJSON_CHECK_H
