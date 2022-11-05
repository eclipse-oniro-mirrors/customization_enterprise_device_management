/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_COMMON_INCLUDE_NAPI_EDM_ERROR_ADDON_H
#define INTERFACES_KITS_COMMON_INCLUDE_NAPI_EDM_ERROR_ADDON_H

#include <string>
#include "edm_errors.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace EDM {
    napi_value CreateError(napi_env env, ErrCode errorCode);
    napi_value CreateError(napi_env env, int32_t errorCode, const std::string &errMessage);
    std::pair<int32_t, std::string> GetMessageFromReturncode(ErrCode returnCode);
    #define ASSERT_AND_THROW_PARAM_ERROR(env, assertion, message)               \
    do {                                                                       \
        if (!(assertion)) {                                                    \
            napi_throw((env), CreateError((env), (EdmReturnErrCode::PARAM_ERROR), (message)));          \
            napi_value ret = nullptr;                                      \
            return ret;                                                    \
        }                                                                    \
    } while (0)
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_COMMON_INCLUDE_NAPI_EDM_ERROR_ADDON_H
