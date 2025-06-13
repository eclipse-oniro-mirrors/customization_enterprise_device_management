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

#ifndef INTERFACES_KITS_COMMON_INCLUDE_NAPI_EDM_ADAPTER_H
#define INTERFACES_KITS_COMMON_INCLUDE_NAPI_EDM_ADAPTER_H

#include <string>
#include <vector>
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_edm_common.h"

namespace OHOS {
namespace EDM {

enum class EdmAddonCommonType {
    VOID = 0,
    ELEMENT_NULL = 1,
    ELEMENT = 2,
    UINT32 = 3,
    STRING = 4,
    ARRAY_STRING = 5,
    BOOLEAN = 6,
    USERID = 7,
    INT32 = 8,
    INT64 = 9,
    ARRAY_INT32 = 10,
    CUSTOM = 100,
};

enum class MethodAttribute {
    HANDLE = 0,
    GET = 1,
    OPERATE_ADMIN = 2,
};

struct BusinessError {
    int32_t errorCode = 0;
    std::string errorMessage;
};

struct AddonMethodSign;

typedef bool (*JsArgToData)(napi_env env, napi_value argv, MessageParcel &data, const AddonMethodSign &methodSign);

struct AddonMethodSign {
    std::string name;
    // Parameter type
    std::vector<EdmAddonCommonType> argsType;
    // Parameter handler pointer
    std::vector<JsArgToData> argsConvert;
    std::string apiVersionTag;
    MethodAttribute methodAttribute = MethodAttribute::GET;
    int32_t defaultArgSize = 0;
    int32_t policyCode = 0;
};

struct AsyncAddonData {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;
};

struct AdapterAddonData : public AsyncCallbackInfo {
    // Business parameters
    MessageParcel data;
    // Business callback error
    BusinessError error;
    // Business callback result data
    napi_value result;
};

napi_value JsObjectToData(napi_env env, napi_callback_info info, const AddonMethodSign &methodSign,
    AdapterAddonData *addonData, bool isAsync = false);

napi_value AddonMethodAdapter(napi_env env, napi_callback_info info, const AddonMethodSign &methodSign,
    napi_async_execute_callback execute, napi_async_complete_callback complete);
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_COMMON_INCLUDE_NAPI_EDM_ADAPTER_H
