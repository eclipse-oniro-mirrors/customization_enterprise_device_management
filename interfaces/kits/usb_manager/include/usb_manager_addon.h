/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_USB_MANAGER_INCLUDE_USB_MANAGER_ADDON_H
#define INTERFACES_KITS_USB_MANAGER_INCLUDE_USB_MANAGER_ADDON_H

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_edm_common.h"
#include "napi_edm_error.h"
#include "want.h"

namespace OHOS {
namespace EDM {
struct AsyncSetUsbPolicyCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    int32_t policy;
};

constexpr int32_t READ_WRITE = 0;
constexpr int32_t READ_ONLY = 1;
constexpr int32_t USB_POLICY[] = {READ_WRITE, READ_ONLY};

class UsbManagerAddon {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value SetUsbPolicy(napi_env env, napi_callback_info info);
    static void CreateUsbPolicyEnum(napi_env env, napi_value value);
    static void NativeSetUsbPolicy(napi_env env, void *data);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_USB_MANAGER_INCLUDE_USB_MANAGER_ADDON_H
