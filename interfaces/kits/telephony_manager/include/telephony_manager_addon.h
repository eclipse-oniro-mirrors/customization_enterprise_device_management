/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_TELEPHONY_MANAGER_INCLUDE_TELEPHONY_MANAGER_ADDON_H
#define INTERFACES_KITS_TELEPHONY_MANAGER_INCLUDE_TELEPHONY_MANAGER_ADDON_H

#include "napi_edm_adapter.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_edm_error.h"
#include "telephony_manager_proxy.h"
#include "want.h"

namespace OHOS {
namespace EDM {

class TelephonyManagerAddon {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value SetSimDisabled(napi_env env, napi_callback_info info);
    static napi_value SetSimEnabled(napi_env env, napi_callback_info info);
    static napi_value IsSimDisabled(napi_env env, napi_callback_info info);
    static napi_value AddOutgoingCallPolicyNumbers(napi_env env, napi_callback_info info);
    static napi_value RemoveOutgoingCallPolicyNumbers(napi_env env, napi_callback_info info);
    static napi_value GetOutgoingCallPolicyNumbers(napi_env env, napi_callback_info info);
    static napi_value AddIncomingCallPolicyNumbers(napi_env env, napi_callback_info info);
    static napi_value RemoveIncomingCallPolicyNumbers(napi_env env, napi_callback_info info);
    static napi_value GetIncomingCallPolicyNumbers(napi_env env, napi_callback_info info);
    static napi_value HangupCalling(napi_env env, napi_callback_info info);
    static bool CheckVectorStringLength(const std::vector<std::string> &array);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_TELEPHONY_MANAGER_INCLUDE_TELEPHONY_MANAGER_ADDON_H
