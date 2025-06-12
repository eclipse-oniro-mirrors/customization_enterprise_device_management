/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_RESTRICTIONS_INCLUDE_RESTRICTIONS_ADDON_H
#define INTERFACES_KITS_RESTRICTIONS_INCLUDE_RESTRICTIONS_ADDON_H

#include "napi_edm_adapter.h"
#include "napi_edm_error.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "restrictions_proxy.h"

namespace OHOS {
namespace EDM {
struct AsyncRestrictionsCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    bool isDisabled = false;
    bool hasAdmin = false;
};

class RestrictionsAddon {
public:
    static napi_value Init(napi_env env, napi_value exports);
private:
    static napi_value SetPrinterDisabled(napi_env env, napi_callback_info info);
    static napi_value IsPrinterDisabled(napi_env env, napi_callback_info info);
    static napi_value SetHdcDisabled(napi_env env, napi_callback_info info);
    static napi_value IsHdcDisabled(napi_env env, napi_callback_info info);
    static napi_value DisableMicrophone(napi_env env, napi_callback_info info);
    static napi_value IsMicrophoneDisabled(napi_env env, napi_callback_info info);
    static napi_value SetFingerprintAuthDisabled(napi_env env, napi_callback_info info);
    static napi_value IsFingerprintAuthDisabled(napi_env env, napi_callback_info info);
    static napi_value SetDisallowedPolicy(napi_env env, napi_callback_info info);
    static napi_value GetDisallowedPolicy(napi_env env, napi_callback_info info);
    static napi_value SetDisallowedPolicyForAccount(napi_env env, napi_callback_info info);
    static napi_value GetDisallowedPolicyForAccount(napi_env env, napi_callback_info info);
    static napi_value AddDisallowedListForAccount(napi_env env, napi_callback_info info);
    static napi_value RemoveDisallowedListForAccount(napi_env env, napi_callback_info info);
    static napi_value AddOrRemoveDisallowedListForAccount(napi_env env, napi_callback_info info, bool isAdd);
    static napi_value GetDisallowedListForAccount(napi_env env, napi_callback_info info);
    static napi_value SetPolicyDisabled(napi_env env, napi_callback_info info, int policyCode);
    static napi_value IsPolicyDisabled(napi_env env, napi_callback_info info, int policyCode);
    static napi_value SetPolicyDisabledSync(napi_env env, napi_callback_info info, int policyCode);
    static napi_value IsPolicyDisabledSync(napi_env env, napi_callback_info info, int policyCode);
    static napi_value SetUserRestriction(napi_env env, napi_callback_info info);
    static void NativeSetPolicyDisabled(napi_env env, void *data);
    static void NativeIsPolicyDisabled(napi_env env, void *data);
    static void SetPolicyDisabledCommon(AddonMethodSign &addonMethodSign, int policyCode);
    static OHOS::ErrCode NativeGetDisallowedPolicyForAccount(bool hasAdmin, AppExecFwk::ElementName &elementName,
        std::uint32_t ipcCode, int32_t accountId, bool &disallow);
    static std::shared_ptr<RestrictionsProxy> restrictionsProxy_;
    static std::unordered_map<std::string, uint32_t> labelCodeMap;
    static std::unordered_map<std::string, uint32_t> itemCodeMap;
    static std::unordered_map<std::string, uint32_t> itemQueryCodeMap;
    static std::vector<uint32_t> multiPermCodes;
    static std::unordered_map<std::string, uint32_t> labelCodeMapForAccount;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_RESTRICTIONS_INCLUDE_RESTRICTIONS_ADDON_H
