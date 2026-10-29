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
#include "napi_edm_common.h"
#include "napi_edm_error.h"
#include "telephony_manager_proxy.h"
#include "call_log_info.h"
#include "want.h"

namespace OHOS {
namespace EDM {

struct AsyncCallLogCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    TelephonyQueryConfig queryConfig;
    std::vector<CallLogInfo> callLogs;
};

struct AsyncSmsMessageCallbackInfo : AsyncCallbackInfo {
    TelephonyQueryConfig queryConfig;
    std::vector<SmsMessageInfo> messages;
};

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
    static napi_value GetCallPolicyNumbersCommon(napi_env env, napi_callback_info info,
        const std::string &callPolicyType, const std::string &methodName);
    static napi_value HangupCalling(napi_env env, napi_callback_info info);
    static napi_value ActiveSim(napi_env env, napi_callback_info info);
    static napi_value DeactiveSim(napi_env env, napi_callback_info info);
    static napi_value SetDefaultDataSim(napi_env env, napi_callback_info info);
    static napi_value GetDefaultDataSim(napi_env env, napi_callback_info info);
    static napi_value GetCallLogs(napi_env env, napi_callback_info info);
    static void NativeGetCallLogs(napi_env env, void *data);
    static void NativeGetCallLogsComplete(napi_env env, napi_status status, void *data);
    static void ConvertVectorCallLogToJs(napi_env env, const std::vector<CallLogInfo> &callLogs,
        napi_value &result);
    static void ConvertVectorSmsMessageToJs(napi_env env, const std::vector<SmsMessageInfo> &messages,
        napi_value &result);
    static napi_value GetSmsMessages(napi_env env, napi_callback_info info);
    static void NativeGetSmsMessages(napi_env env, void *data);
    static void NativeGetSmsMessagesComplete(napi_env env, napi_status status, void *data);
    static bool CheckVectorStringLength(const std::vector<std::string> &array);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_TELEPHONY_MANAGER_INCLUDE_TELEPHONY_MANAGER_ADDON_H
