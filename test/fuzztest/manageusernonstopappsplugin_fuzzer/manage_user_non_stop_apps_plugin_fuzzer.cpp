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

#include "manage_user_non_stop_apps_plugin_fuzzer.h"

#include <system_ability_definition.h>
#include "common_fuzzer.h"
#include "cJSON.h"
#define protected public
#define private public
#include "manage_user_non_stop_apps_plugin.h"
#include "manage_user_non_stop_apps_serializer.h"
#undef protected
#undef private
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "ienterprise_device_mgr.h"
#include "func_code.h"
#include "manage_user_non_stop_apps_info.h"
#include "message_parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 24;
constexpr int32_t WITHOUT_USERID = 0;
constexpr const char *WITHOUT_PERMISSION_TAG = "";

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    TEST::Utils::SetEdmPermissions();
    return 0;
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < MIN_SIZE) {
        return 0;
    }
    int32_t stringSize = size / 9;
    int32_t pos = 0;
    AppExecFwk::ElementName admin;
    admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
    admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
    ManageUserNonStopAppsPlugin plugin;
    int32_t funcCode = CommonFuzzer::GetU32Data(data);
    int32_t userId = CommonFuzzer::GetU32Data(data);
    int32_t systemAbilityId = CommonFuzzer::GetU32Data(data);
    MessageParcel parcel;
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(WITHOUT_USERID);
    parcel.WriteParcelable(&admin);
    parcel.WriteString(WITHOUT_PERMISSION_TAG);
    std::vector<ApplicationInstance> userNonStopApps;
    int32_t arraySize = CommonFuzzer::GetU32Data(data) % 11;
    for (int i = 0; i < arraySize; i++) {
        ApplicationInstance instance;
        instance.appIdentifier = CommonFuzzer::GetString(data, pos, stringSize, size);
        instance.accountId = CommonFuzzer::GetU32Data(data);
        instance.appIndex = CommonFuzzer::GetU32Data(data);
        userNonStopApps.emplace_back(std::move(instance));
    }
    std::vector<ApplicationMsg> userNonStopBundles;
    for (int i = 0; i < arraySize; i++) {
        ApplicationMsg instance;
        instance.bundleName = CommonFuzzer::GetString(data, pos, stringSize, size);
        instance.accountId = CommonFuzzer::GetU32Data(data);
        instance.appIndex = CommonFuzzer::GetU32Data(data);
        userNonStopBundles.emplace_back(std::move(instance));
    }
    ApplicationInstanceHandle::WriteApplicationInstanceVector(parcel, userNonStopApps);
    MessageParcel reply;
    HandlePolicyData policyData;
    std::string currentPolicyData = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string mergePolicyData = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string currentJsonData = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string mergeJsonData = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string othersMergePolicyData = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::vector<ManageUserNonStopAppInfo> currentData;
    ManageUserNonStopAppsSerializer::GetInstance()->Deserialize(currentPolicyData, currentData);
    std::vector<ManageUserNonStopAppInfo> mergeData;
    ManageUserNonStopAppsSerializer::GetInstance()->Deserialize(mergePolicyData, mergeData);
    std::vector<ManageUserNonStopAppInfo> needRemovePolicy =
        ManageUserNonStopAppsSerializer::GetInstance()->SetIntersectionPolicyData(userNonStopBundles,
        currentData);
    std::vector<ManageUserNonStopAppInfo> needResetPolicy =
        ManageUserNonStopAppsSerializer::GetInstance()->SetDifferencePolicyData(mergeData, needRemovePolicy);
    std::vector<ManageUserNonStopAppInfo> needRemoveMergePolicy =
        ManageUserNonStopAppsSerializer::GetInstance()->SetNeedRemoveMergePolicyData(mergeData, needRemovePolicy);
    plugin.OnHandlePolicy(funcCode, parcel, reply, policyData, userId);
    plugin.OnSetPolicy(userNonStopBundles, currentData, mergeData);
    plugin.OnRemovePolicy(userNonStopBundles, currentData, mergeData);
    plugin.SetOtherModulePolicy(needResetPolicy);
    plugin.RemoveOtherModulePolicy(needResetPolicy, needRemovePolicy);
    plugin.OnGetPolicy(currentPolicyData, parcel, reply, userId);
    plugin.OnAdminRemove(adminName, currentJsonData, mergeJsonData, userId);
    plugin.GetOthersMergePolicyData(adminName, userId, othersMergePolicyData);
    plugin.OnOtherServiceStart(systemAbilityId);
    plugin.FilterUninstalledBundle(currentData, needRemoveMergePolicy);
    std::string appPolicyJsonStr;
    for (const auto &item : needResetPolicy) {
        plugin.ConvertAppPolicyToJsonStr(item, appPolicyJsonStr);
    }
    return 0;
}
} // namespace EDM
} // namespace OHOS