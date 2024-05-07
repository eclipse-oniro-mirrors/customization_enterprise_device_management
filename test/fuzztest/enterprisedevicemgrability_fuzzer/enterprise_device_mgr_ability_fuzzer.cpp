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

#include "enterprise_device_mgr_ability_fuzzer.h"

#include "common_event_data.h"
#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "get_data_template.h"
#include "message_parcel.h"
#define protected public
#define private public
#include "enterprise_device_mgr_ability.h"
#undef protected
#undef private
#include "ienterprise_device_mgr.h"
#include "securec.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 64;

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < MIN_SIZE) {
        return 0;
    }
    g_data = data;
    g_size = size;
    g_pos = 0;

    TEST::Utils::SetEdmInitialEnv();
    sptr<EnterpriseDeviceMgrAbility> enterpriseDeviceMgrAbility = EnterpriseDeviceMgrAbility::GetInstance();
    enterpriseDeviceMgrAbility->OnStart();
    EventFwk::CommonEventData eventData = GetData<EventFwk::CommonEventData>();

    enterpriseDeviceMgrAbility->OnCommonEventSystemUpdate(eventData);
    enterpriseDeviceMgrAbility->OnCommonEventUserRemoved(eventData);
    enterpriseDeviceMgrAbility->OnCommonEventPackageAdded(eventData);
    enterpriseDeviceMgrAbility->OnCommonEventPackageRemoved(eventData);
    int32_t systemAbilityId = CommonFuzzer::GetU32Data(data);
    const std::string deviceId(reinterpret_cast<const char*>(data), size);
    enterpriseDeviceMgrAbility->OnAddSystemAbility(systemAbilityId, deviceId);
    enterpriseDeviceMgrAbility->OnAppManagerServiceStart(systemAbilityId, deviceId);
    enterpriseDeviceMgrAbility->OnAbilityManagerServiceStart(systemAbilityId, deviceId);
    enterpriseDeviceMgrAbility->OnCommonEventServiceStart(systemAbilityId, deviceId);

    int32_t userId = CommonFuzzer::GetU32Data(data);
    enterpriseDeviceMgrAbility->SubscribeAppState();
    enterpriseDeviceMgrAbility->UnsubscribeAppState();
    AppExecFwk::ElementName admin;
    std::string fuzzString(reinterpret_cast<const char*>(data), size);
    admin.SetBundleName(fuzzString);
    admin.SetAbilityName(fuzzString);
    AdminType type = GetData<AdminType>();
    bool isDebug = CommonFuzzer::GetU32Data(data) % 2;
    enterpriseDeviceMgrAbility->VerifyEnableAdminCondition(admin, type, userId, isDebug);
    std::string adminName(reinterpret_cast<const char*>(data), size);
    const std::string policyName(reinterpret_cast<const char*>(data), size);
    const std::string policyValue(reinterpret_cast<const char*>(data), size);
    enterpriseDeviceMgrAbility->RemoveAdminItem(adminName, policyName, policyValue, userId);
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    enterpriseDeviceMgrAbility->CheckCallingUid(bundleName);
    TEST::Utils::ResetTokenTypeAndUid();
    return 0;
}
} // namespace EDM
} // namespace OHOS