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
const std::string FIRMWARE_EVENT_INFO_NAME = "version";
const std::string FIRMWARE_EVENT_INFO_TYPE = "packageType";
const std::string FIRMWARE_EVENT_INFO_CHECK_TIME = "firstReceivedTime";

EventFwk::CommonEventData getCommonEventData(const uint8_t* data, size_t size)
{
    int32_t pos = 0;
    EventFwk::CommonEventData eventData;
    EventFwk::Want want;
    AppExecFwk::ElementName admin;
    int32_t code = CommonFuzzer::GetU32Data(data, pos, size);
    int uid = CommonFuzzer::GetU32Data(data, pos, size);
    long checkTime = CommonFuzzer::GetLong(data, pos, size);
    int32_t stringSize = (size - pos) / 5;
    admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
    admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
    eventData.SetCode(code);
    want.SetParam(FIRMWARE_EVENT_INFO_NAME, CommonFuzzer::GetString(data, pos, stringSize, size));
    want.SetParam(FIRMWARE_EVENT_INFO_TYPE, CommonFuzzer::GetString(data, pos, stringSize, size));
    want.SetParam(FIRMWARE_EVENT_INFO_CHECK_TIME, checkTime);
    want.SetParam(AppExecFwk::Constants::USER_ID, uid);
    want.SetAction(CommonFuzzer::GetString(data, pos, stringSize, size));
    eventData.SetWant(want);
    want.SetElement(admin);
    return eventData;
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
    g_data = data;
    g_size = size;
    g_pos = 0;

    TEST::Utils::SetEdmInitialEnv();
    sptr<EnterpriseDeviceMgrAbility> enterpriseDeviceMgrAbility = EnterpriseDeviceMgrAbility::GetInstance();
    enterpriseDeviceMgrAbility->OnStart();
    EventFwk::CommonEventData eventData = getCommonEventData(data, size);

    enterpriseDeviceMgrAbility->OnCommonEventSystemUpdate(eventData);
    enterpriseDeviceMgrAbility->OnCommonEventUserRemoved(eventData);
    enterpriseDeviceMgrAbility->OnCommonEventPackageAdded(eventData);
    enterpriseDeviceMgrAbility->OnCommonEventPackageRemoved(eventData);
    int32_t systemAbilityId = CommonFuzzer::GetU32Data(data);
    const std::string deviceId(reinterpret_cast<const char*>(data), size);
    enterpriseDeviceMgrAbility->OnAddSystemAbility(systemAbilityId, deviceId);
    enterpriseDeviceMgrAbility->OnAppManagerServiceStart();
    enterpriseDeviceMgrAbility->OnAbilityManagerServiceStart();
    enterpriseDeviceMgrAbility->OnCommonEventServiceStart();

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