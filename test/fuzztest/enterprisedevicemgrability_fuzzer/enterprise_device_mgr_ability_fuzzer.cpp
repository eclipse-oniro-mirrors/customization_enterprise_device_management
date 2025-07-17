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
#include "user_policy_manager.h"
#include "permission_checker.h"
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

void InitAdminParam(Admin &admin, std::string fuzzString, EntInfo entInfo, ManagedEvent event)
{
    AdminInfo fuzzAdminInfo;
    fuzzAdminInfo.packageName_ = fuzzString;
    fuzzAdminInfo.className_ = fuzzString;
    fuzzAdminInfo.entInfo_ = entInfo;
    fuzzAdminInfo.permission_ = { fuzzString };
    fuzzAdminInfo.managedEvents_ = { event };
    fuzzAdminInfo.parentAdminName_ = fuzzString;
    admin.adminInfo_ = fuzzAdminInfo;
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
    int32_t pos = 0;
    int32_t stringSize = (size - pos) / 5;

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
    bool isDebug = CommonFuzzer::GetU32Data(data) % BINARY_DECISION_DIVISOR;
    enterpriseDeviceMgrAbility->VerifyEnableAdminCondition(admin, type, userId, isDebug);
    std::string adminName(reinterpret_cast<const char*>(data), size);
    const std::string policyName(reinterpret_cast<const char*>(data), size);
    const std::string policyValue(reinterpret_cast<const char*>(data), size);
    enterpriseDeviceMgrAbility->RemoveAdminItem(adminName, policyName, policyValue, userId);
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    TEST::Utils::ResetTokenTypeAndUid();
    PluginManager::GetInstance()->DumpPlugin();

    std::string abilityName = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string newAdminName = CommonFuzzer::GetString(data, pos, stringSize, size);
    uint32_t code = CommonFuzzer::GetU32Data(data);
    bool isAdminEnabled = CommonFuzzer::GetU32Data(data) % 2;
    std::vector<std::u16string> args;
    std::vector<std::string> policies;
    Admin edmAdmin;
    ManagedEvent event = GetData<ManagedEvent>();
    EntInfo entInfo;
    entInfo.enterpriseName = fuzzString;
    entInfo.description = fuzzString;
    InitAdminParam(edmAdmin, fuzzString, entInfo, event);
    std::shared_ptr<Admin> adminPtr = std::make_shared<Admin>(edmAdmin);
    enterpriseDeviceMgrAbility->OnCommonEventUserAdded(eventData);
    enterpriseDeviceMgrAbility->OnCommonEventUserSwitched(eventData);
    enterpriseDeviceMgrAbility->OnCommonEventPackageChanged(eventData);
    enterpriseDeviceMgrAbility->OnCommonEventBmsReady(eventData);
    enterpriseDeviceMgrAbility->OnAdminEnabled(bundleName, abilityName, code, userId, isAdminEnabled);
    enterpriseDeviceMgrAbility->AddDisallowUninstallApp(bundleName, userId);
    enterpriseDeviceMgrAbility->DelDisallowUninstallApp(bundleName);
    enterpriseDeviceMgrAbility->HandleKeepPolicy(adminName, newAdminName, edmAdmin, adminPtr);
    enterpriseDeviceMgrAbility->AfterEnableAdmin(admin, type, userId);
    enterpriseDeviceMgrAbility->RemoveAdminAndAdminPolicy(adminName, userId);
    enterpriseDeviceMgrAbility->RemoveAdmin(adminName, userId);
    enterpriseDeviceMgrAbility->RemoveAdminPolicy(adminName, userId);
    enterpriseDeviceMgrAbility->RemoveSubSuperAdminAndAdminPolicy(bundleName);
    enterpriseDeviceMgrAbility->RemoveSuperAdminAndAdminPolicy(bundleName);
    enterpriseDeviceMgrAbility->CheckDelegatedPolicies(adminPtr, policies);
    enterpriseDeviceMgrAbility->CheckRunningMode(code);
    enterpriseDeviceMgrAbility->CheckManagedEvent(code);
    enterpriseDeviceMgrAbility->SetDelegatedPolicies(bundleName, policies, userId);
    enterpriseDeviceMgrAbility->SetDelegatedPolicies(admin, bundleName, policies);
    enterpriseDeviceMgrAbility->OnStop();
    UserPolicyManager userPolicyMgr(0);
    PolicyItemsMap itemMap;
    itemMap[adminName] = fuzzString;
    userPolicyMgr.GetAllPolicyByAdmin(adminName, itemMap);
    userPolicyMgr.DeleteCombinedPolicy(fuzzString);
    userPolicyMgr.ReplacePolicyByAdminName(0, adminName, fuzzString);
    userPolicyMgr.DumpAdminPolicy();
    userPolicyMgr.DumpAdminList();
    userPolicyMgr.DumpCombinedPolicy();
    PermissionChecker::GetInstance()->CheckCallerPermission(adminPtr, fuzzString, isAdminEnabled);
    PermissionChecker::GetInstance()->CheckCallingUid(fuzzString);
    PermissionChecker::GetInstance()->GetAllPermissionsByAdmin(fuzzString, type, userId, policies);
    FuncOperateType fType = GetData<FuncOperateType>();
    PermissionChecker::GetInstance()->CheckHandlePolicyPermission(fType, bundleName, fuzzString, fuzzString, userId);
    PermissionChecker::GetInstance()->CheckAndUpdatePermission(adminPtr, 0, fuzzString, userId);
    PermissionChecker::GetInstance()->GetCurrentUserId();
    PermissionChecker::GetInstance()->CheckSpecialPolicyCallQuery(userId);
    return 0;
}
} // namespace EDM
} // namespace OHOS