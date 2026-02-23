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
#include "parameters.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 64;
const std::string FIRMWARE_EVENT_INFO_NAME = "version";
const std::string FIRMWARE_EVENT_INFO_TYPE = "packageType";
const std::string FIRMWARE_EVENT_INFO_CHECK_TIME = "firstReceivedTime";
const std::string PARAM_EDM_ENABLE = "persist.edm.edm_enable";

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    TEST::Utils::SetEdmPermissions();
    return 0;
}

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

void InitAdminParam(AdminInfo &adminInfo, std::string fuzzString, EntInfo entInfo, ManagedEvent event)
{
    AdminInfo fuzzAdminInfo;
    fuzzAdminInfo.packageName_ = fuzzString;
    fuzzAdminInfo.className_ = fuzzString;
    fuzzAdminInfo.entInfo_ = entInfo;
    fuzzAdminInfo.permission_ = { fuzzString };
    fuzzAdminInfo.managedEvents_ = { event };
    fuzzAdminInfo.parentAdminName_ = fuzzString;
    adminInfo = fuzzAdminInfo;
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
    int32_t stringSize = (size - pos) / 8;

    TEST::Utils::SetUid();
    sptr<EnterpriseDeviceMgrAbility> enterpriseDeviceMgrAbility = EnterpriseDeviceMgrAbility::GetInstance();
    enterpriseDeviceMgrAbility->OnStart();
    EventFwk::CommonEventData eventData = getCommonEventData(data, size);

    enterpriseDeviceMgrAbility->OnCommonEventSystemUpdate(eventData);
    enterpriseDeviceMgrAbility->OnCommonEventUserRemoved(eventData);
    enterpriseDeviceMgrAbility->OnCommonEventPackageAdded(eventData);
    enterpriseDeviceMgrAbility->OnCommonEventPackageRemoved(eventData);
    int32_t systemAbilityId = CommonFuzzer::GetU32Data(data);
    const std::string deviceId = CommonFuzzer::GetString(data, pos, stringSize, size);
    enterpriseDeviceMgrAbility->OnAddSystemAbility(systemAbilityId, deviceId);
    enterpriseDeviceMgrAbility->OnAppManagerServiceStart();
    enterpriseDeviceMgrAbility->OnAbilityManagerServiceStart();
    enterpriseDeviceMgrAbility->OnCommonEventServiceStart();

    int32_t userId = CommonFuzzer::GetU32Data(data);
    int32_t accountId = CommonFuzzer::GetU32Data(data);
    int32_t interfaceCode = CommonFuzzer::GetU32Data(data);
    enterpriseDeviceMgrAbility->SubscribeAppState();
    enterpriseDeviceMgrAbility->UnsubscribeAppState();
    AppExecFwk::ElementName admin;
    std::string fuzzString = CommonFuzzer::GetString(data, pos, stringSize, size);
    admin.SetBundleName(fuzzString);
    admin.SetAbilityName(fuzzString);
    AdminType type = GetData<AdminType>();
    bool isDebug = CommonFuzzer::GetU32Data(data) % BINARY_DECISION_DIVISOR;
    enterpriseDeviceMgrAbility->VerifyEnableAdminCondition(admin, type, userId, isDebug);
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);
    const std::string policyName = CommonFuzzer::GetString(data, pos, stringSize, size);
    const std::string policyValue = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string bundleName = CommonFuzzer::GetString(data, pos, stringSize, size);
    TEST::Utils::ResetUid();
    PluginManager::GetInstance()->DumpPlugin();

    std::string abilityName = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string newAdminName = CommonFuzzer::GetString(data, pos, stringSize, size);
    uint32_t code = CommonFuzzer::GetU32Data(data);
    bool isAdminEnabled = CommonFuzzer::GetU32Data(data) % 2;
    bool isModeOn = CommonFuzzer::GetU32Data(data) % 2;
    bool isByod = CommonFuzzer::GetU32Data(data) % 2;
    std::vector<std::u16string> args;
    std::vector<std::string> policies;
    AdminInfo edmAdmin;
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
    enterpriseDeviceMgrAbility->OnCommonEventKioskMode(eventData, isModeOn);
    enterpriseDeviceMgrAbility->OnAdminEnabled(bundleName, abilityName, code, userId, isAdminEnabled);
    enterpriseDeviceMgrAbility->AddDisallowUninstallApp(bundleName);
    enterpriseDeviceMgrAbility->AddDisallowUninstallAppForAccount(bundleName, userId);
    enterpriseDeviceMgrAbility->UpdateClipboardInfo(bundleName, userId);
    enterpriseDeviceMgrAbility->DelDisallowUninstallApp(bundleName);
    enterpriseDeviceMgrAbility->DelDisallowUninstallAppForAccount(bundleName, userId);
    enterpriseDeviceMgrAbility->HandleKeepPolicy(adminName, newAdminName, edmAdmin, adminPtr->adminInfo_);
    enterpriseDeviceMgrAbility->AfterEnableAdmin(admin, type, userId);
    enterpriseDeviceMgrAbility->RemoveAdminAndAdminPolicy(adminName, userId, type);
    enterpriseDeviceMgrAbility->RemoveAdmin(adminName, userId, type);
    enterpriseDeviceMgrAbility->RemoveAdminPolicy(adminName, userId);
    enterpriseDeviceMgrAbility->RemoveSubSuperAdminAndAdminPolicy(bundleName, type);
    enterpriseDeviceMgrAbility->RemoveSuperAdminAndAdminPolicy(bundleName);
    enterpriseDeviceMgrAbility->CheckDelegatedPolicies(type, policies);
    enterpriseDeviceMgrAbility->CheckRunningMode(code);
    enterpriseDeviceMgrAbility->CheckManagedEvent(code);
    enterpriseDeviceMgrAbility->ConnectAbility(accountId, adminPtr);
    enterpriseDeviceMgrAbility->ConnectAbilityOnSystemAccountEvent(accountId, event);
    enterpriseDeviceMgrAbility->ConnectAbilityOnSystemEvent(bundleName, event, userId);
    enterpriseDeviceMgrAbility->CallOnOtherServiceStart(interfaceCode);
    enterpriseDeviceMgrAbility->CallOnOtherServiceStart(interfaceCode, systemAbilityId);
    enterpriseDeviceMgrAbility->IsByodAdmin(admin, isByod);
    enterpriseDeviceMgrAbility->SetDelegatedPolicies(bundleName, policies, userId);
    enterpriseDeviceMgrAbility->SetDelegatedPolicies(admin, bundleName, policies);
    enterpriseDeviceMgrAbility->EnableDeviceAdmin(admin);
    enterpriseDeviceMgrAbility->DisableDeviceAdmin(admin);
    enterpriseDeviceMgrAbility->CheckEnableDeviceAdmin(admin);
    enterpriseDeviceMgrAbility->CheckDisableDeviceAdmin(adminPtr);
    enterpriseDeviceMgrAbility->OnAdminEnabled(edmAdmin, code, userId, bundleName);
    AAFwk::Want want;
    want.SetElement(admin);
    enterpriseDeviceMgrAbility->StartAbilityByAdmin(admin, want);
    enterpriseDeviceMgrAbility->CheckStartAbility(userId, admin, bundleName);
    std::string tips;
    enterpriseDeviceMgrAbility->GetEnterpriseManagedTips(tips);
    UserPolicyManager userPolicyMgr(0);
    PolicyItemsMap itemMap;
    itemMap[adminName] = fuzzString;
    userPolicyMgr.GetAllPolicyByAdmin(adminName, itemMap);
    userPolicyMgr.DeleteCombinedPolicy(fuzzString);
    userPolicyMgr.ReplacePolicyByAdminName(0, adminName, fuzzString);
    userPolicyMgr.DumpAdminPolicy();
    userPolicyMgr.DumpAdminList();
    userPolicyMgr.DumpCombinedPolicy();
    PermissionChecker::GetInstance()->CheckCallerPermission(adminPtr->adminInfo_.packageName_, fuzzString);
    PermissionChecker::GetInstance()->CheckCallingUid(fuzzString);
    PermissionChecker::GetInstance()->GetAllPermissionsByAdmin(fuzzString, userId, policies);
    FuncOperateType fType = GetData<FuncOperateType>();
    PermissionChecker::GetInstance()->CheckHandlePolicyPermission(fType, adminPtr, fuzzString, fuzzString, userId);
    PermissionChecker::GetInstance()->GetCurrentUserId();
    PermissionChecker::GetInstance()->CheckSpecialPolicyCallQuery(userId);

    system::SetParameter(PARAM_EDM_ENABLE, "false");
    return 0;
}
} // namespace EDM
} // namespace OHOS