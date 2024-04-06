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

#include "admin_manager_fuzzer.h"

#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "get_data_template.h"
#include "message_parcel.h"
#define private public
#include "admin_manager.h"
#undef private
#include "ienterprise_device_mgr.h"


namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 1024;

void DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::shared_ptr<AdminManager> adminManager = AdminManager::GetInstance();
    adminManager->Init();
    std::string permission(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> permissions = { permission };
    EdmPermission edmPermission = GetData<EdmPermission>();
    std::vector<EdmPermission> reqPermissions = { edmPermission };
    adminManager->GetReqPermission(permissions, reqPermissions);

    ManagedEvent event = GetData<ManagedEvent>();
    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> subscribeAdmins =
        GetData<std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>>>();
    adminManager->GetAdminBySubscribeEvent(event, subscribeAdmins);

    AppExecFwk::ExtensionAbilityInfo abilityInfo = GetData<AppExecFwk::ExtensionAbilityInfo>();
    EntInfo entInfo = GetData<EntInfo>();
    AdminType role = GetData<AdminType>();
    int32_t userId = CommonFuzzer::GetU32Data(data);
    bool isDebug = CommonFuzzer::GetU32Data(data) % 2;
    Admin admin(abilityInfo, role, entInfo, permissions, isDebug);
    adminManager->SetAdminValue(userId, admin);

    std::string packageName(reinterpret_cast<const char*>(data), size);
    adminManager->GetAdminByPkgName(packageName, userId);
    adminManager->DeleteAdmin(packageName, userId);
    adminManager->GetGrantedPermission(permissions, role);
    adminManager->UpdateAdmin(abilityInfo, permissions, userId);
    adminManager->IsSuperAdminExist();
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    adminManager->IsSuperAdmin(bundleName);
    adminManager->IsSuperOrSubSuperAdmin(bundleName);

    std::vector<std::string> packageNameList = { packageName };
    adminManager->GetEnabledAdmin(role, packageNameList, userId);
    std::string subAdminName(reinterpret_cast<const char*>(data), size);
    std::shared_ptr<Admin> subOrSuperAdmin = GetData<std::shared_ptr<Admin>>();
    adminManager->GetSubOrSuperAdminByPkgName(subAdminName, subOrSuperAdmin);

    std::string parentName(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> subAdmins = GetData<std::vector<std::string>>();
    adminManager->GetSubSuperAdminsByParentName(parentName, subAdmins);
    adminManager->GetEntInfo(packageName, entInfo, userId);
    adminManager->SetEntInfo(packageName, entInfo, userId);
    std::vector<uint32_t> events = GetData<std::vector<uint32_t>>();
    adminManager->SaveSubscribeEvents(events, bundleName, userId);
    adminManager->RemoveSubscribeEvents(events, bundleName, userId);
    adminManager->SaveAuthorizedAdmin(bundleName, permissions, parentName);
    adminManager->GetSuperAdmin();
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

    DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
} // namespace EDM
} // namespace OHOS