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
constexpr size_t MIN_SIZE = 64;

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

void DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::shared_ptr<AdminManager> adminManager = AdminManager::GetInstance();
    adminManager->Init();
    std::string fuzzString(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> permissions = { fuzzString };
    EdmPermission edmPermission;
    edmPermission.permissionName_ = fuzzString;
    std::vector<EdmPermission> reqPermissions = { edmPermission };
    ManagedEvent event = GetData<ManagedEvent>();
    Admin admin;
    EntInfo entInfo;
    entInfo.enterpriseName = fuzzString;
    entInfo.description = fuzzString;
    InitAdminParam(admin, fuzzString, entInfo, event);
    std::shared_ptr<Admin> adminPtr = std::make_shared<Admin>(admin);
    std::vector<std::shared_ptr<Admin>> adminPtrVec = { adminPtr };
    int32_t eventId = CommonFuzzer::GetU32Data(data);
    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> subscribeAdmins;
    subscribeAdmins[eventId] = adminPtrVec;
    int32_t userId = CommonFuzzer::GetU32Data(data);
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    AdminType role = GetData<AdminType>();
    std::string packageName(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> packageNameList = { packageName };
    std::string subAdminName(reinterpret_cast<const char*>(data), size);
    std::shared_ptr<Admin> subOrSuperAdmin = std::make_shared<Admin>(admin);
    std::string parentName(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> subAdmins = { fuzzString };
    uint32_t fuzzEvent = GetData<uint32_t>();
    std::vector<uint32_t> events = { fuzzEvent };
    adminManager->GetAdminBySubscribeEvent(event, subscribeAdmins);
    adminManager->SetAdminValue(userId, admin);
    adminManager->GetReqPermission(permissions, reqPermissions);
    adminManager->GetAdminByPkgName(packageName, userId);
    adminManager->DeleteAdmin(packageName, userId);
    adminManager->GetGrantedPermission(permissions, role);
    adminManager->IsSuperAdminExist();
    adminManager->IsSuperAdmin(bundleName);
    adminManager->IsSuperOrSubSuperAdmin(bundleName);
    adminManager->GetEnabledAdmin(role, packageNameList, userId);
    adminManager->GetSubOrSuperAdminByPkgName(subAdminName, subOrSuperAdmin);
    adminManager->GetSubSuperAdminsByParentName(parentName, subAdmins);
    adminManager->GetEntInfo(packageName, entInfo, userId);
    adminManager->SetEntInfo(packageName, entInfo, userId);
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