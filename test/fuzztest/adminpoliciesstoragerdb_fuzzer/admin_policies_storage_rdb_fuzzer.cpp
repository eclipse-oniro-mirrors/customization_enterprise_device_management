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

#include "admin_policies_storage_rdb_fuzzer.h"

#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "get_data_template.h"
#include "message_parcel.h"
#define private public
#include "admin_policies_storage_rdb.h"
#undef private
#include "ienterprise_device_mgr.h"

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

    std::shared_ptr<AdminPoliciesStorageRdb> adminPoliciesStorageRdb = AdminPoliciesStorageRdb::GetInstance();
    int32_t userId = CommonFuzzer::GetU32Data(data);
    std::string fuzzString(reinterpret_cast<const char*>(data), size);
    ManagedEvent event = GetData<ManagedEvent>();
    Admin admin;
    AdminInfo fuzzAdminInfo;
    EntInfo entInfo;
    entInfo.enterpriseName = fuzzString;
    entInfo.description = fuzzString;
    fuzzAdminInfo.packageName_ = fuzzString;
    fuzzAdminInfo.className_ = fuzzString;
    fuzzAdminInfo.entInfo_ = entInfo;
    fuzzAdminInfo.permission_ = { fuzzString };
    fuzzAdminInfo.managedEvents_ = { event };
    fuzzAdminInfo.parentAdminName_ = fuzzString;
    admin.adminInfo_ = fuzzAdminInfo;

    std::vector<std::string> permissions = { fuzzString };

    adminPoliciesStorageRdb->InsertAdmin(userId, admin);
    adminPoliciesStorageRdb->UpdateAdmin(userId, admin);
    adminPoliciesStorageRdb->CreateValuesBucket(userId, admin);

    std::string packageName(reinterpret_cast<const char*>(data), size);
    adminPoliciesStorageRdb->DeleteAdmin(userId, packageName);

    std::string className(reinterpret_cast<const char*>(data), size);
    adminPoliciesStorageRdb->UpdateAdmin(userId, packageName, className, permissions);
    
    adminPoliciesStorageRdb->UpdateEntInfo(userId, packageName, entInfo);

    std::vector<ManagedEvent> managedEvents = {event};
    adminPoliciesStorageRdb->UpdateManagedEvents(userId, packageName, managedEvents);

    std::string str(reinterpret_cast<const char*>(data), size);
    Json::Value json;
    json["test"] = str;
    adminPoliciesStorageRdb->ConvertStrToJson(str, json);

    std::string bundleName(reinterpret_cast<const char*>(data), size);
    std::string parentName(reinterpret_cast<const char*>(data), size);
    adminPoliciesStorageRdb->InsertAuthorizedAdmin(bundleName, permissions, parentName);
    adminPoliciesStorageRdb->UpdateAuthorizedAdmin(bundleName, permissions, parentName);
    return 0;
}
} // namespace EDM
} // namespace OHOS