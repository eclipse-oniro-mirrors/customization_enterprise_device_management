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

#include "cJSON.h"
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

void InitAdminParam(AdminInfo &adminInfo, const uint8_t* data, int32_t& pos, size_t& size, int32_t stringSize)
{
    AdminInfo fuzzAdminInfo;
    fuzzAdminInfo.packageName_ = CommonFuzzer::GetString(data, pos, stringSize, size);
    fuzzAdminInfo.className_ = CommonFuzzer::GetString(data, pos, stringSize, size);
    fuzzAdminInfo.entInfo_.enterpriseName = CommonFuzzer::GetString(data, pos, stringSize, size);
    fuzzAdminInfo.entInfo_.description = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string permission = CommonFuzzer::GetString(data, pos, stringSize, size);
    fuzzAdminInfo.permission_.push_back(permission);
    ManagedEvent event = GetData<ManagedEvent>();
    fuzzAdminInfo.managedEvents_.push_back(event);
    fuzzAdminInfo.parentAdminName_ = CommonFuzzer::GetString(data, pos, stringSize, size);
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
    int32_t stringSize = size / 9;
    std::shared_ptr<AdminPoliciesStorageRdb> adminPoliciesStorageRdb = AdminPoliciesStorageRdb::GetInstance();
    int32_t userId = CommonFuzzer::GetU32Data(data);
    AdminInfo admin;
    InitAdminParam(admin, data, pos, size, stringSize);
    adminPoliciesStorageRdb->InsertAdmin(userId, admin);
    adminPoliciesStorageRdb->CreateInsertValuesBucket(userId, admin);
    std::string packageName = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string stringInfo = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string info = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::vector<std::string> infos = {info};
    adminPoliciesStorageRdb->DeleteAdmin(userId, packageName);
    ManagedEvent event = GetData<ManagedEvent>();
    std::vector<ManagedEvent> managedEvents = {event};
    adminPoliciesStorageRdb->SetAdminStringInfo(stringInfo, infos);
    std::shared_ptr<NativeRdb::ResultSet> resultSet;
    std::shared_ptr<Admin> item = std::make_shared<Admin>(admin);
    adminPoliciesStorageRdb->SetAdminItems(resultSet, item->adminInfo_);
    adminPoliciesStorageRdb->SetManagedEventStr(resultSet, item->adminInfo_);
    adminPoliciesStorageRdb->QueryAllAdmin();
    return 0;
}
} // namespace EDM
} // namespace OHOS