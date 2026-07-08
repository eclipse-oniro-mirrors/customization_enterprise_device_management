/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "enterprise_device_mgr_ability_part_two_fuzzer.h"

#include "message_parcel.h"
#include "parameters.h"
#include "securec.h"

#include "common_event_data.h"
#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#define protected public
#define private public
#include "enterprise_device_mgr_ability.h"
#undef protected
#undef private
#include "func_code.h"
#include "get_data_template.h"
#include "ienterprise_device_mgr.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 64;
const std::string PARAM_EDM_ENABLE = "persist.edm.edm_enable";

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    TEST::Utils::SetEdmPermissions();
    sptr<EnterpriseDeviceMgrAbility> enterpriseDeviceMgrAbility = EnterpriseDeviceMgrAbility::GetInstance();
    enterpriseDeviceMgrAbility->OnStart();
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
    g_data = data;
    g_size = size;
    g_pos = 0;
    sptr<EnterpriseDeviceMgrAbility> enterpriseDeviceMgrAbility = EnterpriseDeviceMgrAbility::GetInstance();
    int32_t userId = CommonFuzzer::GetU32Data(data);
    AdminType type = GetData<AdminType>();
    std::string adminName = std::string(reinterpret_cast<const char*>(data), size);
    enterpriseDeviceMgrAbility->RemoveAdminAndAdminPolicy(adminName, userId, type);
    enterpriseDeviceMgrAbility->RemoveAdminPolicy(adminName, userId);
    system::SetParameter(PARAM_EDM_ENABLE, "false");
    return 0;
}
} // namespace EDM
} // namespace OHOS