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

#include "common_fuzzer.h"

#include <system_ability_definition.h>

#define protected public
#define private public
#include "enterprise_device_mgr_ability.h"
#undef protected
#undef private
#include "func_code.h"
#include "ienterprise_device_mgr.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr int32_t NUM_24 = 24;
constexpr int32_t NUM_16 = 16;
constexpr int32_t NUM_8 = 8;
constexpr int32_t NUM_INDEX_ZERO = 0;
constexpr int32_t NUM_INDEX_FIRST = 1;
constexpr int32_t NUM_INDEX_SECOND = 2;
constexpr int32_t NUM_INDEX_THIRD = 3;

void CommonFuzzer::OnRemoteRequestFuzzerTest(uint32_t code, const uint8_t* data, size_t size, MessageParcel &parcel)
{
    TEST::Utils::SetEdmInitialEnv();
    sptr<EnterpriseDeviceMgrAbility> enterpriseDeviceMgrAbility = EnterpriseDeviceMgrAbility::GetInstance();
    enterpriseDeviceMgrAbility->OnStart();

    MessageParcel reply;
    MessageOption option;

    enterpriseDeviceMgrAbility->OnRemoteRequest(code, parcel, reply, option);
    TEST::Utils::ResetTokenTypeAndUid();
}

void CommonFuzzer::SetParcelContent(MessageParcel &parcel, const uint8_t* data, size_t size)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.example.edmtest");
    admin.SetAbilityName("com.example.edmtest.EnterpriseAdminAbility");
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgr::GetDescriptor());
    parcel.WriteParcelable(&admin);
    parcel.WriteBuffer(data, size);
}

uint32_t CommonFuzzer::GetU32Data(const uint8_t* ptr)
{
    return (ptr[NUM_INDEX_ZERO] << NUM_24) | (ptr[NUM_INDEX_FIRST] << NUM_16) | (ptr[NUM_INDEX_SECOND] << NUM_8) |
        ptr[NUM_INDEX_THIRD];
}
} // namespace EDM
} // namespace OHOS