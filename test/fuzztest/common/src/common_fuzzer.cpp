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
#include "edm_ipc_interface_code.h"
#include "enterprise_device_mgr_ability.h"
#include "element_name.h"
#undef protected
#undef private
#include "func_code.h"
#include "parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
void CommonFuzzer::OnRemoteRequestFuzzerTest(uint32_t code, const uint8_t* data, size_t size)
{
    TEST::Utils::SetEdmInitialEnv();
    sptr<EnterpriseDeviceMgrAbility> enterpriseDeviceMgrAbility = EnterpriseDeviceMgrAbility::GetInstance();
    enterpriseDeviceMgrAbility->OnStart();
    AppExecFwk::ElementName admin;
    admin.bundleName_ = "com.example.edmtest";
    admin.abilityName_ = "com.example.edmtest.EnterpriseAdminAbility";

    MessageParcel parcel;
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgr::GetDescriptor());
    parcel.WriteParcelable(&admin);
    parcel.WriteBuffer(data, size);
    
    MessageParcel reply;
    MessageOption option;

    enterpriseDeviceMgrAbility->OnRemoteRequest(code, parcel, reply, option);
    TEST::Utils::ResetTokenTypeAndUid();
}
} // namespace EDM
} // namespace OHOS