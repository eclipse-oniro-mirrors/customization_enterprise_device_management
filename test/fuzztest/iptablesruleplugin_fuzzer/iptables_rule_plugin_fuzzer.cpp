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

#include "iptables_rule_plugin_fuzzer.h"

#include <system_ability_definition.h>

#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "get_data_template.h"
#include "ienterprise_device_mgr.h"
#include "iptables_utils.h"
#include "message_parcel.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 256;
constexpr int32_t WITHOUT_USERID = 0;
constexpr int32_t MAX_ENUM_LENGTH = 2;
constexpr int32_t MAX_PROTOCOL_LENGTH = 4;

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < MIN_SIZE) {
        return 0;
    }
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::GET);
        operateType <= static_cast<uint32_t>(FuncOperateType::REMOVE); operateType++) {
        uint32_t code = EdmInterfaceCode::IPTABLES_RULE;
        code = POLICY_FUNC_CODE(operateType, code);

        AppExecFwk::ElementName admin;
        admin.SetBundleName("com.example.edmtest");
        admin.SetAbilityName("com.example.edmtest.EnterpriseAdminAbility");
        MessageParcel parcel;
        parcel.WriteInterfaceToken(IEnterpriseDeviceMgr::GetDescriptor());
        parcel.WriteInt32(WITHOUT_USERID);
        if (operateType) {
            parcel.WriteParcelable(&admin);
            parcel.WriteString("");
        } else {
            parcel.WriteString("");
            parcel.WriteInt32(0);
            parcel.WriteParcelable(&admin);
        }
        IPTABLES::AddFilter addFilter;
        addFilter.ruleNo = CommonFuzzer::GetU32Data(data);
        std::string srcAddr(reinterpret_cast<const char*>(data), size);
        std::string destAddr(reinterpret_cast<const char*>(data), size);
        std::string srcPort(reinterpret_cast<const char*>(data), size);
        std::string destPort(reinterpret_cast<const char*>(data), size);
        std::string uid(reinterpret_cast<const char*>(data), size);
        addFilter.srcAddr = srcAddr;
        addFilter.destAddr = destAddr;
        addFilter.srcPort = srcPort;
        addFilter.destPort = destPort;
        addFilter.uid = uid;
        addFilter.method = static_cast<IPTABLES::AddMethod>(CommonFuzzer::GetU32Data(data) % MAX_ENUM_LENGTH);
        addFilter.direction = static_cast<IPTABLES::Direction>(CommonFuzzer::GetU32Data(data) % MAX_ENUM_LENGTH);
        addFilter.action = static_cast<IPTABLES::Action>(CommonFuzzer::GetU32Data(data) % MAX_ENUM_LENGTH);
        addFilter.protocol = static_cast<IPTABLES::Protocol>(CommonFuzzer::GetU32Data(data) % MAX_PROTOCOL_LENGTH);
        IPTABLES::IptablesUtils::WriteAddFilterConfig(addFilter, parcel);
        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);

        MessageParcel messageParcel;
        messageParcel.WriteInterfaceToken(IEnterpriseDeviceMgr::GetDescriptor());
        messageParcel.WriteInt32(WITHOUT_USERID);
        messageParcel.WriteParcelable(&admin);
        IPTABLES::AddFilter addFilterFuzzTest = GetData<IPTABLES::AddFilter>();
        IPTABLES::IptablesUtils::WriteAddFilterConfig(addFilterFuzzTest, messageParcel);
        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, messageParcel);
    }
    return 0;
}
} // namespace EDM
} // namespace OHOS