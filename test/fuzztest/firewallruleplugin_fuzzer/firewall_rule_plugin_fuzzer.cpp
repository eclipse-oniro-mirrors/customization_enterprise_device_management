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

#include "firewall_rule_plugin_fuzzer.h"

#include <system_ability_definition.h>

#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "firewall_rule.h"
#include "func_code.h"
#include "ienterprise_device_mgr.h"
#include "iptables_utils.h"
#include "message_parcel.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 16;
constexpr int32_t WITHOUT_USERID = 0;
constexpr int32_t MAX_ENUM_LENGTH = 2;
constexpr int32_t MAX_PROTOCOL_LENGTH = 4;

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < MIN_SIZE) {
        return 0;
    }

    int32_t pos = 0;
    int32_t stringSize = size / 6;
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::GET);
        operateType <= static_cast<uint32_t>(FuncOperateType::REMOVE); operateType++) {
        uint32_t code = EdmInterfaceCode::FIREWALL_RULE;
        code = POLICY_FUNC_CODE(operateType, code);

        AppExecFwk::ElementName admin;
        admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
        admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
        MessageParcel parcel;
        parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
        parcel.WriteInt32(WITHOUT_USERID);
        if (operateType) {
            parcel.WriteParcelable(&admin);
            IPTABLES::FirewallRule firewall;
            std::string srcAddr(reinterpret_cast<const char*>(data), size);
            std::string destAddr(reinterpret_cast<const char*>(data), size);
            std::string srcPort(reinterpret_cast<const char*>(data), size);
            std::string destPort(reinterpret_cast<const char*>(data), size);
            std::string uid(reinterpret_cast<const char*>(data), size);
            IPTABLES::Direction directionEnum =
                static_cast<IPTABLES::Direction>(CommonFuzzer::GetU32Data(data) % MAX_ENUM_LENGTH);
            IPTABLES::Action actionEnum =
                static_cast<IPTABLES::Action>(CommonFuzzer::GetU32Data(data) % MAX_ENUM_LENGTH);
            IPTABLES::Protocol protocolEnum =
                static_cast<IPTABLES::Protocol>(CommonFuzzer::GetU32Data(data) % MAX_PROTOCOL_LENGTH);
            firewall = {directionEnum, actionEnum, protocolEnum, srcAddr, destAddr, srcPort, destPort, uid};
            IPTABLES::FirewallRuleParcel firewallRuleParcel{firewall};
            firewallRuleParcel.Marshalling(parcel);
        } else {
            parcel.WriteString("");
            parcel.WriteInt32(0);
            parcel.WriteParcelable(&admin);
        }
        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    }
    return 0;
}
} // namespace EDM
} // namespace OHOS