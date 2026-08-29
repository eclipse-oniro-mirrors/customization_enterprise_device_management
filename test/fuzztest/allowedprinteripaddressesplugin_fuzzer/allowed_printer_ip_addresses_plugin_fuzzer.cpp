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
 
#include "allowed_printer_ip_addresses_plugin_fuzzer.h"
 
#include <system_ability_definition.h>
 
#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "ienterprise_device_mgr.h"
#include "func_code.h"
#include "message_parcel.h"
#include "utils.h"
 
namespace OHOS {
namespace EDM {

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    TEST::Utils::SetEdmPermissions();
    return 0;
}
 
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < MIN_SIZE) {
        return 0;
    }
 
    int32_t pos = 0;
    int32_t stringSize = size / 8;
 
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::GET);
        operateType <= static_cast<uint32_t>(FuncOperateType::REMOVE); operateType++) {
        uint32_t deviceCode = EdmInterfaceCode::ALLOWED_PRINTER_IP_ADDRESS_FOR_DEVICE;
        uint32_t userCode = EdmInterfaceCode::ALLOWED_PRINTER_IP_ADDRESS_FOR_ACCOUNT;
        
        for (uint32_t code : {deviceCode, userCode}) {
            uint32_t fullCode = POLICY_FUNC_CODE(operateType, code);
 
            AppExecFwk::ElementName admin;
            admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
            admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
            MessageParcel parcel;
            parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
            parcel.WriteInt32(WITHOUT_USERID);
            
            if (operateType != static_cast<uint32_t>(FuncOperateType::GET)) {
                parcel.WriteParcelable(&admin);
                std::vector<std::string> ipAddresses;
                uint32_t ipCount = CommonFuzzer::GetU32Data(data) % 10;
                for (uint32_t i = 0; i < ipCount && ipAddresses.size() < MAX_SIZE; ++i) {
                    ipAddresses.push_back(CommonFuzzer::GetString(data, pos, stringSize, size));
                }
                parcel.WriteStringVector(ipAddresses);
            } else {
                parcel.WriteString("");
                bool hasAdmin = CommonFuzzer::GetU32Data(data) % BINARY_DECISION_DIVISOR;
                if (hasAdmin) {
                    parcel.WriteInt32(HAS_ADMIN);
                    parcel.WriteParcelable(&admin);
                } else {
                    parcel.WriteInt32(WITHOUT_ADMIN);
                }
            }
 
            CommonFuzzer::OnRemoteRequestFuzzerTest(fullCode, data, size, parcel);
        }
    }
    return 0;
}
} // namespace EDM
} // namespace OHOS