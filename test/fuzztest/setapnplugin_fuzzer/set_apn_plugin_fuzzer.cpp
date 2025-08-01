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

#include "set_apn_plugin_fuzzer.h"

#include <system_ability_definition.h>

#define protected public
#define private public
#include "set_apn_plugin.h"
#undef protected
#undef private
#include "common_fuzzer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "ienterprise_device_mgr.h"
#include "func_code.h"
#include "message_parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 70;
constexpr size_t MAX_NUM_OF_GET_STRING = 16;
constexpr int32_t WITHOUT_USERID = 0;
constexpr uint32_t SET_FLAG_FACTOR = 3;
constexpr uint32_t GET_FLAG_FACTOR = 2;
constexpr auto REQUIRED_KEYS = { "profile_name", "mcc", "mnc", "apn" };
constexpr uint32_t DEFAULT_INFO_SIZE = REQUIRED_KEYS.size();

enum ApnSetFlag {
    INSERT,
    UPDATE,
    SET_PREFER
};

enum ApnGetFlag {
    QUERYID,
    QUERYINFO
};

extern "C" int LLVMFuzzerInitialize(const uint8_t* data, size_t size)
{
    TEST::Utils::SetEdmPermissions();
    return 0;
}

static void GenerateSetData(const uint8_t* data, int32_t& pos, int32_t stringSize, size_t size, MessageParcel &parcel)
{
    uint32_t flag = CommonFuzzer::GetU32Data(data) % SET_FLAG_FACTOR;
    if (flag == INSERT || flag == UPDATE) {
        if (flag == INSERT) {
            parcel.WriteString(EdmConstants::SetApn::ADD_FLAG);
        } else {
            parcel.WriteString(EdmConstants::SetApn::UPDATE_FLAG);
            parcel.WriteString(CommonFuzzer::GetString(data, pos, stringSize, size));
        }
        parcel.WriteInt32(DEFAULT_INFO_SIZE);
        for (auto &ele : REQUIRED_KEYS) {
            parcel.WriteString(ele);
        }
        for (uint32_t idx = 0; idx < DEFAULT_INFO_SIZE; idx++) {
            parcel.WriteString(CommonFuzzer::GetString(data, pos, stringSize, size));
        }
    } else {
        if (flag == SET_PREFER) {
            parcel.WriteString(EdmConstants::SetApn::SET_PREFER_FLAG);
        } else {
            parcel.WriteString(CommonFuzzer::GetString(data, pos, stringSize, size));
        }
        parcel.WriteString(CommonFuzzer::GetString(data, pos, stringSize, size));
    }
}

static void GenerateGetData(const uint8_t* data, int32_t& pos, int32_t stringSize, size_t size, MessageParcel &parcel)
{
    uint32_t flag = CommonFuzzer::GetU32Data(data) % GET_FLAG_FACTOR;
    if (flag == QUERYID) {
        parcel.WriteString(EdmConstants::SetApn::QUERY_ID_FLAG);
        parcel.WriteInt32(DEFAULT_INFO_SIZE);
        for (auto &ele : REQUIRED_KEYS) {
            parcel.WriteString(ele);
        }
        for (uint32_t idx = 0; idx < DEFAULT_INFO_SIZE; idx++) {
            parcel.WriteString(CommonFuzzer::GetString(data, pos, stringSize, size));
        }
    } else {
        if (flag == QUERYINFO) {
            parcel.WriteString(EdmConstants::SetApn::QUERY_INFO_FLAG);
        } else {
            parcel.WriteString(CommonFuzzer::GetString(data, pos, stringSize, size));
        }
        parcel.WriteString(CommonFuzzer::GetString(data, pos, stringSize, size));
    }
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
    int32_t pos = 0;
    int32_t stringSize = size / MAX_NUM_OF_GET_STRING;
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::GET);
        operateType <= static_cast<uint32_t>(FuncOperateType::REMOVE); operateType++) {
        uint32_t code = EdmInterfaceCode::SET_APN_INFO;
        code = POLICY_FUNC_CODE(operateType, code);

        AppExecFwk::ElementName admin;
        admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
        admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
        MessageParcel parcel;
        parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
        parcel.WriteInt32(WITHOUT_USERID);
        if (operateType == static_cast<uint32_t>(FuncOperateType::GET)) {
            parcel.WriteParcelable(&admin);
            GenerateGetData(data, pos, stringSize, size, parcel);
        } else if (operateType == static_cast<uint32_t>(FuncOperateType::SET)) {
            parcel.WriteParcelable(&admin);
            GenerateSetData(data, pos, stringSize, size, parcel);
        } else if (operateType == static_cast<uint32_t>(FuncOperateType::REMOVE)) {
            parcel.WriteParcelable(&admin);
            parcel.WriteString(CommonFuzzer::GetString(data, pos, stringSize, size));
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