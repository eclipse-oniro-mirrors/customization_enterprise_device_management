/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "set_apn_plugin.h"
 
#include <memory>
#include "edm_constants.h"
#include "iplugin_manager.h"
#include "func_code_utils.h"
#include "edm_ipc_interface_code.h"

namespace OHOS {
namespace EDM {
namespace {
const std::string ADD_FLAG = "AddApn";
const std::string UPDATE_FLAG = "UpdateApn";
const std::string SET_PREFER_FLAG = "SetPreferApn";
const std::string QUERY_ID_FLAG = "QueryApnIds";
const std::string QUERY_INFO_FLAG = "QueryApn";
}
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<SetApnPlugin>());

SetApnPlugin::SetApnPlugin()
{
    policyCode_ = EdmInterfaceCode::SET_APN_INFO;
    policyName_ = PolicyName::POLICY_SET_APN_INFO;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APN);
    permissionConfig_.apiType = IPlugin::ApiType::SYSTEM;
    needSave_ = false;
}
 
ErrCode SetApnPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("SetApnPlugin::OnHandlePolicy start");
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    if (type == FuncOperateType::SET) {
        const std::string flag = data.ReadString();
        if (flag == ADD_FLAG) {
            return HandleAdd(data);
        } else if (flag == UPDATE_FLAG) {
            return HandleUpdate(data);
        } else if (flag == SET_PREFER_FLAG) {
            return HandleSetPrefer(data);
        } else {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    } else if (type == FuncOperateType::REMOVE) {
        return HandleRemove(data);
    } else {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
}

ErrCode SetApnPlugin::HandleAdd(MessageParcel &data)
{
    EDMLOGI("SetApnPlugin::HandleAdd start");
    std::map<std::string, std::string> apnInfo = ParserApnMap(data);
    return ApnUtils::ApnInsert(apnInfo) >= 0 ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode SetApnPlugin::HandleUpdate(MessageParcel &data)
{
    EDMLOGI("SetApnPlugin::HandleUpdate start");
    std::string apnId;
    if (data.ReadString(apnId)) {
        std::map<std::string, std::string> apnInfo = ParserApnMap(data);
        return ApnUtils::ApnUpdate(apnInfo, apnId) >= 0 ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
    } else {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
}

ErrCode SetApnPlugin::HandleSetPrefer(MessageParcel &data)
{
    EDMLOGI("SetApnPlugin::HandleSetPrefer start");
    std::string apnId;
    if (data.ReadString(apnId)) {
        return ApnUtils::ApnSetPrefer(apnId);
    } else {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
}

ErrCode SetApnPlugin::HandleRemove(MessageParcel &data)
{
    EDMLOGI("SetApnPlugin::HandleRemove start");
    std::string apnId;
    if (data.ReadString(apnId)) {
        return ApnUtils::ApnDelete(apnId) >= 0 ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
    } else {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
}

std::map<std::string, std::string> SetApnPlugin::ParserApnMap(MessageParcel &data)
{
    EDMLOGI("SetApnPlugin::ParserApnMap start");
    std::map<std::string, std::string> result;
    int32_t mapSize = -1;
    if (!data.ReadInt32(mapSize)) {
        EDMLOGI("SetApnPlugin::HandleRemove start");
        return {};
    }
    std::vector<std::string> keys(mapSize);
    for (int32_t idx = 0; idx < mapSize; ++idx) {
        keys[idx] = data.ReadString();
    }
    std::vector<std::string> values(mapSize);
    for (int32_t idx = 0; idx < mapSize; ++idx) {
        values[idx] = data.ReadString();
    }
    for (int32_t idx = 0; idx < mapSize; ++idx) {
        result[keys[idx]] = values[idx];
    }
    return result;
}

void SetApnPlugin::GenerateApnMap(std::map<std::string, std::string> &apnInfo, MessageParcel &reply)
{
    EDMLOGI("SetApnPlugin::GenerateApnMap start");
    reply.WriteInt32(static_cast<int32_t>(apnInfo.size()));
    for (auto & [key, value] : apnInfo) {
        reply.WriteString(key);
    }
    for (auto & [key, value] : apnInfo) {
        reply.WriteString(value);
    }
}

ErrCode SetApnPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    EDMLOGI("SetApnPlugin::OnGetPolicy start");
    const std::string flag = data.ReadString();
    if (flag == QUERY_ID_FLAG) {
        return QueryId(data, reply);
    } else if (flag == QUERY_INFO_FLAG) {
        return QueryInfo(data, reply);
    } else {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode SetApnPlugin::QueryInfo(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGI("SetApnPlugin::QueryInfo start");
    std::string apnId;
    if (data.ReadString(apnId)) {
        std::map<std::string, std::string> apnInfo = ApnUtils::ApnQuery(apnId);
        GenerateApnMap(apnInfo, reply);
        return ERR_OK;
    } else {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
}

ErrCode SetApnPlugin::QueryId(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGI("SetApnPlugin::QueryId start");
    std::map<std::string, std::string> apnInfo = ParserApnMap(data);
    std::vector<std::string> result = ApnUtils::ApnQuery(apnInfo);
    reply.WriteInt32(static_cast<int32_t>(result.size()));
    for (auto & ele : result) {
        reply.WriteString(ele);
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS