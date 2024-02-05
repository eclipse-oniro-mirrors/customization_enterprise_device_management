/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "disallow_add_os_account_by_user_plugin.h"

#include "edm_ipc_interface_code.h"
#include "edm_utils.h"
#include "os_account_manager.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(DisallowAddOsAccountByUserPlugin::GetPlugin());
const char* const CONSTRAINT_CREATE_OS_ACCOUNT = "constraint.os.account.create";
const char* const CONSTRAINT_CREATE_OS_ACCOUNT_DIRECTLY = "constraint.os.account.create.directly";

void DisallowAddOsAccountByUserPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowAddOsAccountByUserPlugin, std::map<std::string, std::string>>> ptr)
{
    EDMLOGI("DisallowAddOsAccountByUserPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOW_ADD_OS_ACCOUNT_BY_USER, "disallow_add_os_account_by_user",
        "ohos.permission.ENTERPRISE_SET_ACCOUNT_POLICY", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(MapStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowAddOsAccountByUserPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode DisallowAddOsAccountByUserPlugin::OnSetPolicy(std::map<std::string, std::string> &data)
{
    auto it = data.begin();
    if (it == data.end()) {
        return ERR_OK;
    }
    int32_t userId = -1;
    ErrCode parseRet = EdmUtils::ParseStringToInt(it -> first, userId);
    if (FAILED(parseRet)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bool isIdExist = false;
    AccountSA::OsAccountManager::IsOsAccountExists(userId, isIdExist);
    if (!isIdExist) {
        EDMLOGE("DisallowAddOsAccountByUserPlugin userId invalid");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    bool disallow = it -> second == "true";
    return SetSpecificOsAccountConstraints(userId, disallow);
}

ErrCode DisallowAddOsAccountByUserPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGD("DisallowAddOsAccountByUserPlugin OnGetPolicy.");
    int32_t targetUserId = data.ReadInt32();
    bool isIdExist = false;
    AccountSA::OsAccountManager::IsOsAccountExists(targetUserId, isIdExist);
    if (!isIdExist) {
        EDMLOGE("DisallowAddOsAccountByUserPlugin userId invalid");
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<std::string> constraints;
    ErrCode ret = AccountSA::OsAccountManager::GetOsAccountAllConstraints(targetUserId, constraints);
    if (FAILED(ret)) {
        EDMLOGE("DisallowAddOsAccountByUserPlugin GetOsAccountAllConstraints failed");
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bool disallow =
        (std::find(constraints.begin(), constraints.end(), CONSTRAINT_CREATE_OS_ACCOUNT) != constraints.end()) &&
        (std::find(constraints.begin(), constraints.end(), CONSTRAINT_CREATE_OS_ACCOUNT_DIRECTLY) != constraints.end());
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(disallow);
    return ERR_OK;
}

ErrCode DisallowAddOsAccountByUserPlugin::SetSpecificOsAccountConstraints(int32_t userId, bool disallow)
{
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_CREATE_OS_ACCOUNT);
    constraints.emplace_back(CONSTRAINT_CREATE_OS_ACCOUNT_DIRECTLY);
    std::vector<int32_t> ids;
    AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (ids.empty()) {
        EDMLOGE("DisallowAddOsAccountByUserPlugin QueryActiveOsAccountIds failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    EDMLOGI("DisallowAddOsAccountByUserPlugin SetSpecificOsAccountConstraints: "
        "disallow: %{public}s, targetId: %{public}d, enforceId: %{public}d",
        disallow ? "true" : "false", userId, ids.at(0));
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(constraints, disallow, userId,
        ids.at(0), true);
    if (FAILED(ret)) {
        EDMLOGE("DisallowAddOsAccountByUserPlugin SetSpecificOsAccountConstraints failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
