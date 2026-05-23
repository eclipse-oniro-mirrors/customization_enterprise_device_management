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

#include "manage_normal_os_account_plugin.h"

#include <cJSON.h>
#include "array_int_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "os_account_manager.h"

namespace OHOS {
namespace EDM {
constexpr int32_t MAX_NORMAL_OS_ACCOUNT_COUNT = 2;
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<ManageNormalOsAccountPlugin>());

ManageNormalOsAccountPlugin::ManageNormalOsAccountPlugin()
{
    policyCode_ = EdmInterfaceCode::MANAGE_NORMAL_OS_ACCOUNT;
    policyName_ = PolicyName::POLICY_MANAGE_NORMAL_OS_ACCOUNT;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_LOCAL_ACCOUNTS);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode ManageNormalOsAccountPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("ManageNormalOsAccountPlugin::OnHandlePolicy start");
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    std::vector<int32_t> accountIds;
    std::string mergePolicyStr;
    IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(), mergePolicyStr, userId);
    ArrayIntSerializer::GetInstance()->Deserialize(mergePolicyStr, accountIds);
    ErrCode ret = ERR_OK;
    if (type == FuncOperateType::SET) {
        ret = HandleCreate(data, reply, accountIds);
    } else if (type == FuncOperateType::REMOVE) {
        ret = HandleRemove(data, accountIds);
    } else {
        ret = EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (ret == ERR_OK) {
        ArrayIntSerializer::GetInstance()->Serialize(accountIds, policyData.mergePolicyData);
        policyData.isChanged = true;
    }
    return ret;
}

ErrCode ManageNormalOsAccountPlugin::HandleCreate(MessageParcel &data, MessageParcel &reply,
    std::vector<int32_t> &accountIds)
{
    std::string accountName = data.ReadString();
    if (accountName.empty()) {
        EDMLOGE("ManageNormalOsAccountPlugin accountName is empty");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (accountIds.size() >= MAX_NORMAL_OS_ACCOUNT_COUNT) {
        EDMLOGE("ManageNormalOsAccountPlugin: the number of accounts is MAX");
        return EdmReturnErrCode::ACCOUNT_NUMBER_UPPER_LIMIT;
    }
    OHOS::AccountSA::OsAccountInfo accountInfo;
    ErrCode ret = OHOS::AccountSA::OsAccountManager::CreateOsAccount(accountName,
        OHOS::AccountSA::OsAccountType::NORMAL, accountInfo);
    if (FAILED(ret)) {
        EDMLOGE("ManageNormalOsAccountPlugin CreateOsAccount failed ret = %{public}d", ret);
        switch (ret) {
            case ERR_AUTHORIZATION_PRIVILEGE_DENIED:
                return EdmReturnErrCode::USER_ACCESS_POLICY_PROHIBITED;
            case ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER:
                return EdmReturnErrCode::ACCOUNT_NUMBER_UPPER_LIMIT;
            case ERR_ACCOUNT_COMMON_NAME_HAD_EXISTED:
                return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
            default:
                return EdmReturnErrCode::ADD_OS_ACCOUNT_FAILED;
        }
    }
    int32_t newAccountId = accountInfo.GetLocalId();
    accountIds.push_back(newAccountId);
    EDMLOGI("ManageNormalOsAccountPlugin created account id = %{public}d, name = %{public}s",
        newAccountId, accountName.c_str());
    reply.WriteInt32(ERR_OK);
    accountInfo.Marshalling(reply);
    return ERR_OK;
}

ErrCode ManageNormalOsAccountPlugin::HandleRemove(MessageParcel &data, std::vector<int32_t> &accountIds)
{
    int32_t accountId = data.ReadInt32();
    EDMLOGI("ManageNormalOsAccountPlugin remove accountId = %{public}d", accountId);
    for (auto it = accountIds.begin(); it != accountIds.end(); ++it) {
        if (*it == accountId) {
            accountIds.erase(it);
            break;
        }
    }
    ErrCode ret = OHOS::AccountSA::OsAccountManager::RemoveOsAccount(accountId);
    if (FAILED(ret)) {
        EDMLOGE("ManageNormalOsAccountPlugin RemoveOsAccount failed ret = %{public}d", ret);
        switch (ret) {
            case ERR_AUTHORIZATION_PRIVILEGE_DENIED:
                return EdmReturnErrCode::USER_ACCESS_POLICY_PROHIBITED;
            case ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR:
                return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
            case ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR:
                return EdmReturnErrCode::ACCOUNT_RESTRICTED;
            default:
                return EdmReturnErrCode::EXECUTE_TIME_OUT;
        }
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS