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
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "os_account_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<ManageNormalOsAccountPlugin>());

ManageNormalOsAccountPlugin::ManageNormalOsAccountPlugin()
{
    policyCode_ = EdmInterfaceCode::MANAGE_NORMAL_OS_ACCOUNT;
    policyName_ = PolicyName::POLICY_MANAGE_NORMAL_OS_ACCOUNT;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_SET_ACCOUNT_POLICY);
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
    DeserializeAccountIds(mergePolicyStr, accountIds);
    ErrCode ret = ERR_OK;
    if (type == FuncOperateType::SET) {
        const std::string flag = data.ReadString();
        if (flag == EdmConstants::CREATE_NORMAL_OS_ACCOUNT) {
            ret = HandleCreate(data, reply, accountIds);
        } else if (flag == EdmConstants::ACTIVATE_OS_ACCOUNT) {
            ret = HandleActivate(data, accountIds);
        } else {
            ret = EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    } else if (type == FuncOperateType::REMOVE) {
        ret = HandleRemove(data, accountIds);
    } else {
        ret = EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (ret == ERR_OK) {
        SerializeAccountIds(accountIds, policyData.mergePolicyData);
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
        return EdmReturnErrCode::PARAM_ERROR;
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
        return EdmReturnErrCode::ADD_OS_ACCOUNT_FAILED;
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
        return EdmReturnErrCode::ACCOUNT_RESTRICTED;
    }
    return ERR_OK;
}

ErrCode ManageNormalOsAccountPlugin::HandleActivate(MessageParcel &data, const std::vector<int32_t> &accountIds)
{
    int32_t accountId = data.ReadInt32();
    EDMLOGI("ManageNormalOsAccountPlugin activate accountId = %{public}d", accountId);
    if (accountId == DEFAULT_USER_ID) {
        ErrCode ret = OHOS::AccountSA::OsAccountManager::ActivateOsAccount(accountId);
        if (FAILED(ret)) {
            EDMLOGE("ManageNormalOsAccountPlugin ActivateOsAccount failed ret = %{public}d", ret);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        return ERR_OK;
    }
    bool accountAllowed = false;
    for (const auto &id : accountIds) {
        if (id == accountId) {
            accountAllowed = true;
            break;
        }
    }
    if (!accountAllowed) {
        EDMLOGE("ManageNormalOsAccountPlugin: Account %{public}d not allowed to activate", accountId);
        return EdmReturnErrCode::ACCOUNT_RESTRICTED;
    }
    ErrCode ret = OHOS::AccountSA::OsAccountManager::ActivateOsAccount(accountId);
    if (FAILED(ret)) {
        EDMLOGE("ManageNormalOsAccountPlugin ActivateOsAccount failed ret=%{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

bool ManageNormalOsAccountPlugin::DeserializeAccountIds(const std::string &policyData, std::vector<int32_t> &accountIds)
{
    if (policyData.empty()) {
        return false;
    }
    cJSON *root = cJSON_Parse(policyData.c_str());
    if (root == nullptr) {
        EDMLOGE("ManageNormalOsAccountPlugin cJSON_Parse failed");
        return false;
    }
    if (!cJSON_IsArray(root)) {
        cJSON_Delete(root);
        EDMLOGE("ManageNormalOsAccountPlugin policyData is not array");
        return false;
    }
    int32_t size = cJSON_GetArraySize(root);
    for (int32_t i = 0; i < size; ++i) {
        cJSON *item = cJSON_GetArrayItem(root, i);
        if (item != nullptr && cJSON_IsNumber(item)) {
            accountIds.push_back(static_cast<int32_t>(item->valueint));
        }
    }
    cJSON_Delete(root);
    return true;
}

bool ManageNormalOsAccountPlugin::SerializeAccountIds(const std::vector<int32_t> &accountIds, std::string &policyData)
{
    cJSON *root = cJSON_CreateArray();
    if (root == nullptr) {
        EDMLOGE("ManageNormalOsAccountPlugin cJSON_CreateArray failed");
        return false;
    }
    for (const auto &id : accountIds) {
        cJSON_AddItemToArray(root, cJSON_CreateNumber(static_cast<double>(id)));
    }
    char *jsonStr = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (jsonStr == nullptr) {
        EDMLOGE("ManageNormalOsAccountPlugin cJSON_PrintUnformatted failed");
        return false;
    }
    policyData = std::string(jsonStr);
    free(jsonStr);
    return true;
}
} // namespace EDM
} // namespace OHOS