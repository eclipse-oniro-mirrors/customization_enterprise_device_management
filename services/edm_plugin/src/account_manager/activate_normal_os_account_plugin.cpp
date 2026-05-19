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

#include "activate_normal_os_account_plugin.h"

#include <cJSON.h>
#include "account_error_no.h"
#include "array_int_serializer.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "os_account_manager.h"


namespace OHOS {
namespace EDM {
constexpr int32_t DEFAULT_USER_ID = 100;
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(ActivateNormalOsAccountPlugin::GetPlugin());

void ActivateNormalOsAccountPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<ActivateNormalOsAccountPlugin,
    int32_t>> ptr)
{
    EDMLOGI("ActivateNormalOsAccountPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::ACTIVATE_NORMAL_OS_ACCOUNT, PolicyName::POLICY_ACTIVATE_NORMAL_OS_ACCOUNT,
        EdmPermission::PERMISSION_ENTERPRISE_INTERACT_ACROSS_LOCAL_ACCOUNTS,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(IntSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&ActivateNormalOsAccountPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode ActivateNormalOsAccountPlugin::OnSetPolicy(int32_t &data)
{
    EDMLOGI("ActivateNormalOsAccountPlugin activate accountId = %{public}d", data);
    if (data == DEFAULT_USER_ID) {
        ErrCode ret = OHOS::AccountSA::OsAccountManager::ActivateOsAccount(data);
        if (FAILED(ret)) {
            EDMLOGE("ActivateNormalOsAccountPlugin ActivateOsAccount failed ret = %{public}d", ret);
            return EdmReturnErrCode::EXECUTE_TIME_OUT;
        }
        return ERR_OK;
    }
    std::vector<int32_t> localAccountIds;
    ErrCode ret = OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIds(localAccountIds);
    if (FAILED(ret)) {
        EDMLOGE("ActivateNormalOsAccountPlugin GetOsAccountLocalIds failed ret=%{public}d", ret);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    bool accountAllowed = IsValidId(localAccountIds, data);
    if (!accountAllowed) {
        EDMLOGE("ActivateNormalOsAccountPlugin: Account %{public}d not exist", data);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    std::vector<int32_t> normalAccountIds;
    std::string mergePolicyStr;
    IPolicyManager::GetInstance()->GetPolicy("", PolicyName::POLICY_MANAGE_NORMAL_OS_ACCOUNT, mergePolicyStr,
        DEFAULT_USER_ID);
    ArrayIntSerializer::GetInstance()->Deserialize(mergePolicyStr, normalAccountIds);
    accountAllowed = IsValidId(normalAccountIds, data);
    if (!accountAllowed) {
        EDMLOGE("ActivateNormalOsAccountPlugin: Account %{public}d not allowed to activate", data);
        return EdmReturnErrCode::ACCOUNT_RESTRICTED;
    }
    ret = OHOS::AccountSA::OsAccountManager::ActivateOsAccount(data);
    if (FAILED(ret)) {
        EDMLOGE("ActivateNormalOsAccountPlugin ActivateOsAccount failed ret=%{public}d", ret);
        if (ret == ERR_OSACCOUNT_SERVICE_LOGGED_IN_ACCOUNTS_OVERSIZE) {
            return EdmReturnErrCode::LOGIN_USER_NUMBER_UPPER_LIMIT;
        } else {
            return EdmReturnErrCode::EXECUTE_TIME_OUT;
        }
    }
    return ERR_OK;
}

bool ActivateNormalOsAccountPlugin::IsValidId(std::vector<int32_t> &accountIds, int32_t &data)
{
    for (const auto &id : accountIds) {
        if (id == data) {
            return true;
            break;
        }
    }
    return false;
}
} // namespace EDM
} // namespace OHOS