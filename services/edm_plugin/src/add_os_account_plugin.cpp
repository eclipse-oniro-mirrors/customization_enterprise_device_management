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

#include "add_os_account_plugin.h"

#include "edm_ipc_interface_code.h"
#include "os_account_info.h"
#include "os_account_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(AddOsAccountPlugin::GetPlugin());

void AddOsAccountPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<AddOsAccountPlugin,
    std::map<std::string, std::string>>> ptr)
{
    EDMLOGD("AddOsAccountPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::ADD_OS_ACCOUNT, "add_os_account",
        "ohos.permission.ENTERPRISE_SET_ACCOUNT_POLICY", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(MapStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&AddOsAccountPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode AddOsAccountPlugin::OnSetPolicy(std::map<std::string, std::string> &data, MessageParcel &reply)
{
    EDMLOGI("AddOsAccountPlugin OnSetPolicy");
    auto it = data.begin();
    std::string accountName = it -> first;
    int32_t type = atoi(it -> second.c_str());
    OHOS::AccountSA::OsAccountType accountType = ParseOsAccountType(type);
    EDMLOGD("hyy ----  AddOsAccountPlugin::OnSetPolicy: name -- %{public}s, type -- %{public}d, ",
        accountName.c_str(), type);
    OHOS::AccountSA::OsAccountInfo accountInfo;
    ErrCode ret = AccountSA::OsAccountManager::CreateOsAccount(accountName, accountType, accountInfo);
    if (FAILED(ret)) {
        EDMLOGE("AddOsAccountPlugin CreateOsAccount failed");
        reply.WriteInt32(EdmReturnErrCode::ADD_OS_ACCOUNT_FAILED);
        return EdmReturnErrCode::ADD_OS_ACCOUNT_FAILED;
    }
    accountInfo.Marshalling(reply);
    EDMLOGI("AddOsAccountPlugin OnSetPolicy end");
    return ERR_OK;
}

OHOS::AccountSA::OsAccountType AddOsAccountPlugin::ParseOsAccountType(int32_t type)
{
    if (type == static_cast<int32_t>(OHOS::AccountSA::OsAccountType::ADMIN)
        || type == static_cast<int32_t>(OHOS::AccountSA::OsAccountType::NORMAL)
        || type == static_cast<int32_t>(OHOS::AccountSA::OsAccountType::GUEST)) {
        return static_cast<OHOS::AccountSA::OsAccountType>(type);
    }
    return OHOS::AccountSA::OsAccountType::END;
}
} // namespace EDM
} // namespace OHOS
