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

#include "extra_policy_notification.h"

#include "admin.h"
#include "admin_manager.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "edm_os_account_manager_impl.h"
#include "enterprise_conn_manager.h"
#include "ienterprise_admin.h"
#include "plugin_manager.h"
#include "ipc_skeleton.h"
#include "edm_os_account_manager_impl.h"

namespace OHOS {
namespace EDM {
ErrCode ExtraPolicyNotification::Notify(const std::string &adminName, const int32_t userId, const bool isSuccess)
{
    UnloadPlugin((std::uint32_t)EdmInterfaceCode::POLICY_CODE_END +
        (std::uint32_t)EdmConstants::PolicyCode::START_COLLECT_LOG);
    std::shared_ptr<Admin> admin = AdminManager::GetInstance()->GetAdminByPkgName(adminName, userId);
    if (admin != nullptr) {
        std::string bundleName = admin->adminInfo_.packageName_;
        std::string abilityName = admin->adminInfo_.className_;
        if (abilityName.empty()) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        AAFwk::Want connectWant;
        connectWant.SetElementName(bundleName, abilityName);
        std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
        bool ret = manager->CreateCollectLogConnection(connectWant, IEnterpriseAdmin::COMMAND_ON_LOG_COLLECTED,
            userId, isSuccess);
        if (!ret) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}

ErrCode ExtraPolicyNotification::ReportKeyEvent(const std::string &adminName, const int32_t userId,
    const std::string &keyEvent)
{
    EDMLOGI("EnterpriseMgrAbility::ReportKeyEvent start");
    UnloadPlugin((std::uint32_t)EdmInterfaceCode::SET_KEY_CODE_POLICYS);
    std::shared_ptr<Admin> admin = AdminManager::GetInstance()->GetAdminByPkgName(adminName, userId);
    if (admin != nullptr) {
        std::string bundleName = admin->adminInfo_.packageName_;
        std::string abilityName = admin->adminInfo_.className_;
        if (abilityName.empty()) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        AAFwk::Want connectWant;
        connectWant.SetElementName(bundleName, abilityName);
        std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
        bool ret = manager->CreateKeyEventConnection(connectWant,
            static_cast<uint32_t>(IEnterpriseAdmin::COMMAND_ON_KEY_EVENT),
            userId, keyEvent);
        if (!ret) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}

ErrCode ExtraPolicyNotification::UnloadPlugin(uint32_t code)
{
    EDMLOGI("ExtraPolicyNotification::UnloadCollectLogPlugin");
    return PluginManager::GetInstance()->SetPluginUnloadFlag(code, true);
}
} // namespace EDM
} // namespace OHOS