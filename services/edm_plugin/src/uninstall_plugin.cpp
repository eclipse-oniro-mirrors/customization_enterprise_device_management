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

#include "uninstall_plugin.h"

#include <system_ability_definition.h>

#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "installer_callback.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(UninstallPlugin::GetPlugin());

void UninstallPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<UninstallPlugin, UninstallParam>> ptr)
{
    EDMLOGI("UninstallPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::UNINSTALL, "uninstall", "ohos.permission.ENTERPRISE_INSTALL_BUNDLE",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(UninstallParamSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&UninstallPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode UninstallPlugin::OnSetPolicy(UninstallParam &param, MessageParcel &reply)
{
    EDMLOGI("UninstallPlugin OnSetPolicy bundleName : %{public}s, userId : %{public}d, isKeepData : %{public}d",
        param.bundleName.c_str(), param.userId, param.isKeepData);

    const std::string bundleName = param.bundleName;
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    auto iBundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        EDMLOGE("can not get iBundleMgr");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    auto iBundleInstaller = iBundleMgr->GetBundleInstaller();
    if ((iBundleInstaller == nullptr) || (iBundleInstaller->AsObject() == nullptr)) {
        EDMLOGE("can not get iBundleInstaller");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<InstallerCallback> callback = new (std::nothrow) InstallerCallback();
    if (callback == nullptr) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    AppExecFwk::InstallParam installParam;
    installParam.userId = param.userId;
    installParam.isKeepData = param.isKeepData;
    iBundleInstaller->Uninstall(bundleName, installParam, callback);
    ErrCode ret = callback->GetResultCode();
    std::string errorMessage = callback->GetResultMsg();
    EDMLOGE("InnerRecover resultCode %{public}d resultMsg %{public}s.", ret, errorMessage.c_str());
    if (FAILED(ret)) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        reply.WriteString(errorMessage);
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
