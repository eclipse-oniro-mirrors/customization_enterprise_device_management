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

#include "install_plugin.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <system_ability_definition.h>
#include <unistd.h>

#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "directory_ex.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "installer_callback.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(InstallPlugin::GetPlugin());
const std::string HAP_DIRECTORY = "/data/service/el1/public/edm/stream_install";
constexpr int32_t EDM_UID = 3057;
constexpr int32_t EDM_GID = 3057;

void InstallPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<InstallPlugin, InstallParam>> ptr)
{
    EDMLOGD("InstallPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::INSTALL, "install", "ohos.permission.ENTERPRISE_INSTALL_BUNDLE",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(InstallParamSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&InstallPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode InstallPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    struct stat buf = {};
    if ((stat(HAP_DIRECTORY.c_str(), &buf) == 0) && S_ISDIR(buf.st_mode)) {
        EDMLOGE("remove dir %{private}s failed", HAP_DIRECTORY.c_str());
        OHOS::ForceRemoveDirectory(HAP_DIRECTORY);
    }

    if (!OHOS::ForceCreateDirectory(HAP_DIRECTORY)) {
        EDMLOGE("mkdir %{private}s failed", HAP_DIRECTORY.c_str());
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }
    if (chown(HAP_DIRECTORY.c_str(), EDM_UID, EDM_GID) != 0) {
        EDMLOGE("fail to change %{private}s ownership", HAP_DIRECTORY.c_str());
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }
    mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    if (!OHOS::ChangeModeFile(HAP_DIRECTORY, mode)) {
        EDMLOGE("change mode failed, temp install dir : %{private}s", HAP_DIRECTORY.c_str());
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }

    std::string fileName = data.ReadString();
    std::string bundlePath = HAP_DIRECTORY + "/" + fileName;

    int32_t fd = open(bundlePath.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        EDMLOGE("open bundlePath %{public}s failed", bundlePath.c_str());
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteFileDescriptor(fd);
    reply.WriteString(bundlePath);
    return ERR_OK;
}

ErrCode InstallPlugin::OnSetPolicy(InstallParam &param, MessageParcel &reply)
{
    EDMLOGI("InstallPlugin OnSetPolicy");
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
    installParam.installFlag = static_cast<AppExecFwk::InstallFlag>(param.installFlag);
    EDMLOGI("InstallPlugin StreamInstall");
    ErrCode ret = iBundleInstaller->StreamInstall(param.hapFilePaths, installParam, callback);
    if (FAILED(ret)) {
        reply.WriteInt32(EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }
    ret = callback->GetResultCode();
    std::string errorMessage = callback->GetResultMsg();
    EDMLOGE("InnerRecover resultCode %{public}d resultMsg %{public}s.", ret, errorMessage.c_str());
    if (ret != ERR_OK) {
        reply.WriteInt32(EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
        reply.WriteString(errorMessage);
    }
    EDMLOGI("InstallPlugin OnSetPolicy end");
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
