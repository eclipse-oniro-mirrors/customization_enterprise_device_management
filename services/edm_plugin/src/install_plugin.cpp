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
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(InstallPlugin::GetPlugin());
const std::string HAP_DIRECTORY = "/data/service/el1/public/edm/stream_install";
const std::string RELATIVE_PATH = "../";
const std::string CURRENT_PATH = "./";
const std::string SEPARATOR = "/";
constexpr int32_t EDM_UID = 3057;
constexpr int32_t EDM_GID = 3057;

void InstallPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<InstallPlugin, InstallParam>> ptr)
{
    EDMLOGI("InstallPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::INSTALL, "install", "ohos.permission.ENTERPRISE_INSTALL_BUNDLE",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(InstallParamSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&InstallPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode InstallPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    std::string fileName = data.ReadString();
    std::string bundlePath = HAP_DIRECTORY + "/" + fileName;

    if (bundlePath.length() > PATH_MAX) {
        EDMLOGE("bundlePath length is error, the length is: [%{public}zu]", bundlePath.length());
        reply.WriteInt32(EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
        reply.WriteString("invalid hapFilePath");
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }
    if (fileName.find(RELATIVE_PATH) != std::string::npos || fileName.find(CURRENT_PATH) != std::string::npos ||
        fileName.find(SEPARATOR) != std::string::npos) {
        EDMLOGE("file path %{public}s invalid", bundlePath.c_str());
        reply.WriteInt32(EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
        reply.WriteString("invalid hapFilePath");
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }
    if (!CreateDirectory()) {
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    int32_t fd = open(bundlePath.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        EDMLOGE("open bundlePath %{public}s failed", bundlePath.c_str());
        DeleteFiles();
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteFileDescriptor(fd);
    reply.WriteString(bundlePath);
    return ERR_OK;
}

bool InstallPlugin::CreateDirectory()
{
    if (!OHOS::ForceCreateDirectory(HAP_DIRECTORY)) {
        EDMLOGE("mkdir %{public}s failed", HAP_DIRECTORY.c_str());
        return false;
    }
    if (chown(HAP_DIRECTORY.c_str(), EDM_UID, EDM_GID) != 0) {
        EDMLOGE("fail to change %{public}s ownership", HAP_DIRECTORY.c_str());
        return false;
    }
    mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    if (!OHOS::ChangeModeFile(HAP_DIRECTORY, mode)) {
        EDMLOGE("change mode failed, temp install dir : %{public}s", HAP_DIRECTORY.c_str());
        return false;
    }
    return true;
}

bool InstallPlugin::DeleteFiles()
{
    std::vector<std::string> files;
    OHOS::GetDirFiles(HAP_DIRECTORY, files);

    for (auto const &file : files) {
        if (!OHOS::RemoveFile(file)) {
            EDMLOGE("can not remove file : %{public}s", file.c_str());
            return false;
        }
    }
    return true;
}

ErrCode InstallPlugin::OnSetPolicy(InstallParam &param, MessageParcel &reply)
{
    EDMLOGI("InstallPlugin OnSetPolicy");
    AppExecFwk::InstallParam installParam;
    std::vector<std::string> realPaths;
    ErrCode initRet = InstallParamInit(param, reply, installParam, realPaths);
    if (initRet != ERR_OK) {
        return initRet;
    }

    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    auto iBundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        EDMLOGE("can not get iBundleMgr");
        DeleteFiles();
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    auto iBundleInstaller = iBundleMgr->GetBundleInstaller();
    if ((iBundleInstaller == nullptr) || (iBundleInstaller->AsObject() == nullptr)) {
        EDMLOGE("can not get iBundleInstaller");
        DeleteFiles();
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<InstallerCallback> callback = new (std::nothrow) InstallerCallback();
    if (callback == nullptr) {
        DeleteFiles();
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    ErrCode ret = iBundleInstaller->StreamInstall(realPaths, installParam, callback);
    if (FAILED(ret)) {
        if (!DeleteFiles()) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        EDMLOGE("StreamInstall resultCode %{public}d", ret);
        reply.WriteInt32(EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
        reply.WriteString("invalid hap file path");
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }
    ret = callback->GetResultCode();
    std::string errorMessage = callback->GetResultMsg();
    EDMLOGE("StreamInstall resultCode %{public}d resultMsg %{public}s.", ret, errorMessage.c_str());
    if (!DeleteFiles()) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (ret != ERR_OK) {
        reply.WriteInt32(EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
        reply.WriteString(errorMessage);
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }
    EDMLOGI("InstallPlugin OnSetPolicy end");
    return ERR_OK;
}

ErrCode InstallPlugin::InstallParamInit(InstallParam &param, MessageParcel &reply,
    AppExecFwk::InstallParam &installParam, std::vector<std::string> &realPaths)
{
    installParam.userId = param.userId;
    installParam.installFlag = static_cast<AppExecFwk::InstallFlag>(param.installFlag);
    std::vector<std::string> hapFilePaths = param.hapFilePaths;

    for (auto const &hapFilePath : hapFilePaths) {
        std::string realPath = "";
        if (!PathToRealPath(hapFilePath, realPath)) {
            EDMLOGE("invalid hap file path");
            std::string errMsg = "invalid hap file path";
            reply.WriteInt32(EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
            reply.WriteString(errMsg);
            DeleteFiles();
            return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
        }
        realPaths.emplace_back(realPath);
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
