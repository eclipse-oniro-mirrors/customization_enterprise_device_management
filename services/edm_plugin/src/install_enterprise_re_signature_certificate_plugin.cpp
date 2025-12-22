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

#include "install_enterprise_re_signature_certificate_plugin.h"

#include <cstdint>
#include <cstdlib>
#include <algorithm>
#include <sys/stat.h>
#include <system_ability_definition.h>

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "bundle_mgr_proxy.h"
#include "edm_sys_manager.h"

namespace OHOS {
namespace EDM {
static constexpr uint32_t MAX_CERTIFICATE_COUNT = 10;
static constexpr uint32_t MAX_FILE_SIZE = 10 * 1024 * 1024;
static const char* const LOWER_CERT_EXT = ".cer";
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<InstallEnterpriseReSignatureCertificatePlugin>());

InstallEnterpriseReSignatureCertificatePlugin::InstallEnterpriseReSignatureCertificatePlugin()
{
    policyCode_ = EdmInterfaceCode::INSTALL_ENTERPRISE_RE_SIGNATURE_CERTIFICATE;
    policyName_ = PolicyName::POLICY_INSTALL_ENTERPRISE_RE_SIGNATURE_CERTIFICATE;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_CERTIFICATE);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = false;
}

ErrCode InstallEnterpriseReSignatureCertificatePlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    if (type == FuncOperateType::SET) {
        return InstallEnterpriseReSignatureCertificate(data);
    } else if (type == FuncOperateType::REMOVE) {
        return UninstallEnterpriseReSignatureCertificate(data);
    }
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode InstallEnterpriseReSignatureCertificatePlugin::CheckParamVaild(std::string certificateAlias, int32_t fd,
    int32_t accountId)
{
    if (certificateAlias.empty() || fd < 0 || accountId < 0) {
        EDMLOGE("InstallEnterpriseReSignatureCertificate: parameter verification failed - "
                "certificateAlias empty or invalid fd or invalid accountId");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    auto aliasLength = certificateAlias.length();
    auto fileExt = aliasLength >= strlen(LOWER_CERT_EXT) ? certificateAlias.substr(aliasLength - 4) : "";
    std::string lowerFileExt = fileExt;
    std::transform(lowerFileExt.begin(), lowerFileExt.end(), lowerFileExt.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (aliasLength < strlen(LOWER_CERT_EXT) || lowerFileExt != LOWER_CERT_EXT) {
        EDMLOGE("InstallEnterpriseReSignatureCertificate: certificate alias format invalid - "
                "alias too short or invalid extension");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    struct stat statbuf;
    int fstatResult = fstat(fd, &statbuf);
    if (fstatResult != 0 || statbuf.st_size > MAX_FILE_SIZE) {
        EDMLOGE("InstallEnterpriseReSignatureCertificate: file validation failed - "
                "fstat failed or file too large");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    return ERR_OK;
}

ErrCode InstallEnterpriseReSignatureCertificatePlugin::InstallEnterpriseReSignatureCertificate(MessageParcel &data)
{
    std::string certificateAlias = data.ReadString();
    int32_t fd = data.ReadFileDescriptor();
    int32_t accountId = data.ReadInt32();
    if (CheckParamVaild(certificateAlias, fd, accountId) != ERR_OK) {
        close(fd);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    auto iBundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        EDMLOGE("InstallEnterpriseReSignatureCertificate: failed to get IBundleMgr");
        close(fd);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    auto iBundleInstaller = iBundleMgr->GetBundleInstaller();
    if (iBundleInstaller == nullptr) {
        EDMLOGE("InstallEnterpriseReSignatureCertificate: failed to get IBundleInstaller");
        close(fd);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::vector<std::string> certificateAliasList;
    if (iBundleInstaller->GetEnterpriseReSignatureCert(accountId, certificateAliasList) != ERR_OK) {
        EDMLOGE("InstallEnterpriseReSignatureCertificate: failed to get certificateAliasList");
        close(fd);
        return EdmReturnErrCode::CERTIFICATE_REACHED_LIMIT;
    }
    if (certificateAliasList.size() >= MAX_CERTIFICATE_COUNT) {
        EDMLOGE("InstallEnterpriseReSignatureCertificate: certificate alias list size >= 10, cannot install more");
        close(fd);
        return EdmReturnErrCode::CERTIFICATE_REACHED_LIMIT;
    }
    if (std::find(certificateAliasList.begin(), certificateAliasList.end(), certificateAlias) !=
        certificateAliasList.end()) {
        EDMLOGE("InstallEnterpriseReSignatureCertificate: certificate alias already exists");
        close(fd);
        return EdmReturnErrCode::CERTIFICATE_IS_INVALID;
    }
    if (iBundleInstaller->InstallEnterpriseReSignatureCert(certificateAlias, fd, accountId) != ERR_OK) {
        EDMLOGE("InstallEnterpriseReSignatureCertificate: failed to install certificate");
        close(fd);
        return EdmReturnErrCode::CERTIFICATE_IS_INVALID;
    }
    close(fd);
    return ERR_OK;
}

ErrCode InstallEnterpriseReSignatureCertificatePlugin::UninstallEnterpriseReSignatureCertificate(MessageParcel &data)
{
    std::string certificateAlias = data.ReadString();
    int32_t accountId = data.ReadInt32();
    auto aliasLength = certificateAlias.length();
    auto fileExt = aliasLength >= strlen(LOWER_CERT_EXT) ? certificateAlias.substr(aliasLength - 4) : "";
    std::string lowerFileExt = fileExt;
    std::transform(lowerFileExt.begin(), lowerFileExt.end(), lowerFileExt.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (certificateAlias.empty() || accountId < 0) {
        EDMLOGE("UninstallEnterpriseReSignatureCertificate: certificateAlias empty or invalid accountId");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (aliasLength < strlen(LOWER_CERT_EXT) || lowerFileExt != LOWER_CERT_EXT) {
        EDMLOGE("UninstallEnterpriseReSignatureCertificate: alias too short or invalid extension");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    auto iBundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        EDMLOGE("UninstallEnterpriseReSignatureCertificate: failed to get IBundleMgr");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    auto iBundleInstaller = iBundleMgr->GetBundleInstaller();
    if (iBundleInstaller == nullptr) {
        EDMLOGE("UninstallEnterpriseReSignatureCertificate: failed to get IBundleInstaller");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::vector<std::string> certificateAliasList;
    ErrCode getRet = iBundleInstaller->GetEnterpriseReSignatureCert(accountId, certificateAliasList);
    if (getRet != ERR_OK) {
        EDMLOGE("UninstallEnterpriseReSignatureCertificate: failed getRet: %{public}d", getRet);
        return EdmReturnErrCode::CERTIFICATE_NOT_EXIST;
    }
    if (std::find(certificateAliasList.begin(), certificateAliasList.end(), certificateAlias) ==
        certificateAliasList.end()) {
        EDMLOGE("UninstallEnterpriseReSignatureCertificate: certificate not found");
        return EdmReturnErrCode::CERTIFICATE_NOT_EXIST;
    }
    ErrCode uninstallRet = iBundleInstaller->UninstallEnterpriseReSignatureCert(certificateAlias, accountId);
    if (uninstallRet != ERR_OK) {
        EDMLOGE("UninstallEnterpriseReSignatureCertificate: failed uninstallRet: %{public}d", uninstallRet);
        return EdmReturnErrCode::CERTIFICATE_NOT_EXIST;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS