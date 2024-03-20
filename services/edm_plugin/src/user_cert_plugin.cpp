/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "user_cert_plugin.h"

#include "cert_manager_api.h"
#include "cm_type.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
static constexpr uint32_t MAX_URI_LEN = 256;
static constexpr uint32_t MAX_ALIAS_LEN = 40;
static constexpr uint32_t MAX_CERT_URI_LEN = 64;
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(std::make_shared<UserCertPlugin>());

UserCertPlugin::UserCertPlugin()
{
    policyCode_ = EdmInterfaceCode::INSTALL_CERTIFICATE;
    policyName_ = "install_certificate";
    permissionConfig_.permission = "ohos.permission.ENTERPRISE_MANAGE_CERTIFICATE";
    permissionConfig_.permissionType = IPlugin::PermissionType::SUPER_DEVICE_ADMIN;
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = false;
}

ErrCode UserCertPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    if (type == FuncOperateType::SET) {
        return InstallUserCert(data, reply);
    } else if (type == FuncOperateType::REMOVE) {
        return UninstallUserCert(data, reply);
    }
    return EdmReturnErrCode::PARAM_ERROR;
}

ErrCode UserCertPlugin::InstallUserCert(MessageParcel &data, MessageParcel &reply)
{
    std::vector<uint8_t> certArray;
    data.ReadUInt8Vector(&certArray);
    std::string alias = data.ReadString();
    if (alias.length() >= MAX_ALIAS_LEN || alias.length() == 0) {
        EDMLOGE("InstallUserCert alias length error");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    uint8_t *ptr = certArray.data();
    CmBlob certCmBlob = {certArray.size(), ptr};

    uint8_t arr[MAX_ALIAS_LEN] = {0};
    std::copy(alias.begin(), alias.end(), std::begin(arr));
    CmBlob aliasCmBlob = {sizeof(arr), arr};

    uint8_t uriBuf[MAX_URI_LEN] = {0};
    CmBlob certUri = {sizeof(uriBuf), uriBuf};

    int32_t ret = CmInstallUserTrustedCert(&certCmBlob, &aliasCmBlob, &certUri);
    EDMLOGD("UserCertPlugin::CmInstallUserTrustedCert : %{public}d.", ret);
    if (FAILED(ret)) {
        reply.WriteInt32(EdmReturnErrCode::MANAGED_CERTIFICATE_FAILED);
        reply.WriteInt32(ret);
    } else {
        reply.WriteInt32(ERR_OK);
        std::string result = std::string(reinterpret_cast<char *>(certUri.data), certUri.size);
        reply.WriteString(result);
    }
    return ERR_OK;
}

ErrCode UserCertPlugin::UninstallUserCert(MessageParcel &data, MessageParcel &reply)
{
    std::string certUri = data.ReadString();
    if (certUri.length() >= MAX_CERT_URI_LEN || certUri.length() == 0) {
        EDMLOGE("UninstallUserCert alias length error");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    uint8_t arr[MAX_CERT_URI_LEN] = {0};
    std::copy(certUri.begin(), certUri.end(), std::begin(arr));
    CmBlob aliasCmBlob = {sizeof(arr), arr};

    int32_t ret = CmUninstallUserTrustedCert(&aliasCmBlob);
    if (FAILED(ret)) {
        reply.WriteInt32(EdmReturnErrCode::MANAGED_CERTIFICATE_FAILED);
        reply.WriteInt32(ret);
    } else {
        reply.WriteInt32(ERR_OK);
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
