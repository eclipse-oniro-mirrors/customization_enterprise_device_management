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

#include <cstdint>
#include <cstdlib>

#include "cert_manager_api.h"
#include "cm_type.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
static constexpr uint32_t MAX_URI_LEN = 256;
static constexpr uint32_t MAX_ALIAS_LEN = 40;
static constexpr uint32_t MAX_CERT_URI_LEN = 64;
static constexpr uint32_t MAX_CERTIFICATE_COUNT = 256;

static const std::string INVALID_PARAMS_MSG = "the input parameters is invalid";
static const std::string NO_FOUND_MSG = "the certificate do not exist";
static const std::string INCORRECT_FORMAT_MSG = "the input cert data is invalid";
static const std::string MAX_CERT_COUNT_REACHED_MSG = "the count of certificates or credentials reach the max";
static const std::string ALIAS_LENGTH_REACHED_LIMIT_MSG = "the input alias length reaches the max";

static const std::unordered_map<int32_t, std::string> certErrMessageMap = {
    { CMR_ERROR_INVALID_ARGUMENT, INVALID_PARAMS_MSG },
    { CMR_ERROR_NOT_FOUND, NO_FOUND_MSG },
    { CMR_ERROR_NOT_EXIST, NO_FOUND_MSG },
    { CMR_ERROR_INVALID_CERT_FORMAT, INCORRECT_FORMAT_MSG },
    { CMR_ERROR_INSUFFICIENT_DATA, INCORRECT_FORMAT_MSG },
    { CMR_ERROR_MAX_CERT_COUNT_REACHED, MAX_CERT_COUNT_REACHED_MSG },
    { CMR_ERROR_ALIAS_LENGTH_REACHED_LIMIT, ALIAS_LENGTH_REACHED_LIMIT_MSG }
};

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<UserCertPlugin>());

UserCertPlugin::UserCertPlugin()
{
    policyCode_ = EdmInterfaceCode::INSTALL_CERTIFICATE;
    policyName_ = "install_certificate";
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_CERTIFICATE);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = false;
}

std::string UserCertPlugin::GetCertMessageFromRetcode(int32_t retCode)
{
    std::string retMessage;
    auto iter = certErrMessageMap.find(retCode);
    if (iter != certErrMessageMap.end()) {
        retMessage = iter->second;
    }
    return retMessage;
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

ErrCode UserCertPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGD("UserCertPlugin::OnGetPolicy");
    int32_t accountId = data.ReadInt32();
    UserCAProperty userCAProperty = {accountId, CM_CURRENT_USER};
    CertList certList = {0};
    certList.certsCount = MAX_CERTIFICATE_COUNT;
    uint32_t buffSize = certList.certsCount * sizeof(CertAbstract);
    certList.certAbstract = static_cast<CertAbstract *>(malloc(buffSize));
    if (certList.certAbstract == nullptr) {
        EDMLOGE("UserCertPlugin::InstallUserCert : malloc failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = CmGetUserCACertList(&userCAProperty, &certList);
    if (FAILED(ret) || certList.certsCount > MAX_CERTIFICATE_COUNT) {
        free(certList.certAbstract);
        certList.certAbstract = nullptr;
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    std::vector<std::string> uriList;
    for (uint32_t count = 0; count < certList.certsCount; count++) {
        std::string uriStr(certList.certAbstract[count].uri);
        uriList.emplace_back(uriStr);
    }
    reply.WriteStringVector(uriList);
    free(certList.certAbstract);
    certList.certAbstract = nullptr;
    return ERR_OK;
}

ErrCode UserCertPlugin::InstallUserCert(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("UserCertPlugin::InstallUserCert");
    std::vector<uint8_t> certArray;
    data.ReadUInt8Vector(&certArray);
    std::string alias = data.ReadString();
    int32_t accountId = data.ReadInt32();
    if (accountId < 0 || alias.length() >= MAX_ALIAS_LEN || alias.length() == 0) {
        EDMLOGE("UserCertPlugin::InstallUserCert: param error");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    uint8_t *ptr = certArray.data();
    CmBlob certCmBlob = {certArray.size(), ptr};

    uint8_t arr[MAX_ALIAS_LEN] = {0};
    std::copy(alias.begin(), alias.end(), std::begin(arr));
    CmBlob aliasCmBlob = {sizeof(arr), arr};

    uint8_t uriBuf[MAX_URI_LEN] = {0};
    CmBlob certUri = {sizeof(uriBuf), uriBuf};
    int32_t ret = CmInstallUserCACert(&certCmBlob, &aliasCmBlob, accountId, true, &certUri);
    EDMLOGD("UserCertPlugin::InstallUserCert : %{public}d.", ret);
    if (FAILED(ret)) {
        reply.WriteInt32(EdmReturnErrCode::MANAGED_CERTIFICATE_FAILED);
        std::string certMessage = GetCertMessageFromRetcode(ret);
        reply.WriteString(certMessage);
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
