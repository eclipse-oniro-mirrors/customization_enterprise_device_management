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

#include "bundle_manager_proxy.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "directory_ex.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "func_code.h"
#include "message_parcel_utils.h"
#include "policy_type.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<BundleManagerProxy> BundleManagerProxy::instance_ = nullptr;
std::mutex BundleManagerProxy::mutexLock_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";
const std::string HAP_DIRECTORY = "/data/service/el1/public/edm/stream_install";
const std::string SEPARATOR = "/";
const int32_t DEFAULT_BUFFER_SIZE = 65536;

BundleManagerProxy::BundleManagerProxy()
{
    AddPolicyTypeMap();
    EDMLOGD("BundleManagerProxy()");
}

BundleManagerProxy::~BundleManagerProxy()
{
    EDMLOGD("~BundleManagerProxy()");
}

void BundleManagerProxy::AddPolicyTypeMap()
{
    policyTypeMap_[static_cast<int32_t>(PolicyType::ALLOW_INSTALL)] = EdmInterfaceCode::ALLOWED_INSTALL_BUNDLES;
    policyTypeMap_[static_cast<int32_t>(PolicyType::DISALLOW_INSTALL)] = EdmInterfaceCode::DISALLOWED_INSTALL_BUNDLES;
    policyTypeMap_[static_cast<int32_t>(PolicyType::DISALLOW_UNINSTALL)] =
        EdmInterfaceCode::DISALLOWED_UNINSTALL_BUNDLES;
}

std::shared_ptr<BundleManagerProxy> BundleManagerProxy::GetBundleManagerProxy()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<BundleManagerProxy> temp = std::make_shared<BundleManagerProxy>();
            instance_ = temp;
        }
    }
    return instance_;
}

int32_t BundleManagerProxy::Uninstall(AppExecFwk::ElementName &admin, std::string bundleName, int32_t userId,
    bool isKeepData, std::string &retMessage)
{
    EDMLOGD("BundleManagerProxy::Uninstall");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteString(bundleName);
    data.WriteInt32(userId);
    data.WriteBool(isKeepData);
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::UNINSTALL);
    ErrCode ret = proxy->HandleDevicePolicy(funcCode, data, reply);
    if (ret == EdmReturnErrCode::PARAM_ERROR) {
        retMessage = reply.ReadString();
    }
    return ret;
}

int32_t BundleManagerProxy::AddBundlesByPolicyType(AppExecFwk::ElementName &admin, std::vector<std::string> &bundles,
    int32_t userId, int32_t policyType)
{
    EDMLOGD("BundleManagerProxy::AddBundlesByPolicyType policyType =%{public}d", policyType);
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode = 0;
    if (policyTypeMap_.count(policyType) > 0) {
        funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, policyTypeMap_[policyType]);
    } else {
        EDMLOGE("can not get policy type");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(userId);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteStringVector(bundles);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t BundleManagerProxy::RemoveBundlesByPolicyType(AppExecFwk::ElementName &admin, std::vector<std::string> &bundles,
    int32_t userId, int32_t policyType)
{
    EDMLOGD("BundleManagerProxy::RemoveBundlesByPolicyType policyType =%{public}d", policyType);
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode = 0;
    if (policyTypeMap_.count(policyType) > 0) {
        funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, policyTypeMap_[policyType]);
    } else {
        EDMLOGE("can not get policy type");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(userId);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteStringVector(bundles);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t BundleManagerProxy::GetBundlesByPolicyType(AppExecFwk::ElementName &admin, int32_t userId,
    std::vector<std::string> &bundles, int32_t policyType)
{
    EDMLOGD("BundleManagerProxy::GetAllowedOrDisallowedInstallBundles policyType =%{public}d", policyType);
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(userId);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    if (policyTypeMap_.count(policyType) > 0) {
        proxy->GetPolicy(policyTypeMap_[policyType], data, reply);
    } else {
        EDMLOGE("can not get policy type");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    int32_t size = reply.ReadInt32();
    if (size > EdmConstants::APPID_MAX_SIZE) {
        EDMLOGE("bundles size=[%{public}d] is too large", size);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.ReadStringVector(&bundles);
    return ERR_OK;
}

int32_t BundleManagerProxy::Install(AppExecFwk::ElementName &admin, std::vector<std::string> &hapFilePaths,
    AppExecFwk::InstallParam &installParam, std::string &errMessage)
{
    EDMLOGD("BundleManagerProxy::install");

    if (hapFilePaths.empty()) {
        EDMLOGE("install failed due to empty hapFilePaths");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<std::string> realPaths;
    for (auto const &hapFilePath : hapFilePaths) {
        ErrCode res = WriteFileToStream(admin, hapFilePath, realPaths, errMessage);
        if (res != ERR_OK) {
            EDMLOGE("WriteFileToStream failed");
            return res;
        }
    }

    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteStringVector(realPaths);
    MessageParcelUtils::WriteInstallParam(installParam, data);
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::INSTALL);
    ErrCode ret = proxy->HandleDevicePolicy(funcCode, data, reply);
    if (ret == EdmReturnErrCode::APPLICATION_INSTALL_FAILED) {
        errMessage = reply.ReadString();
        EDMLOGE("Install failed");
    }
    return ret;
}

ErrCode BundleManagerProxy::WriteFileToInner(MessageParcel &reply, const std::string &realPath,
    std::vector<std::string> &servicePaths, std::string &errMessage)
{
    int32_t sharedFd = reply.ReadFileDescriptor();
    servicePaths.emplace_back(reply.ReadString());
    if (sharedFd < 0) {
        EDMLOGE("write file to stream failed due to invalid file descriptor");
        errMessage = "write file to stream failed due to invalid file descriptor";
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }
    int32_t outputFd = dup(sharedFd);
    close(sharedFd);

    int32_t inputFd = open(realPath.c_str(), O_RDONLY);
    if (inputFd < 0) {
        close(outputFd);
        EDMLOGE("write file to stream failed due to open the hap file");
        errMessage = "write file to stream failed due to open the hap file";
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }
    char buffer[DEFAULT_BUFFER_SIZE] = {0};
    int offset = -1;
    while ((offset = read(inputFd, buffer, sizeof(buffer))) > 0) {
        if (write(outputFd, buffer, offset) < 0) {
            close(inputFd);
            close(outputFd);
            EDMLOGE("write file to the temp dir failed");
            errMessage = "write file to the temp dir failed";
            return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
        }
    }
    close(inputFd);
    fsync(outputFd);
    close(outputFd);
    return ERR_OK;
}

ErrCode BundleManagerProxy::WriteFileToStream(AppExecFwk::ElementName &admin, const std::string &hapFilePath,
    std::vector<std::string> &servicePaths, std::string &errMessage)
{
    std::string fileName;
    std::string realPath;
    ErrCode checkRet = checkHapFilePath(hapFilePath, fileName, realPath, errMessage);
    if (checkRet != ERR_OK) {
        return checkRet;
    }

    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    data.WriteString(fileName);
    proxy->GetPolicy(POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, EdmInterfaceCode::INSTALL), data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("BundleManagerProxy:WriteFileToStream fail. %{public}d", ret);
        errMessage = reply.ReadString();
        return ret;
    }
    if (WriteFileToInner(reply, realPath, servicePaths, errMessage) != ERR_OK) {
        EDMLOGE("write file to stream failed");
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }
    return ERR_OK;
}

ErrCode BundleManagerProxy::checkHapFilePath(const std::string &hapFilePath, std::string &fileName,
    std::string &realPath, std::string &errMessage)
{
    if (!PathToRealPath(hapFilePath, realPath)) {
        EDMLOGE("install failed due to invalid hapFilePaths");
        errMessage = "install failed due to invalid hapFilePaths";
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }

    // find hap file name
    size_t pos = realPath.find_last_of(SEPARATOR);
    if (pos == std::string::npos || pos == realPath.size() - 1) {
        EDMLOGE("write file to stream failed due to invalid file path");
        errMessage = "write file to stream failed due to invalid file path";
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }
    fileName = realPath.substr(pos + 1);
    if (fileName.empty()) {
        EDMLOGE("write file to stream failed due to invalid file path");
        errMessage = "write file to stream failed due to invalid file path";
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }
    std::string innerFilePath = HAP_DIRECTORY + SEPARATOR + fileName;
    if ((innerFilePath.length() > PATH_MAX)) {
        errMessage = "invalid hap file path";
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
