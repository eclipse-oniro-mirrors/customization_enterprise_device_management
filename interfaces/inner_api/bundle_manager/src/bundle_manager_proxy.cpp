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
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "directory_ex.h"
#include "edm_log.h"
#include "func_code.h"
#include "message_parcel_utils.h"
#include "policy_type.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<BundleManagerProxy> BundleManagerProxy::instance_ = nullptr;
std::once_flag BundleManagerProxy::flag_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";
const std::string HAP_DIRECTORY = "/data/service/el1/public/edm/stream_install";
const std::string SEPARATOR = "/";
const int32_t SET_MARKET_APPS = 0;

bool BundleManagerProxy::GetData(void *&buffer, size_t size, const void *data)
{
    if (data == nullptr) {
        EDMLOGE("GetData failed due to null data");
        return false;
    }
    if (size == 0 || size > EdmConstants::MAX_PARCEL_CAPACITY_OF_ASHMEM) {
        EDMLOGE("GetData failed due to zero size");
        return false;
    }
    buffer = malloc(size);
    if (buffer == nullptr) {
        EDMLOGE("GetData failed due to malloc buffer failed");
        return false;
    }
    if (memcpy_s(buffer, size, data, size) != EOK) {
        free(buffer);
        EDMLOGE("GetData failed due to memcpy_s failed");
        return false;
    }
    return true;
}

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
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<BundleManagerProxy>();
        }
    });
    return instance_;
}

int32_t BundleManagerProxy::Uninstall(AppExecFwk::ElementName &admin, std::string bundleName, int32_t userId,
    bool isKeepData, std::string &retMessage)
{
    EDMLOGD("BundleManagerProxy::Uninstall");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
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
    MessageParcel data;
    std::uint32_t funcCode = 0;
    if (policyTypeMap_.find(policyType) != policyTypeMap_.end()) {
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
    MessageParcel data;
    std::uint32_t funcCode = 0;
    if (policyTypeMap_.find(policyType) != policyTypeMap_.end()) {
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
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(userId);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    if (policyTypeMap_.find(policyType) != policyTypeMap_.end()) {
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
    reply.ReadStringVector(&bundles);
    return ERR_OK;
}

int32_t BundleManagerProxy::InstallMarketApps(MessageParcel &data, std::vector<std::string> &apps)
{
    EDMLOGD("BundleManagerProxy::InstallMarketApps");
    data.WriteInt32(SET_MARKET_APPS);
    MessageParcel reply;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::INSTALL_MARKET_APPS);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
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
    off_t offset = 0;
    struct stat stat_buff;
    if (fstat(inputFd, &stat_buff) != 0) {
        EDMLOGE("fstat file failed!");
        close(outputFd);
        close(inputFd);
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }

    if (sendfile(outputFd, inputFd, &offset, stat_buff.st_size) == -1) {
        EDMLOGE("send file failed!");
        close(outputFd);
        close(inputFd);
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
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

int32_t BundleManagerProxy::GetInstalledBundleInfoList(AppExecFwk::ElementName &admin, int32_t userId,
    std::vector<EdmBundleInfo> &bundleInfos)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(userId);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::GET_BUNDLE_INFO_LIST, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("BundleManagerProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    return InnerGetVectorFromParcelIntelligent(reply, bundleInfos);
}

int32_t BundleManagerProxy::AddOrRemoveInstallationAllowedAppDistributionTypes(MessageParcel &data,
    FuncOperateType operateType)
{
    EDMLOGD("BluetoothManagerProxy::AddOrRemoveAllowedInstallAppDistributionTypes");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)operateType, EdmInterfaceCode::ALLOWED_INSTALL_APP_TYPE);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t BundleManagerProxy::GetInstallationAllowedAppDistributionTypes(MessageParcel &data,
    std::vector<int32_t> &installationAllowedAppDistributionTypes)
{
    EDMLOGD("BundleManagerProxy::GetInstallationAllowedAppDistributionTypes");
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::ALLOWED_INSTALL_APP_TYPE, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadInt32Vector(&installationAllowedAppDistributionTypes);
    return ERR_OK;
}

ErrCode BundleManagerProxy::InnerGetVectorFromParcelIntelligent(MessageParcel &reply,
    std::vector<EdmBundleInfo> &parcelableInfos)
{
    size_t dataSize = static_cast<size_t>(reply.ReadInt32());
    if (dataSize == 0) {
        EDMLOGI("Parcel no data");
        return ERR_OK;
    }

    void *buffer = nullptr;
    if (dataSize > EdmConstants::MAX_IPC_RAWDATA_SIZE) {
        EDMLOGI("dataSize is too large, use ashmem");
        if (GetParcelInfoFromAshMem(reply, buffer) != ERR_OK) {
            EDMLOGE("read data from ashmem fail, length %{public}zu", dataSize);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    } else {
        if (!GetData(buffer, dataSize, reply.ReadRawData(dataSize))) {
            EDMLOGE("Fail read raw data length %{public}zu", dataSize);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }

    MessageParcel tempParcel;
    if (!tempParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
        EDMLOGE("Fail to ParseFrom");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    int32_t infoSize = tempParcel.ReadInt32();
    if (!ContainerSecurityVerify(tempParcel, infoSize, parcelableInfos)) {
        EDMLOGE("security verify failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<EdmBundleInfo> info(tempParcel.ReadParcelable<EdmBundleInfo>());
        if (info == nullptr) {
            EDMLOGE("Read Parcelable infos failed");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        parcelableInfos.emplace_back(*info);
    }

    return ERR_OK;
}

ErrCode BundleManagerProxy::GetParcelInfoFromAshMem(MessageParcel &reply, void *&data)
{
    sptr<Ashmem> ashMem = reply.ReadAshmem();
    if (ashMem == nullptr) {
        EDMLOGE("Ashmem is nullptr");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    if (!ashMem->MapReadOnlyAshmem()) {
        EDMLOGE("MapReadOnlyAshmem failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ashMemSize = ashMem->GetAshmemSize();
    int32_t offset = 0;
    const void* ashDataPtr = ashMem->ReadFromAshmem(ashMemSize, offset);
    if (ashDataPtr == nullptr) {
        EDMLOGE("ashDataPtr is nullptr");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if ((ashMemSize == 0) || ashMemSize > static_cast<int32_t>(EdmConstants::MAX_PARCEL_CAPACITY_OF_ASHMEM)) {
        EDMLOGE("failed due to wrong size");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    data = malloc(ashMemSize);
    if (data == nullptr) {
        EDMLOGE("failed due to malloc data failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (memcpy_s(data, ashMemSize, ashDataPtr, ashMemSize) != EOK) {
        free(data);
        EDMLOGE("failed due to memcpy_s failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

bool BundleManagerProxy::ContainerSecurityVerify(MessageParcel &parcel, int32_t infoSize,
    std::vector<EdmBundleInfo> &parcelables)
{
    size_t readAbleDataSize = parcel.GetReadableBytes();
    size_t readSize = static_cast<size_t>(infoSize);
    if ((readSize > readAbleDataSize) || (parcelables.max_size() < readSize)) {
        EDMLOGE("Failed to read container, readSize = %{public}zu, readAbleDataSize = %{public}zu",
            readSize, readAbleDataSize);
        return false;
    }
    return true;
}
} // namespace EDM
} // namespace OHOS
