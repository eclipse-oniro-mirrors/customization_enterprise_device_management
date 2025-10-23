/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "installed_bundle_info_list_query.h"

#include <system_ability_definition.h>

#include <tuple>
#include <vector>

#include "bundle_info.h"
#include "bundle_mgr_proxy.h"
#include "bundle_resource_proxy.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace EDM {
const std::string BUNDLE_MANAGER_ASHMEM_NAME = "EdmBundleQueryAshemeName";

std::string InstalledBundleInfoListQuery::GetPolicyName()
{
    return PolicyName::POLICY_INSTALLED_BUNDLE_INFO_LIST;
}

std::string InstalledBundleInfoListQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_GET_ALL_BUNDLE_INFO;
}

ErrCode InstalledBundleInfoListQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    uint32_t bundleInfoGetFlag = data.ReadUint32();
    EDMLOGI("InstalledBundleInfoListQuery QueryPolicy bundleInfoGetFlag = %{public}d", bundleInfoGetFlag);
    std::vector<OHOS::AppExecFwk::BundleInfo> bundleInfos;
    bool queryResult = GetBundleInfosData(bundleInfoGetFlag, bundleInfos, userId);
    if (!queryResult) {
        EDMLOGE("InstalledBundleInfoListQuery QueryPolicy from bms failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (bundleInfos.empty()) {
        EDMLOGI("InstalledBundleInfoListQuery QueryPolicy queryResult empty.");
        return ERR_OK;
    }
    std::vector<EdmBundleInfo> edmBundleInfos;
    ConvertBundleInfoListData(bundleInfoGetFlag, bundleInfos, edmBundleInfos);
    bool additionalRet = GetAdditionalResourceInfosData(bundleInfoGetFlag, edmBundleInfos);
    if (!additionalRet) {
        EDMLOGE("InstalledBundleInfoListQuery GetAdditionalResourceInfosData from bms failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bool writeRet = WriteVectorToParcelIntelligent(edmBundleInfos, reply);
    if (!writeRet) {
        EDMLOGE("InstalledBundleInfoListQuery QueryPolicy WriteVectorToParcelIntelligent failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

bool InstalledBundleInfoListQuery::GetBundleInfosData(uint32_t edmBundleFlag,
    std::vector<OHOS::AppExecFwk::BundleInfo> &bundleInfos, int32_t userId)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (!proxy) {
        EDMLOGE("InstalledBundleInfoListQuery QueryPolicy getBundleMgr failed.");
        return false;
    }
    int32_t bmsFlags = 0;
    if ((edmBundleFlag & static_cast<uint32_t>(BundleInfoGetFlag::WITH_APPLICATION_INFO)) != 0) {
        bmsFlags |= static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    }
    if ((edmBundleFlag & static_cast<uint32_t>(BundleInfoGetFlag::WITH_SIGNATURE_INFO)) != 0) {
        bmsFlags |= static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO);
    }
    ErrCode getResult = proxy->GetBundleInfosV9(bmsFlags, bundleInfos, userId);
    if (FAILED(getResult)) {
        EDMLOGE("InstalledBundleInfoListQuery QueryPolicy getResult failed.");
        return false;
    }
    return true;
}

void InstalledBundleInfoListQuery::ConvertBundleInfoListData(uint32_t edmBundleFlag,
    const std::vector<OHOS::AppExecFwk::BundleInfo> &bmsBundleInfos, std::vector<EdmBundleInfo> &edmBundleInfos)
{
    for (auto &data : bmsBundleInfos) {
        EdmBundleInfo edmBundleInfo;
        ConvertBundleInfoListItem(edmBundleFlag, data, edmBundleInfo);
        edmBundleInfos.emplace_back(edmBundleInfo);
    }
}

void InstalledBundleInfoListQuery::ConvertBundleInfoListItem(uint32_t edmBundleFlag,
    const OHOS::AppExecFwk::BundleInfo &bundleInfo, EdmBundleInfo &edmBundleInfo)
{
    edmBundleInfo.versionCode = bundleInfo.versionCode;
    edmBundleInfo.minCompatibleVersionCode = bundleInfo.minCompatibleVersionCode;
    edmBundleInfo.targetVersion = bundleInfo.targetVersion;
    edmBundleInfo.appIndex = bundleInfo.appIndex;
    edmBundleInfo.installTime = bundleInfo.installTime;
    edmBundleInfo.updateTime = bundleInfo.updateTime;
    edmBundleInfo.firstInstallTime = bundleInfo.firstInstallTime;
    edmBundleInfo.name = bundleInfo.name;
    edmBundleInfo.vendor = bundleInfo.vendor;
    edmBundleInfo.versionName = bundleInfo.versionName;

    EdmSignatureInfo edmSignatureInfo;
    if ((edmBundleFlag & static_cast<uint32_t>(BundleInfoGetFlag::WITH_SIGNATURE_INFO)) != 0) {
        ConvertSignatureInfo(bundleInfo.signatureInfo, edmSignatureInfo);
    }
    edmBundleInfo.signatureInfo = edmSignatureInfo;

    EdmApplicationInfo edmApplicationInfo;
    if ((edmBundleFlag & static_cast<uint32_t>(BundleInfoGetFlag::WITH_APPLICATION_INFO)) != 0) {
        ConvertApplicationInfo(bundleInfo.applicationInfo, edmApplicationInfo);
    }
    edmBundleInfo.applicationInfo = edmApplicationInfo;
}

void InstalledBundleInfoListQuery::ConvertApplicationInfo(const OHOS::AppExecFwk::ApplicationInfo &applicationInfo,
    EdmApplicationInfo &edmApplicationInfo)
{
    edmApplicationInfo.removable = applicationInfo.removable;
    edmApplicationInfo.isSystemApp = applicationInfo.isSystemApp;
    edmApplicationInfo.debug = applicationInfo.debug;
    edmApplicationInfo.userDataClearable = applicationInfo.userDataClearable;
    edmApplicationInfo.enabled = applicationInfo.enabled;
    edmApplicationInfo.accessTokenId = applicationInfo.accessTokenId;
    edmApplicationInfo.iconId = applicationInfo.iconId;
    edmApplicationInfo.labelId = applicationInfo.labelId;
    edmApplicationInfo.descriptionId = applicationInfo.descriptionId;
    edmApplicationInfo.uid = applicationInfo.uid;
    edmApplicationInfo.appIndex = applicationInfo.appIndex;
    edmApplicationInfo.name = applicationInfo.name;
    edmApplicationInfo.description = applicationInfo.description;
    edmApplicationInfo.label = applicationInfo.label;
    edmApplicationInfo.icon = applicationInfo.iconPath;
    edmApplicationInfo.process = applicationInfo.process;
    edmApplicationInfo.codePath = applicationInfo.codePath;
    edmApplicationInfo.appDistributionType = applicationInfo.appDistributionType;
    edmApplicationInfo.appProvisionType = applicationInfo.appProvisionType;
    edmApplicationInfo.nativeLibraryPath = applicationInfo.nativeLibraryPath;
    edmApplicationInfo.installSource = applicationInfo.installSource;
    edmApplicationInfo.apiReleaseType = applicationInfo.apiReleaseType;

    EdmResource iconResource;
    ConvertResourceInfo(applicationInfo.iconResource, iconResource);
    edmApplicationInfo.iconResource = iconResource;

    EdmResource labelResource;
    ConvertResourceInfo(applicationInfo.labelResource, labelResource);
    edmApplicationInfo.labelResource = labelResource;

    EdmResource descriptionResource;
    ConvertResourceInfo(applicationInfo.descriptionResource, descriptionResource);
    edmApplicationInfo.descriptionResource = descriptionResource;
}

void InstalledBundleInfoListQuery::ConvertResourceInfo(const OHOS::AppExecFwk::Resource &resource,
    EdmResource &edmResource)
{
    edmResource.id = resource.id;
    edmResource.bundleName = resource.bundleName;
    edmResource.moduleName = resource.moduleName;
}

void InstalledBundleInfoListQuery::ConvertSignatureInfo(const OHOS::AppExecFwk::SignatureInfo &signatureInfo,
    EdmSignatureInfo &edmSignatureInfo)
{
    edmSignatureInfo.appId = signatureInfo.appId;
    edmSignatureInfo.fingerprint = signatureInfo.fingerprint;
    edmSignatureInfo.appIdentifier = signatureInfo.appIdentifier;
    edmSignatureInfo.certificate = signatureInfo.certificate;
}

bool InstalledBundleInfoListQuery::GetAdditionalResourceInfosData(uint32_t edmBundleFlag,
    std::vector<EdmBundleInfo> &edmBundleInfos)
{
    if ((edmBundleFlag & static_cast<uint32_t>(BundleInfoGetFlag::WITH_APPLICATION_INFO)) != 0 ||
        (edmBundleFlag & static_cast<uint32_t>(BundleInfoGetFlag::WITH_APPLICATION_ICON_INFO)) != 0) {
        std::vector<OHOS::AppExecFwk::BundleResourceInfo> bundleResourceInfos;
        bool getResourceRet = GetBundleResourceInfosData(edmBundleFlag, bundleResourceInfos);
        if (!getResourceRet) {
            EDMLOGE("InstalledBundleInfoListQuery GetBundleResourceInfosData failed.");
            return false;
        }
        AssembleBundleResourceInfo(edmBundleInfos, bundleResourceInfos);
    }
    return true;
}

bool InstalledBundleInfoListQuery::GetBundleResourceInfosData(uint32_t edmBundleFlag,
    std::vector<OHOS::AppExecFwk::BundleResourceInfo> &bundleResourceInfos)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (!proxy) {
        EDMLOGE("InstalledBundleInfoListQuery QueryPolicy getBundleMgr failed.");
        return false;
    }
    auto bundleResourceProxy = proxy->GetBundleResourceProxy();
    if (!bundleResourceProxy) {
        EDMLOGE("InstalledBundleInfoListQuery QueryPolicy GetBundleResourceProxy failed.");
        return false;
    }
    uint32_t bmsFlags = 0;
    if ((edmBundleFlag & static_cast<uint32_t>(BundleInfoGetFlag::WITH_APPLICATION_INFO)) != 0) {
        bmsFlags |= static_cast<uint32_t>(OHOS::AppExecFwk::ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL);
    }
    if ((edmBundleFlag & static_cast<uint32_t>(BundleInfoGetFlag::WITH_APPLICATION_ICON_INFO)) != 0) {
        bmsFlags |= static_cast<uint32_t>(OHOS::AppExecFwk::ResourceFlag::GET_RESOURCE_INFO_WITH_ICON);
    }
    ErrCode resourceResult = bundleResourceProxy->GetAllBundleResourceInfo(bmsFlags, bundleResourceInfos);
    if (FAILED(resourceResult)) {
        EDMLOGE("InstalledBundleInfoListQuery QueryPolicy resourceResult failed.");
        return false;
    }
    return true;
}

bool InstalledBundleInfoListQuery::WriteVectorToParcelIntelligent(std::vector<EdmBundleInfo>& parcelableVector,
    MessageParcel& reply)
{
    MessageParcel tempParcel;
    (void)tempParcel.SetMaxCapacity(EdmConstants::MAX_PARCEL_CAPACITY);
    if (!tempParcel.WriteInt32(parcelableVector.size())) {
        EDMLOGE("write ParcelableVector failed");
        return false;
    }

    for (auto &parcelable : parcelableVector) {
        if (!tempParcel.WriteParcelable(&parcelable)) {
            EDMLOGE("write ParcelableVector failed");
            return false;
        }
    }
    reply.WriteInt32(ERR_OK);
    size_t dataSize = tempParcel.GetDataSize();
    if (!reply.WriteInt32(static_cast<int32_t>(dataSize))) {
        EDMLOGE("write WriteInt32 failed");
        return false;
    }

    if (dataSize > EdmConstants::MAX_IPC_RAWDATA_SIZE) {
        (void)tempParcel.SetMaxCapacity(EdmConstants::MAX_PARCEL_CAPACITY_OF_ASHMEM);
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        EDMLOGI("datasize is too large, use ashmem %{public}d", callingUid);
        return WriteParcelableIntoAshmem(tempParcel, reply);
    }
    EDMLOGI("write to raw data");
    if (!reply.WriteRawData(reinterpret_cast<uint8_t *>(tempParcel.GetData()), dataSize)) {
        EDMLOGE("Failed to write data");
        return false;
    }
    return true;
}

bool InstalledBundleInfoListQuery::WriteParcelableIntoAshmem(MessageParcel &tempParcel, MessageParcel &reply)
{
    size_t dataSize = tempParcel.GetDataSize();
    // The ashmem name must be unique.
    sptr<Ashmem> ashmem = Ashmem::CreateAshmem(
        (BUNDLE_MANAGER_ASHMEM_NAME + std::to_string(AllocatAshmemNum())).c_str(), dataSize);
    if (ashmem == nullptr) {
        EDMLOGE("Create shared memory failed");
        return false;
    }

    // Set the read/write mode of the ashme.
    if (!ashmem->MapReadAndWriteAshmem()) {
        EDMLOGE("Map shared memory fail");
        return false;
    }

    // Write the size and content of each item to the ashmem.
    int32_t offset = 0;
    if (!ashmem->WriteToAshmem(reinterpret_cast<uint8_t *>(tempParcel.GetData()), dataSize, offset)) {
        EDMLOGE("Write info to shared memory fail");
        return false;
    }

    if (!reply.WriteAshmem(ashmem)) {
        EDMLOGE("Write ashmem to tempParcel fail");
        return false;
    }
    return true;
}

int32_t InstalledBundleInfoListQuery::AllocatAshmemNum()
{
    std::lock_guard<std::mutex> lock(bundleAshmemMutex_);
    return ashmemNum_++;
}

void InstalledBundleInfoListQuery::AssembleBundleResourceInfo(std::vector<EdmBundleInfo> &edmBundleInfos,
    std::vector<OHOS::AppExecFwk::BundleResourceInfo> &bundleResourceInfos)
{
    std::unordered_map<std::string, std::tuple<std::string, std::string>> sourceMap;
    for (const auto &item : bundleResourceInfos) {
        sourceMap[item.bundleName + "_" + std::to_string(item.appIndex)] = {item.label, item.icon};
    }
    for (auto &item : edmBundleInfos) {
        if (sourceMap.find(item.name + "_" + std::to_string(item.appIndex)) != sourceMap.end()) {
            auto &[label, iconData] = sourceMap[item.name + "_" + std::to_string(item.appIndex)];
            item.applicationInfo.label = label;
            item.applicationInfo.iconData = iconData;
        } else {
            EDMLOGW("not find resource info %{public}s", item.name.c_str());
        }
    }
}
} // namespace EDM
} // namespace OHOS