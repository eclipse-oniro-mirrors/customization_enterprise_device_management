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
    EDMLOGI("InstalledBundleInfoListQuery QueryPolicy");
    std::vector<OHOS::AppExecFwk::BundleInfo> bundleInfos;
    std::vector<OHOS::AppExecFwk::BundleResourceInfo> bundleResourceInfos;
    bool queryResult = GetBundleInfosData(bundleInfos, bundleResourceInfos, userId);
    if (!queryResult) {
        EDMLOGE("InstalledBundleInfoListQuery QueryPolicy from bms failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (bundleInfos.empty() || bundleResourceInfos.empty()) {
        EDMLOGI("InstalledBundleInfoListQuery QueryPolicy queryResult empty.");
        return ERR_OK;
    }
    std::vector<EdmBundleInfo> edmBundleInfos;
    for (auto &data : bundleInfos) {
        EdmBundleInfo edmBundleInfo;
        bool convertRet = ConvertBundleInfoList(data, edmBundleInfo);
        if (!convertRet) {
            EDMLOGE("InstalledBundleInfoListQuery QueryPolicy ConvertBundleInfoList failed");
            continue;
        }
        edmBundleInfos.emplace_back(edmBundleInfo);
    }
    AssembleBundleResourceInfo(edmBundleInfos, bundleResourceInfos);
    bool writeRet = WriteVectorToParcelIntelligent(edmBundleInfos, reply);
    if (!writeRet) {
        EDMLOGE("InstalledBundleInfoListQuery QueryPolicy WriteVectorToParcelIntelligent failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

bool InstalledBundleInfoListQuery::GetBundleInfosData(std::vector<OHOS::AppExecFwk::BundleInfo> &bundleInfos,
    std::vector<OHOS::AppExecFwk::BundleResourceInfo> &bundleResourceInfos, int32_t userId)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (!proxy) {
        EDMLOGE("InstalledBundleInfoListQuery QueryPolicy getBundleMgr failed.");
        return false;
    }
    int32_t bundleFlags =
        static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION) |
        static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO);
    ErrCode getResult = proxy->GetBundleInfosV9(bundleFlags, bundleInfos, userId);
    if (FAILED(getResult)) {
        EDMLOGE("InstalledBundleInfoListQuery QueryPolicy getResult failed.");
        return false;
    }
    auto bundleResourceProxy = proxy->GetBundleResourceProxy();
    if (!bundleResourceProxy) {
        EDMLOGE("InstalledBundleInfoListQuery QueryPolicy GetBundleResourceProxy failed.");
        return false;
    }
    uint32_t bundleResourceFlags =
        static_cast<uint32_t>(OHOS::AppExecFwk::ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL);
    ErrCode resourceResult = bundleResourceProxy->GetAllBundleResourceInfo(bundleResourceFlags, bundleResourceInfos);
    if (FAILED(resourceResult)) {
        EDMLOGE("InstalledBundleInfoListQuery QueryPolicy resourceResult failed.");
        return false;
    }
    return true;
}

bool InstalledBundleInfoListQuery::ConvertBundleInfoList(OHOS::AppExecFwk::BundleInfo &bundleInfo,
    EdmBundleInfo &edmBundleInfo)
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
    bool signatureRet = ConvertSignatureInfo(bundleInfo.signatureInfo, edmSignatureInfo);
    if (!signatureRet) {
        EDMLOGE("InstalledBundleInfoListQuery ConvertSignatureInfo failed");
        return false;
    }
    edmBundleInfo.signatureInfo = edmSignatureInfo;

    EdmApplicationInfo edmApplicationInfo;
    bool applicationRet = ConvertApplicationInfo(bundleInfo.applicationInfo, edmApplicationInfo);
    if (!applicationRet) {
        EDMLOGE("InstalledBundleInfoListQuery ConvertApplicationInfo failed");
        return false;
    }
    edmBundleInfo.applicationInfo = edmApplicationInfo;
    return true;
}

bool InstalledBundleInfoListQuery::ConvertApplicationInfo(OHOS::AppExecFwk::ApplicationInfo &applicationInfo,
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
    return true;
}

bool InstalledBundleInfoListQuery::ConvertResourceInfo(OHOS::AppExecFwk::Resource &resource, EdmResource &edmResource)
{
    edmResource.id = resource.id;
    edmResource.bundleName = resource.bundleName;
    edmResource.moduleName = resource.moduleName;
    return true;
}

bool InstalledBundleInfoListQuery::ConvertSignatureInfo(OHOS::AppExecFwk::SignatureInfo &signatureInfo,
    EdmSignatureInfo &edmSignatureInfo)
{
    edmSignatureInfo.appId = signatureInfo.appId;
    edmSignatureInfo.fingerprint = signatureInfo.fingerprint;
    edmSignatureInfo.appIdentifier = signatureInfo.appIdentifier;
    edmSignatureInfo.certificate = signatureInfo.certificate;
    return true;
}

bool InstalledBundleInfoListQuery::WriteVectorToParcelIntelligent(std::vector<EdmBundleInfo> &parcelableVector,
    MessageParcel &reply)
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
    std::unordered_map<std::string, std::string> labelMap;
    for (const auto &item : bundleResourceInfos) {
        labelMap[item.bundleName + "_" + std::to_string(item.appIndex)] = item.label;
    }
    for (auto &item: edmBundleInfos) {
        if (labelMap.find(item.applicationInfo.name + "_" + std::to_string(item.appIndex)) != labelMap.end()) {
            item.applicationInfo.label = labelMap[item.applicationInfo.name + "_" + std::to_string(item.appIndex)];
        } else {
            EDMLOGW("not find label info %{public}s", item.applicationInfo.name.c_str());
        }
    }
}

} // namespace EDM
} // namespace OHOS