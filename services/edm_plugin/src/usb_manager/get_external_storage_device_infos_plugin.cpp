/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "get_external_storage_device_infos_plugin.h"

#include "disk_manager_client.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "external_storage_device_info.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<GetExternalStorageDeviceInfosPlugin>());

GetExternalStorageDeviceInfosPlugin::GetExternalStorageDeviceInfosPlugin()
{
    EDMLOGI("GetExternalStorageDeviceInfosPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::GET_EXTERNAL_STORAGE_DEVICE_INFOS;
    policyName_ = PolicyName::POLICY_EXTERNAL_STORAGE_DEVICE_INFOS;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode GetExternalStorageDeviceInfosPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("GetExternalStorageDeviceInfosPlugin OnGetPolicy.");
    auto &client = OHOS::DiskManager::DiskManagerClient::GetInstance();
    std::vector<OHOS::DiskManager::VolumeExternal> volumes;
    int32_t ret = client.GetAllVolumes(volumes);
    if (ret != 0) {
        EDMLOGE("GetExternalStorageDeviceInfosPlugin GetAllVolumes failed, ret=%{public}d", ret);
        reply.WriteInt32(EdmReturnErrCode::EXECUTE_TIME_OUT);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    EDMLOGI("GetExternalStorageDeviceInfosPlugin GetAllVolumes size=%{public}zu", volumes.size());

    std::vector<ExternalStorageDeviceInfo> deviceInfos;
    for (const auto &volume : volumes) {
        const std::string &diskId = volume.GetDiskId();
        OHOS::DiskManager::Disk disk;
        ret = client.GetDiskById(diskId, disk);
        if (ret != 0) {
            EDMLOGW("GetExternalStorageDeviceInfosPlugin GetDiskById failed, diskId=%{public}s ret=%{public}d",
                diskId.c_str(), ret);
            continue;
        }
        int32_t diskType = disk.GetDiskType();
        if (diskType != OHOS::DiskManager::DiskType::SD_FLAG &&
            diskType != OHOS::DiskManager::DiskType::USB_FLAG &&
            diskType != OHOS::DiskManager::DiskType::CD_FLAG) {
            continue;
        }
        ExternalStorageDeviceInfo deviceInfo;
        deviceInfo.type = diskType;
        deviceInfo.devicePath = volume.GetPath();
        deviceInfo.volumeId = volume.GetId();
        deviceInfo.mountStatus = (volume.GetState() == OHOS::DiskManager::VolumeState::MOUNTED);
        deviceInfo.vendorId = disk.GetVendorId();
        deviceInfo.productId = disk.GetProductId();
        deviceInfo.serial = disk.GetSerialNumber();
        deviceInfos.push_back(deviceInfo);
    }
    EDMLOGI("GetExternalStorageDeviceInfosPlugin return size=%{public}zu", deviceInfos.size());

    reply.WriteInt32(ERR_OK);
    reply.WriteUint32(static_cast<uint32_t>(deviceInfos.size()));
    for (const auto &deviceInfo : deviceInfos) {
        if (!deviceInfo.Marshalling(reply)) {
            EDMLOGE("GetExternalStorageDeviceInfosPlugin Marshalling failed");
            return EdmReturnErrCode::EXECUTE_TIME_OUT;
        }
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
