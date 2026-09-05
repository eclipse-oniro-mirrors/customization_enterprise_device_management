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

#include "external_storage_device_mount_policy_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "disk_manager_client.h"
#include "disk.h"
#include "mount_param.h"
#include "mount_policy.h"
#include "volume_external.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<ExternalStorageDeviceMountPolicyPlugin>());

ExternalStorageDeviceMountPolicyPlugin::ExternalStorageDeviceMountPolicyPlugin()
{
    EDMLOGI("ExternalStorageDeviceMountPolicyPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::EXTERNAL_STORAGE_DEVICE_MOUNT_POLICY;
    policyName_ = PolicyName::POLICY_EXTERNAL_STORAGE_DEVICE_MOUNT_POLICY;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = false;
}

ErrCode ExternalStorageDeviceMountPolicyPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("ExternalStorageDeviceMountPolicyPlugin OnHandlePolicy");
    std::string volumeId = data.ReadString();
    int32_t policy = data.ReadInt32();
    EDMLOGI("volumeId: %{public}s, policy: %{public}d", volumeId.c_str(), policy);

    ErrCode ret = ExecuteMountPolicy(volumeId, policy);
    if (ret != ERR_OK) {
        EDMLOGE("ExecuteMountPolicy failed, volumeId: %{public}s, policy: %{public}d", volumeId.c_str(), policy);
        return ret;
    }
    return ERR_OK;
}

ErrCode ExternalStorageDeviceMountPolicyPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("ExternalStorageDeviceMountPolicyPlugin OnGetPolicy");
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}

ErrCode ExternalStorageDeviceMountPolicyPlugin::ExecuteMountPolicy(const std::string &volumeId, int32_t policy)
{
    int32_t ret = ERR_OK;
    if (policy == static_cast<int32_t>(MountPolicy::MOUNT_READ_WRITE) ||
        policy == static_cast<int32_t>(MountPolicy::MOUNT_READ_ONLY)) {
        EDMLOGI("Mount volumeId: %{public}s, policy: %{public}d", volumeId.c_str(), policy);
        OHOS::DiskManager::MountParam mountParam(policy == static_cast<int32_t>(MountPolicy::MOUNT_READ_ONLY));
        mountParam.SetFromEdmMount(true);
        ret = OHOS::DiskManager::DiskManagerClient::GetInstance().Mount(volumeId, mountParam);
        if (ret != ERR_OK) {
            EDMLOGE("Mount failed, volumeId: %{public}s, ret: %{public}d", volumeId.c_str(), ret);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    } else if (policy == static_cast<int32_t>(MountPolicy::UNMOUNT)) {
        EDMLOGI("Unmount volumeId: %{public}s", volumeId.c_str());
        ret = OHOS::DiskManager::DiskManagerClient::GetInstance().Unmount(volumeId);
        if (ret != ERR_OK) {
            EDMLOGE("Unmount failed, volumeId: %{public}s, ret: %{public}d", volumeId.c_str(), ret);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    } else {
        EDMLOGE("Invalid mount policy: %{public}d", policy);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
