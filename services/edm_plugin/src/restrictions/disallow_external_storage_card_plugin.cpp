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

#include "disallow_external_storage_card_plugin.h"

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "volume_external.h"
#include "iservice_registry.h"
#include "parameters.h"
#ifdef EXTERNAL_DISK_MANAGER_EDM_ENABLE
#include "disk_manager_client.h"
#endif

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<DisallowExternalStorageCardPlugin>());

DisallowExternalStorageCardPlugin::DisallowExternalStorageCardPlugin()
{
    EDMLOGI("DisallowExternalStorageCardPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOWED_EXTERNAL_STORAGE_CARD;
    policyName_ = PolicyName::POLICY_DISALLOWED_EXTERNAL_STORAGE_CARD;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
}

ErrCode DisallowExternalStorageCardPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisallowExternalStorageCardPlugin SetOtherModulePolicy");
    if (!system::SetParameter("persist.edm.external_storage_card_disable", data ? "true" : "false")) {
        EDMLOGE("DisallowExternalStorageCardPlugin set param failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (data) {
        ErrCode Ret = UnmountStorageDevice();
        if (Ret != ERR_OK) {
            EDMLOGI("DisallowExternalStorageCardPlugin: unmount storage device failed ret: %{public}d", Ret);
            return Ret;
        }
    }
    return ERR_OK;
}

ErrCode DisallowExternalStorageCardPlugin::UnmountStorageDevice()
{
#ifdef EXTERNAL_DISK_MANAGER_EDM_ENABLE
    std::vector<DiskManager::VolumeExternal> volList;
    int32_t storageRet = OHOS::DiskManager::DiskManagerClient::GetInstance().GetAllVolumes(volList);
    if (storageRet != ERR_OK) {
        EDMLOGE("DisallowExternalStorageCardPlugin diskMgr GetAllVolumes failed! ret:%{public}d", storageRet);
        return EdmReturnErrCode::DISALLOW_NOT_TAKE_EFFECT;
    }
    if (volList.empty()) {
        return ERR_OK;
    }
    for (auto &vol : volList) {
        if (OHOS::DiskManager::DiskManagerClient::GetInstance().Unmount(vol.GetId()) != ERR_OK) {
            EDMLOGE("DisallowExternalStorageCardPlugin SetPolicy diskMgr Unmount failed!");
            return EdmReturnErrCode::DISALLOW_NOT_TAKE_EFFECT;
        }
    }
    return ERR_OK;
#else
    EDMLOGE("DisallowExternalStorageCardPlugin::UnmountStorageDevice not support");
    return ERR_OK;
#endif
}
} // namespace EDM
} // namespace OHOS