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

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "volume_external.h"
#include "iservice_registry.h"


namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    DisallowExternalStorageCardPlugin::GetPlugin());
constexpr int32_t STORAGE_MANAGER_MANAGER_ID = 5003;

void DisallowExternalStorageCardPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowExternalStorageCardPlugin, bool>> ptr)
{
    EDMLOGI("DisallowExternalStorageCardPlugin InitPlugin...");
    ptr->InitAttribute(
        EdmInterfaceCode::DISALLOWED_EXTERNAL_STORAGE_CARD,
        PolicyName::POLICY_DISALLOWED_EXTERNAL_STORAGE_CARD,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowExternalStorageCardPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisallowExternalStorageCardPlugin::OnAdminRemove);
    persistParam_ = "persist.edm.external_storage_card_disable";
}

ErrCode DisallowExternalStorageCardPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisallowExternalStorageCardPlugin SetOtherModulePolicy");
    if (data == true) {
        ErrCode Ret = UnmountStorageDevice();
        if (Ret != ERR_OK) {
            EDMLOGI("DisallowExternalStorageCardPlugin OnSetPolicy: unmount storage device failed ret: %{public}d", Ret);
            return Ret;
        }
    }
    return ERR_OK;
}

ErrCode DisallowExternalStorageCardPlugin::OnSetPolicy(bool &data, bool &currentData, bool &mergeData, int32_t userId)
{
    EDMLOGI("DisallowExternalStorageCardPlugin OnSetPolicy");

    if (!persistParam_.empty() && !system::SetParameter(persistParam_, data ? "true" : "false")) {
        EDMLOGE("DisallowExternalStorageCardPlugin set param failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (data == true) {
        ErrCode Ret = SetOtherModulePolicy(data, userId);
        return Ret
    }
    return ERR_OK;
}

ErrCode DisallowExternalStorageCardPlugin::UnmountStorageDevice()
{
    auto storageMgrProxy = GetStorageManager();
    if (storageMgrProxy == nullptr) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::vector<StorageManager::VolumeExternal> volList;
    int32_t storageRet = storageMgrProxy->GetAllVolumes(volList);
    if (storageRet != ERR_OK) {
        EDMLOGE("DisallowExternalStorageCardPlugin SetPolicy storageMgrProxy GetAllVolumes failed! ret:%{public}d", storageRet);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (volList.empty()) {
        return ERR_OK;
    }
    for (auto &vol : volList) {
        if (storageMgrProxy->Unmount(vol.GetId()) != ERR_OK) {
            EDMLOGE("DisallowExternalStorageCardPlugin SetPolicy storageMgrProxy Unmount failed!");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}

OHOS::sptr<OHOS::StorageManager::IStorageManager> DisallowExternalStorageCardPlugin::GetStorageManager()
{
    auto saMgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        EDMLOGE("DisallowExternalStorageCardPlugin GetStorageManager:get saMgr fail");
        return nullptr;
    }
    sptr<IRemoteObject> obj = saMgr->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (obj == nullptr) {
        EDMLOGE("DisallowExternalStorageCardPlugin GetStorageManager:get storage manager client fail");
        return nullptr;
    }
    auto storageMgrProxy = iface_cast<OHOS::StorageManager::IStorageManager>(obj);
    if (storageMgrProxy == nullptr) {
        EDMLOGE("DisallowExternalStorageCardPlugin GetStorageManager:get storageMgrProxy fail");
    }
    return storageMgrProxy;
}
} // namespace EDM
} // namespace OHOS