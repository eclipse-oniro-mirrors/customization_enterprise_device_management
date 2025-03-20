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

#include "snapshot_skip_plugin.h"

#include "mock_session_manager_service_interface.h"

#include "array_string_serializer.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "iplugin_manager.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SnapshotSkipPlugin::GetPlugin());

void SnapshotSkipPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<SnapshotSkipPlugin, std::vector<std::string>>> ptr)
{
    EDMLOGI("SnapshotSkipPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::SNAPSHOT_SKIP, PolicyName::POLICY_SNAPSHOT_SKIP,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SnapshotSkipPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&SnapshotSkipPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
}

ErrCode SnapshotSkipPlugin::OnSetPolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId)
{
    EDMLOGD("SnapshotSkipPlugin OnSetPolicy");
    if (data.empty()) {
        EDMLOGW("SnapshotSkipPlugin OnSetPolicy data is empty.");
        return ERR_OK;
    }
    if (data.size() > EdmConstants::DISALLOW_LIST_FOR_ACCOUNT_MAX_SIZE) {
        EDMLOGE("SnapshotSkipPlugin OnSetPolicy input data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    auto afterHandle = ArrayStringSerializer::GetInstance()->SetUnionPolicyData(currentData, data);
    auto afterMerge = ArrayStringSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);
    if (afterMerge.size() > EdmConstants::DISALLOW_LIST_FOR_ACCOUNT_MAX_SIZE) {
        EDMLOGE("SnapshotSkipPlugin OnSetPolicy merge data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    int32_t ret = SetSnapshotSkipByUserIdAndBundleNameList(userId, afterMerge);
    if (FAILED(ret)) {
        EDMLOGE("SnapshotSkipPlugin SetSnapshotSkipByUserIdAndBundleNameList failed %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode SnapshotSkipPlugin::OnRemovePolicy(std::vector<std::string> &data, std::vector<std::string> &currentData,
    std::vector<std::string> &mergeData, int32_t userId)
{
    if (data.empty()) {
        EDMLOGW("SnapshotSkipPlugin OnRemovePolicy data is empty.");
        return ERR_OK;
    }
    if (data.size() > EdmConstants::DISALLOW_LIST_FOR_ACCOUNT_MAX_SIZE) {
        EDMLOGE("SnapshotSkipPlugin OnRemovePolicy input data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    auto afterHandle = ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(data, currentData);
    auto afterMerge = ArrayStringSerializer::GetInstance()->SetUnionPolicyData(mergeData, currentData);

    int32_t ret = SetSnapshotSkipByUserIdAndBundleNameList(userId, afterMerge);
    if (FAILED(ret)) {
        EDMLOGE("SnapshotSkipPlugin SetSnapshotSkipByUserIdAndBundleNameList failed %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

int32_t SnapshotSkipPlugin::SetSnapshotSkipByUserIdAndBundleNameList(int32_t userId,
    const std::vector<std::string> &mergeData)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(WINDOW_MANAGER_SERVICE_ID);
    if (remoteObject == nullptr) {
        EDMLOGE("SetSnapshotSkipByUserIdAndBundleNameList wms obj get fial");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    auto mockSessionManagerServiceProxy = iface_cast<OHOS::Rosen::IMockSessionManagerInterface>(remoteObject);
    if (mockSessionManagerServiceProxy == nullptr) {
        EDMLOGE("SetSnapshotSkipByUserIdAndBundleNameList wms obj cast fial");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return mockSessionManagerServiceProxy->SetSnapshotSkipByUserIdAndBundleNames(userId, mergeData);
}

ErrCode SnapshotSkipPlugin::OnAdminRemove(const std::string &adminName, std::vector<std::string> &data,
    std::vector<std::string> &mergeData, int32_t userId)
{
    int32_t ret = SetSnapshotSkipByUserIdAndBundleNameList(userId, mergeData);
    if (FAILED(ret)) {
        EDMLOGE("SnapshotSkipPlugin OnAdminRemove failed %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
