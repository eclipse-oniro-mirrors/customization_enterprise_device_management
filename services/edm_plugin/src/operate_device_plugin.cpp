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

#include "operate_device_plugin.h"

#include "power_mgr_client.h"
#include "screenlock_manager.h"
#include "update_service_kits.h"

#include "edm_ipc_interface_code.h"
#include "operate_device_param_serializer.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(OperateDevicePlugin::GetPlugin());

void OperateDevicePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<OperateDevicePlugin, OperateDeviceParam>> ptr)
{
    EDMLOGI("OperateDevicePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::OPERATE_DEVICE, "operate_device", "ohos.permission.ENTERPRISE_OPERATE_DEVICE",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(OperateDeviceParamSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&OperateDevicePlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode OperateDevicePlugin::OnSetPolicy(OperateDeviceParam &param, MessageParcel &reply)
{
    EDMLOGD("OperateDevicePlugin OnSetPolicy operate = %{public}s, userId = %{public}d", param.operate.c_str(),
        param.userId);
    if (param.operate == EdmConstants::DeviceControl::LOCK_SCREEN) {
        int32_t ret = ScreenLock::ScreenLockManager::GetInstance()->Lock(param.userId);
        if (ret != ScreenLock::E_SCREENLOCK_OK) {
            EDMLOGE("OperateDevicePlugin:OnSetPolicy send request fail. %{public}d", ret);
            reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        reply.WriteInt32(ERR_OK);
        return ERR_OK;
    }
    if (param.operate == EdmConstants::DeviceControl::SHUT_DOWN ||
        param.operate == EdmConstants::DeviceControl::REBOOT) {
        auto& powerMgrClient = PowerMgr::PowerMgrClient::GetInstance();
        PowerMgr::PowerErrors ret;
        if (param.operate == EdmConstants::DeviceControl::SHUT_DOWN) {
            ret = powerMgrClient.ShutDownDevice("edm_Shutdown");
        } else {
            ret = powerMgrClient.RebootDevice("edm_Reboot");
        }
        if (ret != PowerMgr::PowerErrors::ERR_OK) {
            EDMLOGE("OperateDevicePlugin:OnSetPolicy send request fail. %{public}d", int32_t(ret));
            reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        reply.WriteInt32(ERR_OK);
        return ERR_OK;
    }
    if (param.operate == EdmConstants::DeviceControl::RESET_FACTORY) {
        UpdateEngine::BusinessError businessError;
        int32_t ret = UpdateEngine::UpdateServiceKits::GetInstance().FactoryReset(businessError);
        if (FAILED(ret)) {
            EDMLOGE("OperateDevicePlugin:OnSetPolicy send request fail. %{public}d", ret);
            reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        reply.WriteInt32(ERR_OK);
        return ERR_OK;
    }
    reply.WriteInt32(EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    OperateDeviceParamSerializer::GetInstance()->WritePolicy(reply, param);
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
} // namespace EDM
} // namespace OHOS
