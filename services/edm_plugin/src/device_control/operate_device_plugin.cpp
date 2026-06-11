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

#include "edm_constants.h"
#include "power_mgr_client.h"
#include "screenlock_manager.h"
#include "update_service_kits.h"

#include "edm_ipc_interface_code.h"
#include "operate_device_param_serializer.h"
#include "iplugin_manager.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
const std::string DISALLOWED_RESET_FACTORY_PARAM = "persist.edm.reset_factory_disallowed";
#ifdef FEATURE_PC_ONLY
const std::string DISABLE_SECURE_ERASE_PARAM = "persist.edm.secure_erase_disable";
#endif
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(OperateDevicePlugin::GetPlugin());

void OperateDevicePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<OperateDevicePlugin, OperateDeviceParam>> ptr)
{
    EDMLOGI("OperateDevicePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::OPERATE_DEVICE, PolicyName::POLICY_OPERATE_DEVICE,
        EdmPermission::PERMISSION_ENTERPRISE_OPERATE_DEVICE, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(OperateDeviceParamSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&OperateDevicePlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode OperateDevicePlugin::OnDiskErase()
{
#ifdef FEATURE_PC_ONLY
    if (system::GetParameter(DISALLOWED_RESET_FACTORY_PARAM, "") == "true" ||
        system::GetParameter(DISABLE_SECURE_ERASE_PARAM, "") == "true") {
        EDMLOGE("disk erase policy conflict");
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    OHOS::UpdateService::FactoryResetStrategy strategy;
    strategy.scope = OHOS::UpdateService::FactoryResetScope::DATA_AND_OS;
    UpdateService::BusinessError businessError;
    int32_t ret = UpdateService::UpdateServiceKits::GetInstance().DeepFactoryReset(strategy, businessError);
    if (FAILED(ret)) {
        EDMLOGE("diskErase deepFactoryReset failed");
        return EdmReturnErrCode::DISK_ERASE_FAILED;
    }
    EDMLOGI("diskErase success");
    return ERR_OK;
#endif
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode OperateDevicePlugin::OnFactoryReset(MessageParcel &reply)
{
    std::string isDisabled = OHOS::system::GetParameter(DISALLOWED_RESET_FACTORY_PARAM, EdmConstants::CONST_FALSE);
    if (isDisabled == EdmConstants::CONST_TRUE) {
        EDMLOGE("OperateDevicePlugin:OnFactoryReset factory reset is disabled by restriction");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    UpdateService::BusinessError businessError;
    int32_t ret = UpdateService::UpdateServiceKits::GetInstance().ForceFactoryReset(businessError);
    if (FAILED(ret)) {
        EDMLOGE("OperateDevicePlugin:OnSetPolicy send request fail. %{public}d", ret);
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}

ErrCode OperateDevicePlugin::OnSetPolicy(OperateDeviceParam &param, MessageParcel &reply)
{
    EDMLOGD("OperateDevicePlugin OnSetPolicy operate = %{public}s", param.operate.c_str());
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
        return OnFactoryReset(reply);
    }
    if (param.operate == EdmConstants::DeviceControl::DISK_ERASE) {
#ifdef FEATURE_PC_ONLY
        return OnDiskErase();
#else
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
    }
    reply.WriteInt32(EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    OperateDeviceParamSerializer::GetInstance()->WritePolicy(reply, param);
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
} // namespace EDM
} // namespace OHOS
