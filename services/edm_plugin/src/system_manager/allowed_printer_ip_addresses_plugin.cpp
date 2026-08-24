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
 
#include "allowed_printer_ip_addresses_plugin.h"
 
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "array_string_serializer.h"
#include "allowed_printer_ip_addresses_util.h"
 
namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(AllowedPrinterIPAddressesPlugin::GetPlugin());
 
void AllowedPrinterIPAddressesPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<AllowedPrinterIPAddressesPlugin, std::vector<std::string>>> ptr)
{
    EDMLOGI("AllowedPrinterIPAddressesPlugin::InitPlugin start");
 
    ptr->InitAttribute(EdmInterfaceCode::ALLOWED_PRINTER_IP_ADDRESS_FOR_DEVICE,
        PolicyName::POLICY_ALLOWED_PRINTER_IP_ADDRESSES_FOR_DEVICE,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&AllowedPrinterIPAddressesPlugin::OnBasicSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&AllowedPrinterIPAddressesPlugin::OnBasicRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnHandlePolicyDoneListener(&AllowedPrinterIPAddressesPlugin::OnChangedPolicyDone, FuncOperateType::SET);
    ptr->SetOnHandlePolicyDoneListener(&AllowedPrinterIPAddressesPlugin::OnChangedPolicyDone, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&AllowedPrinterIPAddressesPlugin::OnBasicAdminRemove);
    ptr->SetOnAdminRemoveDoneListener(&AllowedPrinterIPAddressesPlugin::OnAdminRemoveDone);
    maxListSize_ = EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE;
    overMaxReturnErrCode_ = EdmReturnErrCode::PARAM_ERROR;
}
 
void AllowedPrinterIPAddressesPlugin::OnChangedPolicyDone(bool isGlobalChanged)
{
    if (!isGlobalChanged) {
        return;
    }
    AllowedPrinterIpAddressesUtil::NotifyPrintPolicyChanged(
        EdmConstants::DEFAULT_USER_ID, AllowedPrinterIpAddressesType::DEVICE_TYPE);
}
 
void AllowedPrinterIPAddressesPlugin::OnAdminRemoveDone()
{
    AllowedPrinterIpAddressesUtil::NotifyPrintPolicyChanged(
        EdmConstants::DEFAULT_USER_ID, AllowedPrinterIpAddressesType::DEVICE_TYPE);
}
 
ErrCode AllowedPrinterIPAddressesPlugin::OnBasicSetPolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId)
{
    return AllowedPrinterIpAddressesUtil::OnSetPolicy(data, currentData, mergeData, userId,
        AllowedPrinterIpAddressesType::DEVICE_TYPE, maxListSize_, overMaxReturnErrCode_);
}
 
ErrCode AllowedPrinterIPAddressesPlugin::OnBasicRemovePolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId)
{
    return AllowedPrinterIpAddressesUtil::OnRemovePolicy(data, currentData, mergeData, userId,
        AllowedPrinterIpAddressesType::DEVICE_TYPE, maxListSize_, overMaxReturnErrCode_);
}
} // namespace EDM
} // namespace OHOS