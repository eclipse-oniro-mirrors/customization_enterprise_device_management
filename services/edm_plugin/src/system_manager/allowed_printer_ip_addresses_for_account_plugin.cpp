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
 
#include "allowed_printer_ip_addresses_for_account_plugin.h"
 
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "array_string_serializer.h"
#include "allowed_printer_ip_addresses_util.h"
 
namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(AllowedPrinterIPAddressesForAccountPlugin::GetPlugin());
 
void AllowedPrinterIPAddressesForAccountPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<AllowedPrinterIPAddressesForAccountPlugin, std::vector<std::string>>> ptr)
{
    EDMLOGI("AllowedPrinterIPAddressesForAccountPlugin::InitPlugin start");
 
    ptr->InitAttribute(EdmInterfaceCode::ALLOWED_PRINTER_IP_ADDRESS_FOR_ACCOUNT,
        PolicyName::POLICY_ALLOWED_PRINTER_IP_ADDRESSES_FOR_ACCOUNT,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&AllowedPrinterIPAddressesForAccountPlugin::OnBasicSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&AllowedPrinterIPAddressesForAccountPlugin::OnBasicRemovePolicy,
        FuncOperateType::REMOVE);
    ptr->SetOnHandlePolicyDoneListener(&AllowedPrinterIPAddressesForAccountPlugin::OnChangedPolicyDone,
        FuncOperateType::SET);
    ptr->SetOnHandlePolicyDoneListener(&AllowedPrinterIPAddressesForAccountPlugin::OnChangedPolicyDone,
        FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&AllowedPrinterIPAddressesForAccountPlugin::OnBasicAdminRemove);
    ptr->SetOnAdminRemoveDoneListener(&AllowedPrinterIPAddressesForAccountPlugin::OnAdminRemoveDone);
    maxListSize_ = EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE;
    overMaxReturnErrCode_ = EdmReturnErrCode::PARAM_ERROR;
}
 
void AllowedPrinterIPAddressesForAccountPlugin::OnChangedPolicyDone(std::vector<std::string> &data,
    bool isGlobalChanged, int32_t userId)
{
    if (!isGlobalChanged) {
        return;
    }
    AllowedPrinterIpAddressesUtil::NotifyPrintPolicyChanged(userId, AllowedPrinterIpAddressesType::USER_TYPE);
}
 
void AllowedPrinterIPAddressesForAccountPlugin::OnAdminRemoveDone(const std::string &adminName,
    std::vector<std::string> &data, int32_t userId)
{
    AllowedPrinterIpAddressesUtil::NotifyPrintPolicyChanged(userId, AllowedPrinterIpAddressesType::USER_TYPE);
}
 
ErrCode AllowedPrinterIPAddressesForAccountPlugin::OnBasicSetPolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId)
{
    return AllowedPrinterIpAddressesUtil::OnSetPolicy(data, currentData, mergeData, userId,
        AllowedPrinterIpAddressesType::USER_TYPE, maxListSize_, overMaxReturnErrCode_);
}
 
ErrCode AllowedPrinterIPAddressesForAccountPlugin::OnBasicRemovePolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId)
{
    return AllowedPrinterIpAddressesUtil::OnRemovePolicy(data, currentData, mergeData, userId,
        AllowedPrinterIpAddressesType::USER_TYPE, maxListSize_, overMaxReturnErrCode_);
}
} // namespace EDM
} // namespace OHOS