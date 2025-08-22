/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "usb_policy_utils.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "ipolicy_manager.h"
#include "usb_device.h"
#include "usb_srv_client.h"
#ifdef OS_ACCOUNT_EDM_ENABLE
#include "os_account_manager.h"
#endif

namespace OHOS {
namespace EDM {
ErrCode UsbPolicyUtils::SetUsbDisabled(bool data)
{
    EDMLOGI("UsbPolicyUtils SetUsbDisabled...disable = %{public}d", data);
    auto &srvClient = OHOS::USB::UsbSrvClient::GetInstance();
    int32_t usbRet = srvClient.ManageGlobalInterface(data);
    if (usbRet == EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGW("UsbPolicyUtils ManageGlobalInterface failed! USB interface not init!");
    }
    if (usbRet != ERR_OK && usbRet != EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGE("UsbPolicyUtils ManageGlobalInterface failed! ret: %{public}d", usbRet);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode UsbPolicyUtils::AddAllowedUsbDevices(std::vector<UsbDeviceId> data)
{
    EDMLOGI("UsbPolicyUtils AddAllowedUsbDevices....data size = %{public}zu", data.size());
    auto &srvClient = OHOS::USB::UsbSrvClient::GetInstance();
    std::vector<OHOS::USB::UsbDevice> whiteList{};
    for (auto &dev : data) {
        USB::UsbDeviceId devId;
        devId.productId = dev.GetProductId();
        devId.vendorId = dev.GetVendorId();
        whiteList.emplace_back(devId);
    }
    int32_t usbRet = srvClient.ManageDevicePolicy(whiteList);
    if (usbRet == EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGW("UsbPolicyUtils ManageDevicePolicy failed! USB interface not init!");
    }
    if (usbRet != ERR_OK && usbRet != EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGE("UsbPolicyUtils ManageDevicePolicy failed: %{public}d", usbRet);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode UsbPolicyUtils::SetDisallowedUsbDevices(std::vector<USB::UsbDeviceType> data)
{
    EDMLOGI("UsbPolicyUtils SetDisallowedUsbDevices...data size = %{public}zu", data.size());
    auto &srvClient = OHOS::USB::UsbSrvClient::GetInstance();
    int32_t usbRet = srvClient.ManageInterfaceType(data, true);
    if (usbRet == EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGW("UsbPolicyUtils ManageInterfaceType failed! USB interface not init!");
    }
    if (usbRet != ERR_OK && usbRet != EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGE("UsbPolicyUtils ManageInterfaceType failed! ret:%{public}d", usbRet);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode UsbPolicyUtils::QueryAllCreatedOsAccountIds(std::vector<int32_t> &userIds)
{
    EDMLOGI("UsbPolicyUtils QueryAllCreatedOsAccountIds enter");
#ifdef OS_ACCOUNT_EDM_ENABLE
    std::vector<AccountSA::OsAccountInfo> accounts;
    ErrCode ret = OHOS::AccountSA::OsAccountManager::QueryAllCreatedOsAccounts(accounts);
    if (FAILED(ret) || accounts.empty()) {
        EDMLOGE("UsbPolicyUtils QueryAllCreatedOsAccountIds, QueryAllCreatedOsAccounts failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    for (auto &account : accounts) {
        userIds.push_back(account.GetLocalId());
    }
    EDMLOGI("UsbPolicyUtils QueryAllCreatedOsAccountIds success, size: %{public}zu", userIds.size());
    return ERR_OK;
#else
    EDMLOGE("UsbPolicyUtils QueryAllCreatedOsAccountIds, QueryAllCreatedOsAccounts Unsupported Capabilities.");
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
#endif
}

#ifdef FEATURE_PC_ONLY
ErrCode UsbPolicyUtils::IsUsbStorageDeviceWriteDisallowed(bool &isDisallowed)
{
    EDMLOGI("UsbPolicyUtils IsUsbStorageDeviceWriteDisallowed enter");
    std::vector<int32_t> userIds;
    if (FAILED(QueryAllCreatedOsAccountIds(userIds))) {
        EDMLOGE("UsbPolicyUtils IsUsbStorageDeviceWriteDisallowed, QueryAllCreatedOsAccountIds failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    auto policyManager = IPolicyManager::GetInstance();
    std::string disallowedUsbStorageDeviceWrite;
    for (size_t i = 0; i < userIds.size(); i++) {
        policyManager->GetPolicy("", PolicyName::POLICY_DISALLOWED_USB_STORAGE_DEVICE_WRITE,
            disallowedUsbStorageDeviceWrite, userIds[i]);
        if (disallowedUsbStorageDeviceWrite == "true") {
            EDMLOGI("UsbPolicyUtils IsUsbStorageDeviceWriteDisallowed, usbStorageDeviceWrite is disallowed");
            isDisallowed = true;
            return ERR_OK;
        }
    }
    EDMLOGI("UsbPolicyUtils IsUsbStorageDeviceWriteDisallowed end");
    return ERR_OK;
}
#endif
} // namespace EDM
} // namespace OHOS