/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "usb_manager_proxy.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code.h"
#include "message_parcel_utils.h"
#include "usb_device_id.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<UsbManagerProxy> UsbManagerProxy::instance_ = nullptr;
std::once_flag UsbManagerProxy::flag_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

std::shared_ptr<UsbManagerProxy> UsbManagerProxy::GetUsbManagerProxy()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<UsbManagerProxy>();
        }
    });
    return instance_;
}

int32_t UsbManagerProxy::SetUsbReadOnly(MessageParcel &data)
{
    EDMLOGD("UsbManagerProxy::SetUsbReadOnly");
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USB_READ_ONLY);
    ErrCode ret = EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
    return ret == EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED ? EdmReturnErrCode::SYSTEM_ABNORMALLY : ret;
}

int32_t UsbManagerProxy::DisableUsb(MessageParcel &data)
{
    EDMLOGD("UsbManagerProxy::DisableUsb");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    return proxy->SetPolicyDisabled(data, EdmInterfaceCode::DISABLE_USB);
}

int32_t UsbManagerProxy::IsUsbDisabled(MessageParcel &data, bool &result)
{
    EDMLOGD("UsbManagerProxy::IsUsbDisabled");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    return proxy->IsPolicyDisabled(data, EdmInterfaceCode::DISABLE_USB, result);
}

int32_t UsbManagerProxy::AddAllowedUsbDevices(MessageParcel &data)
{
    EDMLOGD("UsbManagerProxy::AddAllowedUsbDevices");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::ALLOWED_USB_DEVICES);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t UsbManagerProxy::RemoveAllowedUsbDevices(MessageParcel &data)
{
    EDMLOGD("UsbManagerProxy::RemoveAllowedUsbDevices");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::ALLOWED_USB_DEVICES);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t UsbManagerProxy::GetAllowedUsbDevices(MessageParcel &data, std::vector<UsbDeviceId> &result)
{
    EDMLOGD("UsbManagerProxy::GetAllowedUsbDevices");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel reply;
    proxy->GetPolicy(EdmInterfaceCode::ALLOWED_USB_DEVICES, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("UsbManagerProxy:GetAllowedUsbDevices fail. %{public}d", ret);
        return ret;
    }
    uint32_t size = reply.ReadUint32();
    if (size > EdmConstants::ALLOWED_USB_DEVICES_MAX_SIZE) {
        EDMLOGE("UsbManagerProxy:GetAllowedUsbDevices size=[%{public}u] is too large", size);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    EDMLOGI("UsbManagerProxy:GetAllowedUsbDevices return size:%{public}u", size);
    for (uint32_t i = 0; i < size; i++) {
        UsbDeviceId usbDeviceId;
        if (!UsbDeviceId::Unmarshalling(reply, usbDeviceId)) {
            EDMLOGE("EnterpriseDeviceMgrProxy::GetEnterpriseInfo read parcel fail");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        result.emplace_back(usbDeviceId);
    }
    return ERR_OK;
}

int32_t UsbManagerProxy::SetUsbStorageDeviceAccessPolicy(MessageParcel &data)
{
    EDMLOGD("UsbManagerProxy::SetUsbStorageDeviceAccessPolicy");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USB_READ_ONLY);
    return proxy->HandleDevicePolicy(funcCode, data);
}


int32_t UsbManagerProxy::GetUsbStorageDeviceAccessPolicy(MessageParcel &data, int32_t &result)
{
    EDMLOGD("UsbManagerProxy::GetUsbStorageDeviceAccessPolicy");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel reply;
    proxy->GetPolicy(EdmInterfaceCode::USB_READ_ONLY, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadInt32(result);
    return ERR_OK;
}
#ifdef USB_EDM_ENABLE
int32_t UsbManagerProxy::AddOrRemoveDisallowedUsbDevices(MessageParcel &data, bool isAdd)
{
    EDMLOGD("UsbManagerProxy::AddOrRemoveDisallowedUsbDevices");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::uint32_t funcCode = 0;
    std::uint32_t funcOperateType = static_cast<std::uint32_t>(isAdd ?
        FuncOperateType::SET : FuncOperateType::REMOVE);
    funcCode = POLICY_FUNC_CODE(funcOperateType, EdmInterfaceCode::DISALLOWED_USB_DEVICES);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t UsbManagerProxy::GetDisallowedUsbDevices(MessageParcel &data,
    std::vector<OHOS::USB::UsbDeviceType> &result)
{
    EDMLOGD("UsbManagerProxy::GetDisallowedUsbDevices");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel reply;
    proxy->GetPolicy(EdmInterfaceCode::DISALLOWED_USB_DEVICES, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("UsbManagerProxy:GetDisallowedUsbDevices fail. %{public}d", ret);
        return ret;
    }
    uint32_t size = reply.ReadUint32();
    if (size > EdmConstants::DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE) {
        EDMLOGE("UsbManagerProxy:GetDisallowedUsbDevices size=[%{public}u] is too large", size);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    EDMLOGI("UsbManagerProxy:GetDisallowedUsbDevices return size:%{public}u", size);
    for (uint32_t i = 0; i < size; i++) {
        OHOS::USB::UsbDeviceType usbDeviceType;
        if (!OHOS::USB::UsbDeviceType::Unmarshalling(reply, usbDeviceType)) {
            EDMLOGE("EnterpriseDeviceMgrProxy::GetEnterpriseInfo read parcel fail");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        result.emplace_back(usbDeviceType);
    }
    return ERR_OK;
}
#endif
} // namespace EDM
} // namespace OHOS
