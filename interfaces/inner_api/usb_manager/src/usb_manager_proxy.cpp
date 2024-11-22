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

int32_t UsbManagerProxy::SetUsbReadOnly(const AppExecFwk::ElementName &admin, bool readOnly)
{
    EDMLOGD("UsbManagerProxy::SetUsbReadOnly");
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USB_READ_ONLY);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(readOnly ? 1 : 0);
    ErrCode ret = EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
    return ret == EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED ? EdmReturnErrCode::SYSTEM_ABNORMALLY : ret;
}

int32_t UsbManagerProxy::DisableUsb(const AppExecFwk::ElementName &admin, bool disable)
{
    EDMLOGD("UsbManagerProxy::DisableUsb");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    return proxy->SetPolicyDisabled(admin, disable, EdmInterfaceCode::DISABLE_USB,
        EdmConstants::PERMISSION_TAG_VERSION_11);
}

int32_t UsbManagerProxy::IsUsbDisabled(const AppExecFwk::ElementName *admin, bool &result)
{
    EDMLOGD("UsbManagerProxy::IsUsbDisabled");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    return proxy->IsPolicyDisabled(admin, EdmInterfaceCode::DISABLE_USB, result,
        EdmConstants::PERMISSION_TAG_VERSION_11);
}

int32_t UsbManagerProxy::AddAllowedUsbDevices(const AppExecFwk::ElementName &admin,
    std::vector<UsbDeviceId> usbDeviceIds)
{
    EDMLOGD("UsbManagerProxy::AddAllowedUsbDevices");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::ALLOWED_USB_DEVICES);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteUint32(usbDeviceIds.size());
    for (const auto &usbDeviceId : usbDeviceIds) {
        if (!usbDeviceId.Marshalling(data)) {
            EDMLOGE("UsbManagerProxy AddAllowedUsbDevices: write parcel failed!");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t UsbManagerProxy::RemoveAllowedUsbDevices(const AppExecFwk::ElementName &admin,
    std::vector<UsbDeviceId> usbDeviceIds)
{
    EDMLOGD("UsbManagerProxy::RemoveAllowedUsbDevices");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::ALLOWED_USB_DEVICES);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteUint32(usbDeviceIds.size());
    for (const auto &usbDeviceId : usbDeviceIds) {
        if (!usbDeviceId.Marshalling(data)) {
            EDMLOGE("UsbManagerProxy RemoveAllowedUsbDevices: write parcel failed!");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t UsbManagerProxy::GetAllowedUsbDevices(const AppExecFwk::ElementName &admin, std::vector<UsbDeviceId> &result)
{
    EDMLOGD("UsbManagerProxy::GetAllowedUsbDevices");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
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

int32_t UsbManagerProxy::SetUsbStorageDeviceAccessPolicy(const AppExecFwk::ElementName &admin, int32_t usbPolicy)
{
    EDMLOGD("UsbManagerProxy::SetUsbStorageDeviceAccessPolicy");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USB_READ_ONLY);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(usbPolicy);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t UsbManagerProxy::GetUsbStorageDeviceAccessPolicy(const AppExecFwk::ElementName &admin, int32_t &result)
{
    EDMLOGD("UsbManagerProxy::GetUsbStorageDeviceAccessPolicy");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
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
int32_t UsbManagerProxy::AddOrRemoveDisallowedUsbDevices(const AppExecFwk::ElementName &admin,
    std::vector<OHOS::USB::UsbDeviceType> usbDeviceTypes, bool isAdd)
{
    EDMLOGD("UsbManagerProxy::AddOrRemoveDisallowedUsbDevices");
    size_t size = usbDeviceTypes.size();
    if (size > EdmConstants::DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE) {
        EDMLOGE("UsbManagerProxy:AddOrRemoveDisallowedUsbDevices size=[%{public}zu] is too large", size);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode = 0;
    if (isAdd) {
        funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_USB_DEVICES);
    } else {
        funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::DISALLOWED_USB_DEVICES);
    }
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteUint32(size);
    for (const auto &usbDeviceType : usbDeviceTypes) {
        if (!usbDeviceType.Marshalling(data)) {
            EDMLOGE("UsbManagerProxy AddOrRemoveDisallowedUsbDevices: write parcel failed!");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    EDMLOGI("UsbManagerProxy::AddOrRemoveDisallowedUsbDevices funcCode: %{public}u, usbDeviceTypes.size: %{public}zu",
        funcCode, size);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t UsbManagerProxy::GetDisallowedUsbDevices(const AppExecFwk::ElementName &admin,
    std::vector<OHOS::USB::UsbDeviceType> &result)
{
    EDMLOGD("UsbManagerProxy::GetDisallowedUsbDevices");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
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
