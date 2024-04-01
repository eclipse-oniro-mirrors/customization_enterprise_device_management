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
std::mutex UsbManagerProxy::mutexLock_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

std::shared_ptr<UsbManagerProxy> UsbManagerProxy::GetUsbManagerProxy()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<UsbManagerProxy> temp = std::make_shared<UsbManagerProxy>();
            instance_ = temp;
        }
    }
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
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return proxy->SetPolicyDisabled(admin, disable, EdmInterfaceCode::DISABLE_USB,
        EdmConstants::PERMISSION_TAG_VERSION_11);
}

int32_t UsbManagerProxy::IsUsbDisabled(const AppExecFwk::ElementName *admin, bool &result)
{
    EDMLOGD("UsbManagerProxy::IsUsbDisabled");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return proxy->IsPolicyDisabled(admin, EdmInterfaceCode::DISABLE_USB, result,
        EdmConstants::PERMISSION_TAG_VERSION_11);
}

int32_t UsbManagerProxy::AddAllowedUsbDevices(const AppExecFwk::ElementName &admin,
    std::vector<UsbDeviceId> usbDeviceIds)
{
    EDMLOGD("UsbManagerProxy::AddAllowedUsbDevices");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::ALLOWED_USB_DEVICES);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(usbDeviceIds.size());
    std::for_each(usbDeviceIds.begin(), usbDeviceIds.end(), [&](const auto usbDeviceId) {
        usbDeviceId.Marshalling(data);
    });
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t UsbManagerProxy::RemoveAllowedUsbDevices(const AppExecFwk::ElementName &admin,
    std::vector<UsbDeviceId> usbDeviceIds)
{
    EDMLOGD("UsbManagerProxy::RemoveAllowedUsbDevices");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::ALLOWED_USB_DEVICES);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(usbDeviceIds.size());
    std::for_each(usbDeviceIds.begin(), usbDeviceIds.end(), [&](const auto usbDeviceId) {
        usbDeviceId.Marshalling(data);
    });
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t UsbManagerProxy::GetAllowedUsbDevices(const AppExecFwk::ElementName &admin, std::vector<UsbDeviceId> &result)
{
    EDMLOGD("UsbManagerProxy::GetAllowedUsbDevices");
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
    proxy->GetPolicy(EdmInterfaceCode::ALLOWED_USB_DEVICES, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("UsbManagerProxy:GetAllowedUsbDevices fail. %{public}d", ret);
        return ret;
    }
    int32_t size = reply.ReadInt32();
    if (size > EdmConstants::ALLOWED_USB_DEVICES_MAX_SIZE) {
        EDMLOGE("UsbManagerProxy:GetAllowedUsbDevices size=[%{public}d] is too large", size);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    EDMLOGI("UsbManagerProxy:GetAllowedUsbDevices return size:%{public}d", size);
    for (int i = 0; i < size; i++) {
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
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
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
} // namespace EDM
} // namespace OHOS
