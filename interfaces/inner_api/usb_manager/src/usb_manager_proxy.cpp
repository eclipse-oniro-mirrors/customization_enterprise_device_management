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
constexpr int32_t DISABLED = 2;

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
    bool isGlobalDisabled;
    std::unordered_map<int32_t, bool> typeMap;
    std::vector<UsbDeviceId> trustList;
    GetUsbPolicy(admin, isGlobalDisabled, typeMap, trustList);
    if (isGlobalDisabled || !trustList.empty()) {
        EDMLOGE("UsbManagerProxy: policy conflicted. isGlobalDisabled: %{public}d, hasTrustList: %{public}d",
            isGlobalDisabled, !trustList.empty());
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }

    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USB_READ_ONLY);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteInt32(readOnly ? 1 : 0);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t UsbManagerProxy::DisableUsb(const AppExecFwk::ElementName &admin, bool disable)
{
    EDMLOGD("UsbManagerProxy::DisableUsb");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    bool isGlobalDisabled;
    std::unordered_map<int32_t, bool> typeMap;
    std::vector<UsbDeviceId> trustList;
    GetUsbPolicy(admin, isGlobalDisabled, typeMap, trustList);
    bool isTypeDisabled = false;
    for (std::pair<int32_t, bool> item : typeMap) {
        if (item.second) {
            isTypeDisabled = true;
            break;
        }
    }
    if (isTypeDisabled || !trustList.empty()) {
        EDMLOGE("UsbManagerProxy: policy conflicted. isTypeDisabled: %{public}d, hasTrustList: %{public}d",
            isTypeDisabled, !trustList.empty());
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    return proxy->SetPolicyDisabled(admin, disable, EdmInterfaceCode::DISABLE_USB);
}

int32_t UsbManagerProxy::IsUsbDisabled(const AppExecFwk::ElementName *admin, bool &result)
{
    EDMLOGD("UsbManagerProxy::IsUsbDisabled");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return proxy->IsPolicyDisabled(admin, EdmInterfaceCode::DISABLE_USB, result);
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

    bool isGlobalDisabled;
    std::unordered_map<int32_t, bool> typeMap;
    std::vector<UsbDeviceId> trustList;
    GetUsbPolicy(admin, isGlobalDisabled, typeMap, trustList);
    bool isTypeDisabled = false;
    for (std::pair<int32_t, bool> item : typeMap) {
        if (item.second) {
            isTypeDisabled = true;
            break;
        }
    }
    if (isGlobalDisabled || isTypeDisabled) {
        EDMLOGE("UsbManagerProxy: policy conflicted. isGlobalDisabled: %{public}d, isTypeDisabled: %{public}d",
            isGlobalDisabled, isTypeDisabled);
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }

    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::ALLOWED_USB_DEVICES);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
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
    data.WriteInt32(usbDeviceIds.size());
    std::for_each(usbDeviceIds.begin(), usbDeviceIds.end(), [&](const auto usbDeviceId) {
        usbDeviceId.Marshalling(data);
    });
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t UsbManagerProxy::GetAllowedUsbDevices(const AppExecFwk::ElementName &admin, std::vector<UsbDeviceId> &result,
    bool hasAdmin)
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
    if (hasAdmin) {
        data.WriteInt32(HAS_ADMIN);
        data.WriteParcelable(&admin);
    } else {
        data.WriteInt32(WITHOUT_ADMIN);
    }
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

    bool isGlobalDisabled;
    std::unordered_map<int32_t, bool> typeMap;
    std::vector<UsbDeviceId> trustList;
    GetUsbPolicy(admin, isGlobalDisabled, typeMap, trustList);
    if (usbPolicy == DISABLED && (isGlobalDisabled || !trustList.empty())) {
        EDMLOGE("UsbManagerProxy: policy conflicted. isGlobalDisabled: %{public}d, hasTrustList: %{public}d",
            isGlobalDisabled, !trustList.empty());
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }

    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USB_READ_ONLY);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteInt32(usbPolicy);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t UsbManagerProxy::GetUsbStorageDeviceAccessPolicy(const AppExecFwk::ElementName &admin, int32_t &result,
    bool hasAdmin)
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
    if (hasAdmin) {
        data.WriteInt32(HAS_ADMIN);
        data.WriteParcelable(&admin);
    } else {
        data.WriteInt32(WITHOUT_ADMIN);
    }
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

int32_t UsbManagerProxy::GetUsbPolicy(const AppExecFwk::ElementName &admin, bool &isGlobalDisabled,
    std::unordered_map<int32_t, bool> &typeDisableMap, std::vector<UsbDeviceId> &trustUsbDeviceIds)
{
    std::vector<UsbDeviceId> usbDeviceIds;
    int32_t ret = GetAllowedUsbDevices(admin, usbDeviceIds, false);
    if (ret != ERR_OK) {
        return ret;
    }
    if (!usbDeviceIds.empty()) {
        trustUsbDeviceIds = usbDeviceIds;
        return ERR_OK;
    }

    ret = IsUsbDisabled(&admin, isGlobalDisabled);
    if (isGlobalDisabled) {
        return ERR_OK;
    }

    int32_t isStorageDeviceDisabled;
    ret = GetUsbStorageDeviceAccessPolicy(admin, isStorageDeviceDisabled, false);
    if (ret != ERR_OK) {
        return ret;
    }
    if (isStorageDeviceDisabled == DISABLED) {
        typeDisableMap.insert(std::make_pair(0, true));
        return ERR_OK;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
