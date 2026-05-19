/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "enterprise_admin_proxy.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
// LCOV_EXCL_START
bool EnterpriseAdminProxy::SendRequest(uint32_t code, MessageParcel &data)
{
    EDMLOGI("EnterpriseAdminProxy::SendRequest %{public}u", code);
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = Remote()->SendRequest(code, data, reply, option);
    if (result != ERR_NONE) {
        EDMLOGE("EnterpriseAdminProxy::SendRequest failed, code=%{public}u, result=%{public}d", code, result);
        return false;
    }
    return true;
}

bool EnterpriseAdminProxy::OnAdmin(uint32_t code)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::OnAdmin write descriptor failed!");
        return false;
    }
    return SendRequest(code, data);
}

bool EnterpriseAdminProxy::OnDeviceBootCompleted()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::OnDeviceBootCompleted write descriptor failed!");
        return false;
    }
    return SendRequest(COMMAND_ON_DEVICE_BOOT_COMPLETED, data);
}

bool EnterpriseAdminProxy::OnDeviceAdmin(uint32_t code, const std::string &bundleName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::OnDeviceAdmin write descriptor failed!");
        return false;
    }
    data.WriteString(bundleName);
    return SendRequest(code, data);
}

bool EnterpriseAdminProxy::OnApp(uint32_t code, const std::string &bundleName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::OnApp write descriptor failed!");
        return false;
    }
    data.WriteString(bundleName);
    return SendRequest(code, data);
}

bool EnterpriseAdminProxy::OnKeyEvent(const std::string &keyEvent)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::OnKeyEvent write descriptor failed!");
        return false;
    }
    data.WriteString(keyEvent);
    return SendRequest(COMMAND_ON_KEY_EVENT, data);
}

bool EnterpriseAdminProxy::OnBundle(uint32_t code, const std::string &bundleName, int32_t accountId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::OnBundle write descriptor failed!");
        return false;
    }
    data.WriteString(bundleName);
    data.WriteInt32(accountId);
    return SendRequest(code, data);
}

bool EnterpriseAdminProxy::OnKioskMode(uint32_t code, const std::string &bundleName, int32_t accountId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::OnKioskMode write descriptor failed!");
        return false;
    }
    data.WriteString(bundleName);
    data.WriteInt32(accountId);
    return SendRequest(code, data);
}

bool EnterpriseAdminProxy::OnMarketAppsInstallStatusChanged(const std::string &bundleName, int32_t status)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::OnMarketAppsInstallStatusChanged write descriptor failed!");
        return false;
    }
    data.WriteString(bundleName);
    data.WriteInt32(status);
    return SendRequest(COMMAND_ON_MARKET_INSTALL_STATUS_CHANGED, data);
}

bool EnterpriseAdminProxy::OnAccount(uint32_t code, const int32_t accountId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::OnAccount write descriptor failed!");
        return false;
    }
    data.WriteInt32(accountId);
    return SendRequest(code, data);
}

bool EnterpriseAdminProxy::OnStartupGuideCompleted(int32_t type)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::OnStartupGuideCompleted write descriptor failed!");
        return false;
    }
    data.WriteInt32(type);
    return SendRequest(COMMAND_ON_STARTUP_GUIDE_COMPLETED, data);
}

bool EnterpriseAdminProxy::OnLogCollected(bool isSuccess)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::OnLogCollected write descriptor failed!");
        return false;
    }
    data.WriteBool(isSuccess);
    return SendRequest(COMMAND_ON_LOG_COLLECTED, data);
}

bool EnterpriseAdminProxy::OnSystemUpdate(const UpdateInfo &updateInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::OnSystemUpdate write descriptor failed!");
        return false;
    }
    data.WriteString(updateInfo.version);
    data.WriteInt64(updateInfo.firstReceivedTime);
    data.WriteString(updateInfo.packageType);
    return SendRequest(COMMAND_ON_SYSTEM_UPDATE, data);
}

bool EnterpriseAdminProxy::OnAdminPolicyChanged(const PolicyChangedEvent &policyChangedEvent)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::OnAdminPolicyChanged write descriptor failed!");
        return false;
    }
    policyChangedEvent.Marshalling(data);
    return SendRequest(COMMAND_ON_POLICIES_CHANGED, data);
}

bool EnterpriseAdminProxy::IsValid()
{
    sptr<IRemoteObject> remoteObject = AsObject();
    if (remoteObject == nullptr) { // LCOV_EXCL_BR_LINE
        EDMLOGE("EnterpriseAdminProxy::IsValid remote object is nullptr");
        return false;
    }
    if (remoteObject->IsObjectDead()) { // LCOV_EXCL_BR_LINE
        EDMLOGW("EnterpriseAdminProxy::IsValid remote object is dead");
        return false;
    }
    return true;
}
// LCOV_EXCL_STOP
} // namespace EDM
} // namespace OHOS