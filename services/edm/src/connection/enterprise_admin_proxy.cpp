/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
void EnterpriseAdminProxy::OnAdminEnabled()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    EDMLOGI("EnterpriseAdminProxy proxy OnAdminEnabled");
    SendRequest(COMMAND_ON_ADMIN_ENABLED, data);
}

void EnterpriseAdminProxy::OnAdminDisabled()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    EDMLOGI("EnterpriseAdminProxy proxy OnAdminDisabled");
    SendRequest(COMMAND_ON_ADMIN_DISABLED, data);
}

void EnterpriseAdminProxy::OnDeviceAdminEnabled(const std::string &bundleName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    data.WriteString(bundleName);
    EDMLOGI("EnterpriseAdminProxy proxy OnDeviceAdminEnabled");
    SendRequest(COMMAND_ON_DEVICE_ADMIN_ENABLED, data);
}

void EnterpriseAdminProxy::OnDeviceAdminDisabled(const std::string &bundleName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    data.WriteString(bundleName);
    EDMLOGI("EnterpriseAdminProxy proxy OnDeviceAdminDisabled");
    SendRequest(COMMAND_ON_DEVICE_ADMIN_DISABLED, data);
}

void EnterpriseAdminProxy::OnBundleAdded(const std::string &bundleName, int32_t accountId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    data.WriteString(bundleName);
    data.WriteInt32(accountId);
    EDMLOGI("EnterpriseAdminProxy proxy OnBundleAdded");
    SendRequest(COMMAND_ON_BUNDLE_ADDED, data);
}

void EnterpriseAdminProxy::OnBundleRemoved(const std::string &bundleName, int32_t accountId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    data.WriteString(bundleName);
    data.WriteInt32(accountId);
    EDMLOGI("EnterpriseAdminProxy proxy OnBundleRemoved");
    SendRequest(COMMAND_ON_BUNDLE_REMOVED, data);
}

void EnterpriseAdminProxy::OnAppStart(const std::string &bundleName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    data.WriteString(bundleName);
    EDMLOGI("EnterpriseAdminProxy proxy OnAppStart");
    SendRequest(COMMAND_ON_APP_START, data);
}

void EnterpriseAdminProxy::OnAppStop(const std::string &bundleName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    data.WriteString(bundleName);
    EDMLOGI("EnterpriseAdminProxy proxy OnAppStop");
    SendRequest(COMMAND_ON_APP_STOP, data);
}

void EnterpriseAdminProxy::OnSystemUpdate(const UpdateInfo &updateInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    data.WriteString(updateInfo.version);
    data.WriteInt64(updateInfo.firstReceivedTime);
    data.WriteString(updateInfo.packageType);
    EDMLOGI("EnterpriseAdminProxy proxy OnSystemUpdate");
    SendRequest(COMMAND_ON_SYSTEM_UPDATE, data);
}

void EnterpriseAdminProxy::OnAccountAdded(const int32_t accountId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    data.WriteInt32(accountId);
    EDMLOGI("EnterpriseAdminProxy proxy OnAccountAdded");
    SendRequest(COMMAND_ON_ACCOUNT_ADDED, data);
}

void EnterpriseAdminProxy::OnAccountSwitched(const int32_t accountId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    data.WriteInt32(accountId);
    EDMLOGI("EnterpriseAdminProxy proxy OnAccountSwitched");
    SendRequest(COMMAND_ON_ACCOUNT_SWITCHED, data);
}

void EnterpriseAdminProxy::OnAccountRemoved(const int32_t accountId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    data.WriteInt32(accountId);
    EDMLOGI("EnterpriseAdminProxy proxy OnAccountRemoved");
    SendRequest(COMMAND_ON_ACCOUNT_REMOVED, data);
}

void EnterpriseAdminProxy::OnKioskModeEntering(const std::string &bundleName, int32_t accountId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    data.WriteString(bundleName);
    data.WriteInt32(accountId);
    EDMLOGI("EnterpriseAdminProxy proxy OnKioskModeEntering");
    SendRequest(COMMAND_ON_KIOSK_MODE_ENTERING, data);
}

void EnterpriseAdminProxy::OnKioskModeExiting(const std::string &bundleName, int32_t accountId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    data.WriteString(bundleName);
    data.WriteInt32(accountId);
    EDMLOGI("EnterpriseAdminProxy proxy OnKioskModeExiting");
    SendRequest(COMMAND_ON_KIOSK_MODE_EXITING, data);
}

void EnterpriseAdminProxy::OnMarketAppsInstallStatusChanged(const std::string &bundleName, int32_t status)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    data.WriteString(bundleName);
    data.WriteInt32(status);
    EDMLOGI("EnterpriseAdminProxy proxy OnMarketAppsInstallStatusChanged");
    SendRequest(COMMAND_ON_MARKET_INSTALL_STATUS_CHANGED, data);
}

void EnterpriseAdminProxy::OnLogCollected(bool isSuccess)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    data.WriteBool(isSuccess);
    EDMLOGI("EnterpriseAdminProxy proxy OnLogCollected");
    SendRequest(COMMAND_ON_LOG_COLLECTED, data);
}

void EnterpriseAdminProxy::OnKeyEvent(const std::string &keyEvent)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    data.WriteString(keyEvent);
    EDMLOGI("EnterpriseAdminProxy proxy OnMarketAppsInstallStatusChanged");
    SendRequest(COMMAND_ON_KEY_EVENT, data);
}

void EnterpriseAdminProxy::SendRequest(uint32_t code, MessageParcel &data)
{
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    Remote()->SendRequest(code, data, reply, option);
}
} // namespace EDM
} // namespace OHOS
