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

#include "callback_strategies.h"

namespace OHOS {
namespace EDM {
// Admin策略
void AdminStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    proxy->OnAdmin(code_);
}

// Device Admin策略
void DeviceAdminStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    proxy->OnDeviceAdmin(code_, bundleName_);
}

// Bundle策略
void BundleStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    proxy->OnBundle(code_, bundleName_, accountId_);
}

// App策略
void AppStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    proxy->OnApp(code_, bundleName_);
}

// System Update策略
void SystemUpdateStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    proxy->OnSystemUpdate(updateInfo_);
}

// Account策略
void AccountStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    proxy->OnAccount(code_, accountId_);
}

// Kiosk策略
void KioskModeStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    proxy->OnKioskMode(code_, bundleName_, accountId_);
}

// Market策略
void MarketAppsInstallStatusChangedStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    proxy->OnMarketAppsInstallStatusChanged(bundleName_, status_);
}

// Log策略
void LogCollectedStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    proxy->OnLogCollected(isSuccess_);
}

// KeyEvent策略
void KeyEventStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    proxy->OnKeyEvent(keyEvent_);
}

// OOBE策略
void StartupGuideCompletedStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    proxy->OnStartupGuideCompleted(type_);
}

void DeviceBootCompletedStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    proxy->OnDeviceBootCompleted();
}

// Policy Changed策略
void AdminPolicyChangedStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    proxy->OnAdminPolicyChanged(event_);
}
} // namespace EDM
} // namespace OHOS