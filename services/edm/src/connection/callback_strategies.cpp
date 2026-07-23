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
bool AdminStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    return proxy->OnAdmin(code_);
}

// Device Admin策略
bool DeviceAdminStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    return proxy->OnDeviceAdmin(code_, bundleName_);
}

// Bundle策略
bool BundleStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    return proxy->OnBundle(code_, bundleName_, accountId_);
}

// App策略
bool AppStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    return proxy->OnApp(code_, bundleName_);
}

// System Update策略
bool SystemUpdateStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    return proxy->OnSystemUpdate(updateInfo_);
}

// Account策略
bool AccountStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    return proxy->OnAccount(code_, accountId_);
}

// Kiosk策略
bool KioskModeStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    return proxy->OnKioskMode(code_, bundleName_, accountId_);
}

// Market策略
bool MarketAppsInstallStatusChangedStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    return proxy->OnMarketAppsInstallStatusChanged(bundleName_, status_);
}

// Log策略
bool LogCollectedStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    return proxy->OnLogCollected(isSuccess_);
}

// KeyEvent策略
bool KeyEventStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    return proxy->OnKeyEvent(keyEvent_);
}

// OOBE策略
bool StartupGuideCompletedStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    return proxy->OnStartupGuideCompleted(type_);
}

bool DeviceBootCompletedStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    return proxy->OnDeviceBootCompleted();
}

// Policy Changed策略
bool AdminPolicyChangedStrategy::ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy)
{
    return proxy->OnAdminPolicyChanged(event_);
}
} // namespace EDM
} // namespace OHOS