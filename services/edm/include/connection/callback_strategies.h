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

#ifndef SERVICES_EDM_INCLUDE_CONNECTION_CALLBACK_STRATEGIES_H
#define SERVICES_EDM_INCLUDE_CONNECTION_CALLBACK_STRATEGIES_H

#include "icallback_strategy.h"
#include "ienterprise_admin.h"
#include "policy_struct.h"

namespace OHOS {
namespace EDM {

class StartStrategy : public ICallbackStrategy {
private:
    void ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy) override {}
};

class AdminStrategy : public ICallbackStrategy {
public:
    explicit AdminStrategy(uint32_t code) : ICallbackStrategy(code) {}

private:
    void ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy) override;
};

class DeviceAdminStrategy : public ICallbackStrategy {
public:
    DeviceAdminStrategy(uint32_t code, const std::string& bundleName)
        : ICallbackStrategy(code), bundleName_(bundleName) {}

private:
    void ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy) override;
    std::string bundleName_;
};

class BundleStrategy : public ICallbackStrategy {
public:
    BundleStrategy(uint32_t code, const std::string& bundleName, int32_t accountId)
        : ICallbackStrategy(code), bundleName_(bundleName), accountId_(accountId) {}

private:
    void ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy) override;
    std::string bundleName_;
    int32_t accountId_;
};

class AppStrategy : public ICallbackStrategy {
public:
    AppStrategy(uint32_t code, const std::string& bundleName)
        : ICallbackStrategy(code), bundleName_(bundleName) {}

private:
    void ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy) override;
    std::string bundleName_;
};

class SystemUpdateStrategy : public ICallbackStrategy {
public:
    explicit SystemUpdateStrategy(const UpdateInfo& updateInfo)
        : ICallbackStrategy(IEnterpriseAdmin::COMMAND_ON_SYSTEM_UPDATE), updateInfo_(updateInfo) {}

private:
    void ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy) override;
    UpdateInfo updateInfo_;
};

class AccountStrategy : public ICallbackStrategy {
public:
    AccountStrategy(uint32_t code, int32_t accountId)
        : ICallbackStrategy(code), accountId_(accountId) {}

private:
    void ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy) override;
    int32_t accountId_;
};

class KioskModeStrategy : public ICallbackStrategy {
public:
    KioskModeStrategy(uint32_t code, const std::string& bundleName, int32_t accountId)
        : ICallbackStrategy(code), bundleName_(bundleName), accountId_(accountId) {}

private:
    void ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy) override;
    std::string bundleName_;
    int32_t accountId_;
};

class MarketAppsInstallStatusChangedStrategy : public ICallbackStrategy {
public:
    MarketAppsInstallStatusChangedStrategy(const std::string& bundleName, int32_t status)
        : ICallbackStrategy(IEnterpriseAdmin::COMMAND_ON_MARKET_INSTALL_STATUS_CHANGED),
          bundleName_(bundleName), status_(status) {}

private:
    void ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy) override;
    std::string bundleName_;
    int32_t status_;
};

class LogCollectedStrategy : public ICallbackStrategy {
public:
    explicit LogCollectedStrategy(bool isSuccess)
        : ICallbackStrategy(IEnterpriseAdmin::COMMAND_ON_LOG_COLLECTED), isSuccess_(isSuccess) {}

private:
    void ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy) override;
    bool isSuccess_;
};

class KeyEventStrategy : public ICallbackStrategy {
public:
    explicit KeyEventStrategy(const std::string& keyEvent)
        : ICallbackStrategy(IEnterpriseAdmin::COMMAND_ON_KEY_EVENT), keyEvent_(keyEvent) {}

private:
    void ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy) override;
    std::string keyEvent_;
};

class StartupGuideCompletedStrategy : public ICallbackStrategy {
public:
    explicit StartupGuideCompletedStrategy(int32_t type)
        : ICallbackStrategy(IEnterpriseAdmin::COMMAND_ON_STARTUP_GUIDE_COMPLETED), type_(type) {}

private:
    void ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy) override;
    int32_t type_;
};

class DeviceBootCompletedStrategy : public ICallbackStrategy {
public:
    DeviceBootCompletedStrategy()
        : ICallbackStrategy(IEnterpriseAdmin::COMMAND_ON_DEVICE_BOOT_COMPLETED) {}

private:
    void ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy) override;
};

class AdminPolicyChangedStrategy : public ICallbackStrategy {
public:
    explicit AdminPolicyChangedStrategy(const PolicyChangedEvent& event)
        : ICallbackStrategy(IEnterpriseAdmin::COMMAND_ON_POLICIES_CHANGED), event_(event) {}

private:
    void ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy) override;
    PolicyChangedEvent event_;
};

} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_CONNECTION_CALLBACK_STRATEGIES_H