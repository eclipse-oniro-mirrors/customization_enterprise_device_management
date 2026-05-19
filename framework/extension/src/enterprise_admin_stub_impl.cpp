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

#include "enterprise_admin_stub_impl.h"

namespace OHOS {
namespace EDM {
bool EnterpriseAdminStubImpl::OnAdmin(uint32_t code)
{
    auto extension = extension_.lock();
    if (extension == nullptr) {
        return false;
    }
    extension->OnAdmin(code);
    return true;
}

bool EnterpriseAdminStubImpl::OnDeviceAdmin(uint32_t code, const std::string &bundleName)
{
    auto extension = extension_.lock();
    if (extension == nullptr) {
        return false;
    }
    extension->OnDeviceAdmin(code, bundleName);
    return true;
}


bool EnterpriseAdminStubImpl::OnBundle(uint32_t code, const std::string &bundleName, int32_t accountId)
{
    auto extension = extension_.lock();
    if (extension == nullptr) {
        return false;
    }
    extension->OnBundle(code, bundleName, accountId);
    return true;
}

bool EnterpriseAdminStubImpl::OnApp(uint32_t code, const std::string &bundleName)
{
    auto extension = extension_.lock();
    if (extension == nullptr) {
        return false;
    }
    extension->OnApp(code, bundleName);
    return true;
}

bool EnterpriseAdminStubImpl::OnSystemUpdate(const UpdateInfo &updateInfo)
{
    auto extension = extension_.lock();
    if (extension == nullptr) {
        return false;
    }
    extension->OnSystemUpdate(updateInfo);
    return true;
}

bool EnterpriseAdminStubImpl::OnAccount(uint32_t code, const int32_t accountId)
{
    auto extension = extension_.lock();
    if (extension == nullptr) {
        return false;
    }
    extension->OnAccount(code, accountId);
    return true;
}

bool EnterpriseAdminStubImpl::OnKioskMode(uint32_t code, const std::string &bundleName, int32_t accountId)
{
    auto extension = extension_.lock();
    if (extension == nullptr) {
        return false;
    }
    extension->OnKioskMode(code, bundleName, accountId);
    return true;
}

bool EnterpriseAdminStubImpl::OnMarketAppsInstallStatusChanged(const std::string &bundleName, int32_t status)
{
    auto extension = extension_.lock();
    if (extension == nullptr) {
        return false;
    }
    extension->OnMarketAppsInstallStatusChanged(bundleName, status);
    return true;
}

bool EnterpriseAdminStubImpl::OnLogCollected(bool isSuccess)
{
    auto extension = extension_.lock();
    if (extension == nullptr) {
        return false;
    }
    extension->OnLogCollected(isSuccess);
    return true;
}

bool EnterpriseAdminStubImpl::OnKeyEvent(const std::string &event)
{
    auto extension = extension_.lock();
    if (extension == nullptr) {
        return false;
    }
    extension->OnKeyEvent(event);
    return true;
}

bool EnterpriseAdminStubImpl::OnStartupGuideCompleted(int32_t type)
{
    auto extension = extension_.lock();
    if (extension == nullptr) {
        return false;
    }
    extension->OnStartupGuideCompleted(type);
    return true;
}

bool EnterpriseAdminStubImpl::OnDeviceBootCompleted()
{
    auto extension = extension_.lock();
    if (extension == nullptr) {
        return false;
    }
    extension->OnDeviceBootCompleted();
    return true;
}

bool EnterpriseAdminStubImpl::OnAdminPolicyChanged(const PolicyChangedEvent &policyChangedEvent)
{
    auto extension = extension_.lock();
    if (extension == nullptr) {
        return false;
    }
    extension->OnAdminPolicyChanged(policyChangedEvent);
    return true;
}
} // namespace EDM
} // namespace OHOS