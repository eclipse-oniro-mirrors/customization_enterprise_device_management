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
#include "edm_log.h"

namespace OHOS {
namespace EDM {
void EnterpriseAdminStubImpl::OnAdminEnabled()
{
    EDMLOGI("EnterpriseAdminStubImpl %{public}s begin.", __func__);
    auto extension = extension_.lock();
    if (extension != nullptr) {
        extension->OnAdminEnabled();
        EDMLOGD("EnterpriseAdminStubImpl %{public}s end successfully.", __func__);
    }
}

void EnterpriseAdminStubImpl::OnAdminDisabled()
{
    EDMLOGI("EnterpriseAdminStubImpl %{public}s begin.", __func__);
    auto extension = extension_.lock();
    if (extension != nullptr) {
        extension->OnAdminDisabled();
        EDMLOGD("EnterpriseAdminStubImpl %{public}s end successfully.", __func__);
    }
}

void EnterpriseAdminStubImpl::OnBundleAdded(const std::string &bundleName, int32_t accountId)
{
    EDMLOGI("EnterpriseAdminStubImpl %{public}s begin.", __func__);
    auto extension = extension_.lock();
    if (extension != nullptr) {
        extension->OnBundleAdded(bundleName, accountId);
        EDMLOGD("EnterpriseAdminStubImpl %{public}s end successfully.", __func__);
    }
}

void EnterpriseAdminStubImpl::OnBundleRemoved(const std::string &bundleName, int32_t accountId)
{
    EDMLOGI("EnterpriseAdminStubImpl %{public}s begin.", __func__);
    auto extension = extension_.lock();
    if (extension != nullptr) {
        extension->OnBundleRemoved(bundleName, accountId);
        EDMLOGD("EnterpriseAdminStubImpl %{public}s end successfully.", __func__);
    }
}

void EnterpriseAdminStubImpl::OnAppStart(const std::string &bundleName)
{
    EDMLOGI("EnterpriseAdminStubImpl %{public}s begin.", __func__);
    auto extension = extension_.lock();
    if (extension != nullptr) {
        extension->OnAppStart(bundleName);
        EDMLOGD("EnterpriseAdminStubImpl %{public}s end successfully.", __func__);
    }
}

void EnterpriseAdminStubImpl::OnAppStop(const std::string &bundleName)
{
    EDMLOGI("EnterpriseAdminStubImpl %{public}s begin.", __func__);
    auto extension = extension_.lock();
    if (extension != nullptr) {
        extension->OnAppStop(bundleName);
        EDMLOGD("EnterpriseAdminStubImpl %{public}s end successfully.", __func__);
    }
}

void EnterpriseAdminStubImpl::OnSystemUpdate(const UpdateInfo &updateInfo)
{
    EDMLOGI("EnterpriseAdminStubImpl %{public}s begin.", __func__);
    auto extension = extension_.lock();
    if (extension != nullptr) {
        extension->OnSystemUpdate(updateInfo);
        EDMLOGD("EnterpriseAdminStubImpl %{public}s end successfully.", __func__);
    }
}

void EnterpriseAdminStubImpl::OnAccountAdded(const int32_t accountId)
{
    EDMLOGI("EnterpriseAdminStubImpl %{public}s begin.", __func__);
    auto extension = extension_.lock();
    if (extension != nullptr) {
        extension->OnAccountAdded(accountId);
        EDMLOGD("EnterpriseAdminStubImpl %{public}s end successfully.", __func__);
    }
}

void EnterpriseAdminStubImpl::OnAccountSwitched(const int32_t accountId)
{
    EDMLOGI("EnterpriseAdminStubImpl %{public}s begin.", __func__);
    auto extension = extension_.lock();
    if (extension != nullptr) {
        extension->OnAccountSwitched(accountId);
        EDMLOGD("EnterpriseAdminStubImpl %{public}s end successfully.", __func__);
    }
}

void EnterpriseAdminStubImpl::OnAccountRemoved(const int32_t accountId)
{
    EDMLOGI("EnterpriseAdminStubImpl %{public}s begin.", __func__);
    auto extension = extension_.lock();
    if (extension != nullptr) {
        extension->OnAccountRemoved(accountId);
        EDMLOGD("EnterpriseAdminStubImpl %{public}s end successfully.", __func__);
    }
}

void EnterpriseAdminStubImpl::OnKioskModeEntering(const std::string &bundleName, int32_t accountId)
{
    EDMLOGI("EnterpriseAdminStubImpl %{public}s begin.", __func__);
    auto extension = extension_.lock();
    if (extension != nullptr) {
        extension->OnKioskModeEntering(bundleName, accountId);
        EDMLOGD("EnterpriseAdminStubImpl %{public}s end successfully.", __func__);
    }
}

void EnterpriseAdminStubImpl::OnKioskModeExiting(const std::string &bundleName, int32_t accountId)
{
    EDMLOGI("EnterpriseAdminStubImpl %{public}s begin.", __func__);
    auto extension = extension_.lock();
    if (extension != nullptr) {
        extension->OnKioskModeExiting(bundleName, accountId);
        EDMLOGD("EnterpriseAdminStubImpl %{public}s end successfully.", __func__);
    }
}
} // namespace EDM
} // namespace OHOS