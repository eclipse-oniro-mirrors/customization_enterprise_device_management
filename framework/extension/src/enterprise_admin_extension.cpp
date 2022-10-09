/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "enterprise_admin_extension.h"

#include "ability_loader.h"
#include "enterprise_admin_extension_context.h"
#include "hilog_wrapper.h"
#include "js_enterprise_admin_extension.h"
#include "runtime.h"

namespace OHOS {
namespace EDM {
using namespace OHOS::AppExecFwk;
EnterpriseAdminExtension* EnterpriseAdminExtension::Create(const std::unique_ptr<AbilityRuntime::Runtime>& runtime)
{
    if (!runtime) {
        return new EnterpriseAdminExtension();
    }
    HILOG_INFO("EnterpriseAdminExtension::Create runtime");
    switch (runtime->GetLanguage()) {
        case AbilityRuntime::Runtime::Language::JS:
            return JsEnterpriseAdminExtension::Create(runtime);
        default:
            return new EnterpriseAdminExtension();
    }
}

void EnterpriseAdminExtension::Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord>& record,
    const std::shared_ptr<AppExecFwk::OHOSApplication>& application,
    std::shared_ptr<AppExecFwk::AbilityHandler>& handler,
    const sptr<IRemoteObject>& token)
{
    HILOG_INFO("EnterpriseAdminExtension begin init");
    ExtensionBase<EnterpriseAdminExtensionContext>::Init(record, application, handler, token);
}

std::shared_ptr<EnterpriseAdminExtensionContext> EnterpriseAdminExtension::CreateAndInitContext(
    const std::shared_ptr<AppExecFwk::AbilityLocalRecord>& record,
    const std::shared_ptr<AppExecFwk::OHOSApplication>& application,
    std::shared_ptr<AppExecFwk::AbilityHandler>& handler,
    const sptr<IRemoteObject>& token)
{
    std::shared_ptr<EnterpriseAdminExtensionContext> context =
        ExtensionBase<EnterpriseAdminExtensionContext>::CreateAndInitContext(record, application, handler, token);
    if (record == nullptr) {
        HILOG_ERROR("EnterpriseAdminExtension::CreateAndInitContext record is nullptr");
        return context;
    }
    return context;
}
} // namespace EDM
} // namespace OHOS