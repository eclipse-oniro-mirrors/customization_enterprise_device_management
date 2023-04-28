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

#ifndef FRAMEWORK_EXTENSION_INCLUDE_JS_ENTERPRISE_ADMIN_EXTENSION_H
#define FRAMEWORK_EXTENSION_INCLUDE_JS_ENTERPRISE_ADMIN_EXTENSION_H

#include <string>

#include "enterprise_admin_extension.h"
#include "js_runtime.h"

namespace OHOS {
namespace EDM {
/**
 * @brief js-level enterprise admin extension.
 */
class JsEnterpriseAdminExtension : public EnterpriseAdminExtension {
public:
    JsEnterpriseAdminExtension(AbilityRuntime::JsRuntime& jsRuntime);
    
    ~JsEnterpriseAdminExtension() override;

    /**
     * @brief Create JsEnterpriseAdminExtension.
     *
     * @param runtime The runtime.
     * @return The JsEnterpriseAdminExtension instance.
     */
    static JsEnterpriseAdminExtension* Create(const std::unique_ptr<AbilityRuntime::Runtime>& runtime);

    void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord>& record,
              const std::shared_ptr<AppExecFwk::OHOSApplication>& application,
              std::shared_ptr<AppExecFwk::AbilityHandler>& handler,
              const sptr<IRemoteObject>& token) override;

    void OnStart(const AAFwk::Want& want) override;

    sptr<IRemoteObject> OnConnect(const AAFwk::Want& want) override;

    void OnDisconnect(const AAFwk::Want& want) override;

    void OnStop() override;

    void OnAdminEnabled();

    void OnAdminDisabled();

    void OnBundleAdded(const std::string &bundleName);

    void OnBundleRemoved(const std::string &bundleName);
private:
    NativeValue* CallObjectMethod(const char* name, NativeValue** argv, size_t argc);

    void GetSrcPath(std::string& srcPath);

    AbilityRuntime::JsRuntime& jsRuntime_;

    std::unique_ptr<NativeReference> jsObj_{nullptr};
};
}  // namespace EDM
}  // namespace OHOS
#endif  // FRAMEWORK_EXTENSION_INCLUDE_JS_ENTERPRISE_ADMIN_EXTENSION_H