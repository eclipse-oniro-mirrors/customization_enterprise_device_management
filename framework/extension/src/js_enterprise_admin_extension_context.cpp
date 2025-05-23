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

#include "js_enterprise_admin_extension_context.h"

#include "js_extension_context.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"

namespace OHOS {
namespace EDM {
namespace {
class JsEnterpriseAdminExtensionContext final {
public:
    explicit JsEnterpriseAdminExtensionContext(const std::shared_ptr<EnterpriseAdminExtensionContext>& context)
        : context_(context) {}
    ~JsEnterpriseAdminExtensionContext() = default;

    static void Finalizer(napi_env env, void* data, void* hint)
    {
        std::unique_ptr<JsEnterpriseAdminExtensionContext>(
            static_cast<JsEnterpriseAdminExtensionContext*>(data));
    }
private:
    std::weak_ptr<EnterpriseAdminExtensionContext> context_;
};
} // namespace

napi_value CreateJsEnterpriseAdminExtensionContext(napi_env env,
    std::shared_ptr<EnterpriseAdminExtensionContext> context)
{
    napi_value objValue = AbilityRuntime::CreateJsExtensionContext(env, context);

    std::unique_ptr<JsEnterpriseAdminExtensionContext> jsContext =
        std::make_unique<JsEnterpriseAdminExtensionContext>(context);
    napi_wrap(env, objValue, jsContext.release(), JsEnterpriseAdminExtensionContext::Finalizer, nullptr, nullptr);
    return objValue;
}
} // namespace EDM
} // namespace OHOS
