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

#ifndef FRAMEWORK_EXTENSION_INCLUDE_JS_ENTERPRISE_ADMIN_EXTENSION_CONTEXT_H
#define FRAMEWORK_EXTENSION_INCLUDE_JS_ENTERPRISE_ADMIN_EXTENSION_CONTEXT_H

#include <memory>

#include "enterprise_admin_extension_context.h"
#include "napi/native_api.h"
#include "napi_edm_common.h"
#include "napi_edm_error.h"
#include "js_runtime_utils.h"
#include "want.h"

namespace OHOS {
namespace EDM {
struct AsyncStartAbilityCallbackInfo : AsyncCallbackInfo {
    AppExecFwk::ElementName admin;
    AAFwk::Want want;
    std::weak_ptr<EnterpriseAdminExtensionContext> context;
};

class JsEnterpriseAdminExtensionContext final {
public:
    explicit JsEnterpriseAdminExtensionContext(const std::shared_ptr<EnterpriseAdminExtensionContext>& context)
        : context_(context) {}
    ~JsEnterpriseAdminExtensionContext() = default;

    static void Finalizer(napi_env env, void* data, void* hint);
    static napi_value StartAbilityByAdmin(napi_env env, napi_callback_info info);
private:
    static void NativeStartAbilityByAdmin(napi_env env, void* data);
    napi_value OnStartAbilityByAdmin(napi_env env, AbilityRuntime::NapiCallbackInfo& info);
    std::weak_ptr<EnterpriseAdminExtensionContext> context_;
};

napi_value CreateJsEnterpriseAdminExtensionContext(napi_env env,
    std::shared_ptr<EnterpriseAdminExtensionContext> context);
} // namespace EDM
} // namespace OHOS
#endif // FRAMEWORK_EXTENSION_INCLUDE_JS_ENTERPRISE_ADMIN_EXTENSION_CONTEXT_H