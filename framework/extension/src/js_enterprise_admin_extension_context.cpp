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

#include "edm_constants.h"
#include "edm_log.h"
#include "hitrace_meter.h"
#include "js_extension_context.h"
#include "js_runtime.h"
#include "napi_common_want.h"

namespace OHOS {
namespace EDM {

using namespace OHOS::AbilityRuntime;

void JsEnterpriseAdminExtensionContext::Finalizer(napi_env env, void* data, void* hint)
{
    std::unique_ptr<JsEnterpriseAdminExtensionContext>(static_cast<JsEnterpriseAdminExtensionContext*>(data));
}

napi_value JsEnterpriseAdminExtensionContext::StartAbilityByAdmin(napi_env env, napi_callback_info info)
{
    GET_NAPI_INFO_AND_CALL(env, info, JsEnterpriseAdminExtensionContext, OnStartAbilityByAdmin);
}

napi_value JsEnterpriseAdminExtensionContext::OnStartAbilityByAdmin(napi_env env, NapiCallbackInfo& info)
{
    EDMLOGI("NAPI_StartAbilityByAdmin called");
    auto asyncCallbackInfo = new (std::nothrow) AsyncStartAbilityCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, info.argc >= ARGS_SIZE_TWO, "Parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->admin, info.argv[ARR_INDEX_ZERO]),
        "Parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, AppExecFwk::UnwrapWant(env, info.argv[ARR_INDEX_ONE], asyncCallbackInfo->want),
        "Parameter want error");
    EDMLOGD("StartAbilityByAdmin: want.bundleName %{public}s, want.abilityName:%{public}s",
        asyncCallbackInfo->want.GetBundle().c_str(), asyncCallbackInfo->want.GetElement().GetAbilityName().c_str());
    asyncCallbackInfo->context = context_;
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "StartAbilityByAdmin",
        NativeStartAbilityByAdmin, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void JsEnterpriseAdminExtensionContext::NativeStartAbilityByAdmin(napi_env env, void* data)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_DEVICE_MANAGER, __PRETTY_FUNCTION__, nullptr);
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncStartAbilityCallbackInfo *asyncCallbackInfo = static_cast<AsyncStartAbilityCallbackInfo *>(data);
    auto context = asyncCallbackInfo->context.lock();
    if (context == nullptr) {
        EDMLOGE("context is nullptr");
        return;
    }

    asyncCallbackInfo->ret = context->StartAbilityByAdmin(asyncCallbackInfo->admin, asyncCallbackInfo->want,
        asyncCallbackInfo->innerCodeMsg);
    if (asyncCallbackInfo->innerCodeMsg.empty()) {
        asyncCallbackInfo->innerCodeMsg = " ";
    }
    if (asyncCallbackInfo->ret != ERR_OK) {
        EDMLOGE("StartAbilityByAdmin fail ret: %{public}d", asyncCallbackInfo->ret);
    }
}

napi_value CreateJsEnterpriseAdminExtensionContext(napi_env env,
    std::shared_ptr<EnterpriseAdminExtensionContext> context)
{
    EDMLOGD("CreateJsEnterpriseAdminExtensionContext called");
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo = nullptr;
    if (context) {
        abilityInfo = context->GetAbilityInfo();
    }
    napi_value objValue = AbilityRuntime::CreateJsExtensionContext(env, context, abilityInfo);

    std::unique_ptr<JsEnterpriseAdminExtensionContext> jsContext =
        std::make_unique<JsEnterpriseAdminExtensionContext>(context);
    napi_wrap(env, objValue, jsContext.release(), JsEnterpriseAdminExtensionContext::Finalizer, nullptr, nullptr);

    const char *moduleName = "JsEnterpriseAdminExtensionContext";
    AbilityRuntime::BindNativeFunction(env, objValue, "startAbilityByAdmin", moduleName,
        JsEnterpriseAdminExtensionContext::StartAbilityByAdmin);
    return objValue;
}
} // namespace EDM
} // namespace OHOS
