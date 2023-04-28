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

#include "js_enterprise_admin_extension.h"

#include <string>

#include "ability_handler.h"
#include "enterprise_admin_extension.h"
#include "enterprise_admin_stub_impl.h"
#include "js_enterprise_admin_extension_context.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "runtime.h"

namespace OHOS {
namespace EDM {
constexpr size_t JS_NAPI_ARGC_ZERO = 0;
constexpr size_t JS_NAPI_ARGC_ONE = 1;

JsEnterpriseAdminExtension* JsEnterpriseAdminExtension::Create(const std::unique_ptr<AbilityRuntime::Runtime>& runtime)
{
    return new JsEnterpriseAdminExtension(static_cast<AbilityRuntime::JsRuntime&>(*runtime));
}

JsEnterpriseAdminExtension::JsEnterpriseAdminExtension(AbilityRuntime::JsRuntime& jsRuntime) : jsRuntime_(jsRuntime) {}
JsEnterpriseAdminExtension::~JsEnterpriseAdminExtension()
{
    HILOG_DEBUG("Js enterprise admin extension destructor.");
    jsRuntime_.FreeNativeReference(std::move(jsObj_));
}

void JsEnterpriseAdminExtension::Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord>& record,
    const std::shared_ptr<AppExecFwk::OHOSApplication>& application,
    std::shared_ptr<AppExecFwk::AbilityHandler>& handler,
    const sptr<IRemoteObject>& token)
{
    EnterpriseAdminExtension::Init(record, application, handler, token);
    std::string srcPath;
    GetSrcPath(srcPath);
    if (srcPath.empty()) {
        HILOG_INFO("JsEnterpriseAdminExtension Failed to get srcPath");
        return;
    }

    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    HILOG_INFO("JsEnterpriseAdminExtension::Init moduleName:%{public}s,srcPath:%{public}s.",
        moduleName.c_str(), srcPath.c_str());
    AbilityRuntime::HandleScope handleScope(jsRuntime_);
    auto& engine = jsRuntime_.GetNativeEngine();

    jsObj_ = jsRuntime_.LoadModule(moduleName, srcPath, abilityInfo_->hapPath);
    if (jsObj_ == nullptr) {
        HILOG_INFO("JsEnterpriseAdminExtension Failed to get jsObj_");
        return;
    }
    HILOG_INFO("JsEnterpriseAdminExtension::Init ConvertNativeValueTo.");
    NativeObject* obj = AbilityRuntime::ConvertNativeValueTo<NativeObject>(jsObj_->Get());
    if (obj == nullptr) {
        HILOG_INFO("JsEnterpriseAdminExtension Failed to get JsEnterpriseAdminExtension object");
        return;
    }

    auto context = GetContext();
    if (context == nullptr) {
        HILOG_INFO("JsEnterpriseAdminExtension Failed to get context");
        return;
    }
    HILOG_INFO("JsEnterpriseAdminExtension::Init CreateJsEnterpriseAdminExtensionContext.");
    NativeValue* contextObj = CreateJsEnterpriseAdminExtensionContext(engine, context);
    auto shellContextRef = jsRuntime_.LoadSystemModule("enterprise.EnterpriseAdminExtensionContext",
        &contextObj, JS_NAPI_ARGC_ONE);
    contextObj = shellContextRef->Get();
    HILOG_INFO("JsEnterpriseAdminExtension::Init Bind.");
    context->Bind(jsRuntime_, shellContextRef.release());
    HILOG_INFO("JsEnterpriseAdminExtension::SetProperty.");
    obj->SetProperty("context", contextObj);

    auto nativeObj = AbilityRuntime::ConvertNativeValueTo<NativeObject>(contextObj);
    if (nativeObj == nullptr) {
        HILOG_ERROR("Failed to get enterprise admin extension native object");
        return;
    }

    HILOG_INFO("Set enterprise admin extension context");

    nativeObj->SetNativePointer(new std::weak_ptr<AbilityRuntime::Context>(context),
        [](NativeEngine*, void* data, void*) {
            HILOG_INFO("Finalizer for weak_ptr service extension context is called");
            delete static_cast<std::weak_ptr<AbilityRuntime::Context>*>(data);
        }, nullptr);

    HILOG_INFO("JsEnterpriseAdminExtension::Init end.");
}

void JsEnterpriseAdminExtension::OnStart(const AAFwk::Want& want)
{
    HILOG_INFO("JsEnterpriseAdminExtension OnStart begin");
    AbilityRuntime::Extension::OnStart(want);
}

void JsEnterpriseAdminExtension::OnStop()
{
    AbilityRuntime::Extension::OnStop();
    HILOG_INFO("JsEnterpriseAdminExtension %{public}s end.", __func__);
}

sptr<IRemoteObject> JsEnterpriseAdminExtension::OnConnect(const AAFwk::Want& want)
{
    AbilityRuntime::Extension::OnConnect(want);
    HILOG_INFO("EnterpriseAdminExtension %{public}s begin.", __func__);
    sptr<EnterpriseAdminStubImpl> remoteObject = new (std::nothrow) EnterpriseAdminStubImpl(
        std::static_pointer_cast<JsEnterpriseAdminExtension>(shared_from_this()));
        
    if (remoteObject == nullptr) {
        HILOG_INFO("OnConnect get null");
        return remoteObject;
    }
    HILOG_INFO("JsEnterpriseAdminExtension %{public}s end. ", __func__);
    return remoteObject->AsObject();
}

void JsEnterpriseAdminExtension::OnDisconnect(const AAFwk::Want& want)
{
    HILOG_INFO("JsEnterpriseAdminExtension %{public}s begin.", __func__);
    AbilityRuntime::Extension::OnDisconnect(want);
}

void JsEnterpriseAdminExtension::OnAdminEnabled()
{
    HILOG_INFO("JsEnterpriseAdminExtension::OnAdminEnabled");
    auto task = [this]() {
        CallObjectMethod("onAdminEnabled", nullptr, JS_NAPI_ARGC_ZERO);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnAdminDisabled()
{
    HILOG_INFO("JsEnterpriseAdminExtension::OnAdminDisabled");
    auto task = [this]() {
        CallObjectMethod("onAdminDisabled", nullptr, JS_NAPI_ARGC_ZERO);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnBundleAdded(const std::string &bundleName)
{
    HILOG_INFO("JsEnterpriseAdminExtension::OnBundleAdded");
    auto task = [bundleName, this]() {
        auto& engine = jsRuntime_.GetNativeEngine();
        NativeValue* argv[] = { AbilityRuntime::CreateJsValue(engine, bundleName) };
        CallObjectMethod("onBundleAdded", argv, JS_NAPI_ARGC_ONE);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnBundleRemoved(const std::string &bundleName)
{
    HILOG_INFO("JsEnterpriseAdminExtension::OnBundleRemoved");
    auto task = [bundleName, this]() {
        auto& engine = jsRuntime_.GetNativeEngine();
        NativeValue* argv[] = { AbilityRuntime::CreateJsValue(engine, bundleName) };
        CallObjectMethod("onBundleRemoved", argv, JS_NAPI_ARGC_ONE);
    };
    handler_->PostTask(task);
}

NativeValue* JsEnterpriseAdminExtension::CallObjectMethod(const char* name, NativeValue** argv, size_t argc)
{
    HILOG_INFO("JsEnterpriseAdminExtension::CallObjectMethod(%{public}s), begin", name);

    if (!jsObj_) {
        HILOG_WARN("Not found EnterpriseAdminExtension.js");
        return nullptr;
    }

    AbilityRuntime::HandleScope handleScope(jsRuntime_);
    auto& nativeEngine = jsRuntime_.GetNativeEngine();

    NativeValue* value = jsObj_->Get();
    NativeObject* obj = AbilityRuntime::ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        HILOG_ERROR("Failed to get EnterpriseAdminExtension object");
        return nullptr;
    }

    NativeValue* method = obj->GetProperty(name);
    if (method == nullptr) {
        HILOG_ERROR("Failed to get '%{public}s' from EnterpriseAdminExtension object", name);
        return nullptr;
    }
    HILOG_INFO("JsEnterpriseAdminExtension::CallFunction(%{public}s), success", name);
    return nativeEngine.CallFunction(value, method, argv, argc);
}

void JsEnterpriseAdminExtension::GetSrcPath(std::string& srcPath)
{
    if (!Extension::abilityInfo_->srcEntrance.empty()) {
        srcPath.append(Extension::abilityInfo_->moduleName + "/");
        srcPath.append(Extension::abilityInfo_->srcEntrance);
        srcPath.erase(srcPath.rfind('.'));
        srcPath.append(".abc");
    }
}
} // namespace EDM
} // namespace OHOS