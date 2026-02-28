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

#include "js_enterprise_admin_extension.h"

#include <string>

#include "ability_handler.h"
#include "edm_log.h"
#include "enterprise_admin_extension.h"
#include "enterprise_admin_stub_impl.h"
#include "js_enterprise_admin_extension_context.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "runtime.h"
#include "cJSON.h"
#include "cjson_check.h"
#include "startup_scene.h"

namespace OHOS {
namespace EDM {
constexpr size_t JS_NAPI_ARGC_ZERO = 0;
constexpr size_t JS_NAPI_ARGC_ONE = 1;
constexpr size_t JS_NAPI_ARGC_TWO = 2;

napi_value AttachEnterpriseAdminExtensionContext(napi_env env, void* value, void*)
{
    EDMLOGI("AttachEnterpriseAdminExtensionContext called");
    if (value == nullptr) {
        EDMLOGI("null value");
        return nullptr;
    }
    auto ptr = reinterpret_cast<std::weak_ptr<EnterpriseAdminExtensionContext>*>(value)->lock();
    if (ptr == nullptr) {
        EDMLOGI("null ptr");
        return nullptr;
    }
    napi_value object = CreateJsEnterpriseAdminExtensionContext(env, ptr);
    if (object == nullptr) {
        EDMLOGE("null object");
    }
    auto sysModule = AbilityRuntime::JsRuntime::LoadSystemModuleByEngine(env,
        "enterprise.EnterpriseAdminExtensionContext", &object, JS_NAPI_ARGC_ONE);
    if (sysModule == nullptr) {
        EDMLOGI("null sysModule");
        return nullptr;
    }
    auto contextObj = sysModule->GetNapiValue();
    napi_coerce_to_native_binding_object(
        env, contextObj, AbilityRuntime::DetachCallbackFunc, AttachEnterpriseAdminExtensionContext, value, nullptr);
    auto workContext = new (std::nothrow) std::weak_ptr<EnterpriseAdminExtensionContext>(ptr);
    auto status = napi_wrap(env, contextObj, workContext,
        [](napi_env, void * data, void *) {
            EDMLOGI("Finalizer for weak_ptr form extension context is called");
            delete static_cast<std::weak_ptr<EnterpriseAdminExtensionContext> *>(data);
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        EDMLOGI("wrap context failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }
    return contextObj;
}

JsEnterpriseAdminExtension* JsEnterpriseAdminExtension::Create(const std::unique_ptr<AbilityRuntime::Runtime>& runtime)
{
    return new JsEnterpriseAdminExtension(static_cast<AbilityRuntime::JsRuntime&>(*runtime));
}

JsEnterpriseAdminExtension::JsEnterpriseAdminExtension(AbilityRuntime::JsRuntime& jsRuntime) : jsRuntime_(jsRuntime) {}
JsEnterpriseAdminExtension::~JsEnterpriseAdminExtension()
{
    EDMLOGD("Js enterprise admin extension destructor.");
    jsRuntime_.FreeNativeReference(std::move(jsObj_));
    jsRuntime_.FreeNativeReference(std::move(shellContextRef_));
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
        EDMLOGE("JsEnterpriseAdminExtension Failed to get srcPath");
        return;
    }

    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    EDMLOGD("JsEnterpriseAdminExtension::Init moduleName:%{public}s,srcPath:%{public}s.",
        moduleName.c_str(), srcPath.c_str());
    AbilityRuntime::HandleScope handleScope(jsRuntime_);
    auto env = jsRuntime_.GetNapiEnv();

    jsObj_ = jsRuntime_.LoadModule(moduleName, srcPath, abilityInfo_->hapPath,
        Extension::abilityInfo_->compileMode == AbilityRuntime::CompileMode::ES_MODULE);
    if (jsObj_ == nullptr) {
        EDMLOGI("JsEnterpriseAdminExtension Failed to get jsObj_");
        return;
    }

    napi_value obj = jsObj_->GetNapiValue();
    if (!AbilityRuntime::CheckTypeForNapiValue(env, obj, napi_object)) {
        EDMLOGI("jsObj_ is null");
        return;
    }

    BindContext(env, obj);
}

void JsEnterpriseAdminExtension::BindContext(napi_env env, napi_value obj)
{
    auto context = GetContext();
    if (context == nullptr) {
        EDMLOGE("JsEnterpriseAdminExtension Failed to get context");
        return;
    }
    EDMLOGI("JsEnterpriseAdminExtension::BindContext CreateJsEnterpriseAdminExtensionContext.");
    napi_value contextObj = CreateJsEnterpriseAdminExtensionContext(env, context);
    shellContextRef_ = AbilityRuntime::JsRuntime::LoadSystemModuleByEngine(env,
        "enterprise.EnterpriseAdminExtensionContext", &contextObj, JS_NAPI_ARGC_ONE);
    if (shellContextRef_ == nullptr) {
        EDMLOGE("BindContext LoadSystemModule null");
        return;
    }

    contextObj = shellContextRef_->GetNapiValue();
    if (!AbilityRuntime::CheckTypeForNapiValue(env, contextObj, napi_object)) {
        EDMLOGE("get context failed");
        return;
    }
    auto workContext = new (std::nothrow) std::weak_ptr<EnterpriseAdminExtensionContext>(context);
    napi_coerce_to_native_binding_object(
        env, contextObj, AbilityRuntime::DetachCallbackFunc,
        AttachEnterpriseAdminExtensionContext, workContext, nullptr);

    context->Bind(jsRuntime_, shellContextRef_.get());
    napi_set_named_property(env, obj, "context", contextObj);

    auto status = napi_wrap(env, contextObj, workContext,
        [](napi_env env, void* data, void*) {
            EDMLOGI("Finalizer for weak_ptr service extension context is called");
            delete static_cast<std::weak_ptr<EnterpriseAdminExtensionContext>*>(data);
        }, nullptr, nullptr);
    if (status != napi_ok) {
        EDMLOGE("wrap context fail: %{public}d", status);
        delete workContext;
    }

    EDMLOGI("JsEnterpriseAdminExtension::BindContext end.");
}

void JsEnterpriseAdminExtension::OnStart(const AAFwk::Want& want)
{
    EDMLOGI("JsEnterpriseAdminExtension OnStart begin");
    AbilityRuntime::Extension::OnStart(want);
    auto task = [this]() {
        CallObjectMethod("onStart", nullptr, JS_NAPI_ARGC_ZERO);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnStop()
{
    AbilityRuntime::Extension::OnStop();
    EDMLOGI("JsEnterpriseAdminExtension %{public}s end.", __func__);
}

sptr<IRemoteObject> JsEnterpriseAdminExtension::OnConnect(const AAFwk::Want& want)
{
    AbilityRuntime::Extension::OnConnect(want);
    EDMLOGI("EnterpriseAdminExtension %{public}s begin.", __func__);
    sptr<EnterpriseAdminStubImpl> remoteObject = new (std::nothrow) EnterpriseAdminStubImpl(
        std::static_pointer_cast<JsEnterpriseAdminExtension>(shared_from_this()));

    if (remoteObject == nullptr) {
        EDMLOGI("OnConnect get null");
        return remoteObject;
    }
    EDMLOGI("JsEnterpriseAdminExtension %{public}s end. ", __func__);
    return remoteObject->AsObject();
}

void JsEnterpriseAdminExtension::OnDisconnect(const AAFwk::Want& want)
{
    EDMLOGI("JsEnterpriseAdminExtension %{public}s begin.", __func__);
    AbilityRuntime::Extension::OnDisconnect(want);
}

void JsEnterpriseAdminExtension::OnAdminEnabled()
{
    EDMLOGI("JsEnterpriseAdminExtension::OnAdminEnabled");
    auto task = [this]() {
        CallObjectMethod("onAdminEnabled", nullptr, JS_NAPI_ARGC_ZERO);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnAdminDisabled()
{
    EDMLOGI("JsEnterpriseAdminExtension::OnAdminDisabled");
    auto task = [this]() {
        CallObjectMethod("onAdminDisabled", nullptr, JS_NAPI_ARGC_ZERO);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnDeviceAdminEnabled(const std::string &bundleName)
{
    EDMLOGI("JsEnterpriseAdminExtension::OnDeviceAdminEnabled");
    auto task = [bundleName, this]() {
        auto env = jsRuntime_.GetNapiEnv();
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            EDMLOGE("OnDeviceAdminEnabled scope is nullptr");
            return;
        }
        napi_value argv[] = { AbilityRuntime::CreateJsValue(env, bundleName) };
        CallObjectMethod("onDeviceAdminEnabled", argv, JS_NAPI_ARGC_ONE);
        napi_close_handle_scope(env, scope);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnDeviceAdminDisabled(const std::string &bundleName)
{
    EDMLOGI("JsEnterpriseAdminExtension::OnDeviceAdminDisabled");
    auto task = [bundleName, this]() {
        auto env = jsRuntime_.GetNapiEnv();
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            EDMLOGE("OnDeviceAdminDisabled scope is nullptr");
            return;
        }
        napi_value argv[] = { AbilityRuntime::CreateJsValue(env, bundleName) };
        CallObjectMethod("onDeviceAdminDisabled", argv, JS_NAPI_ARGC_ONE);
        napi_close_handle_scope(env, scope);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnBundleAdded(const std::string &bundleName, int32_t accountId)
{
    EDMLOGI("JsEnterpriseAdminExtension::OnBundleAdded");
    auto task = [bundleName, accountId, this]() {
        auto env = jsRuntime_.GetNapiEnv();
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            EDMLOGE("OnBundleAdded scope is nullptr");
            return;
        }
        napi_value argv[] = { AbilityRuntime::CreateJsValue(env, bundleName),
            AbilityRuntime::CreateJsValue(env, accountId) };
        CallObjectMethod("onBundleAdded", argv, JS_NAPI_ARGC_TWO);
        napi_close_handle_scope(env, scope);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnBundleRemoved(const std::string &bundleName, int32_t accountId)
{
    EDMLOGI("JsEnterpriseAdminExtension::OnBundleRemoved");
    auto task = [bundleName, accountId, this]() {
        auto env = jsRuntime_.GetNapiEnv();
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            EDMLOGE("OnBundleRemoved scope is nullptr");
            return;
        }
        napi_value argv[] = { AbilityRuntime::CreateJsValue(env, bundleName),
            AbilityRuntime::CreateJsValue(env, accountId) };
        CallObjectMethod("onBundleRemoved", argv, JS_NAPI_ARGC_TWO);
        napi_close_handle_scope(env, scope);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnAppStart(const std::string &bundleName)
{
    EDMLOGI("JsEnterpriseAdminExtension::OnAppStart");
    auto task = [bundleName, this]() {
        auto env = jsRuntime_.GetNapiEnv();
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            EDMLOGE("OnAppStart scope is nullptr");
            return;
        }
        napi_value argv[] = { AbilityRuntime::CreateJsValue(env, bundleName) };
        CallObjectMethod("onAppStart", argv, JS_NAPI_ARGC_ONE);
        napi_close_handle_scope(env, scope);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnAppStop(const std::string &bundleName)
{
    EDMLOGI("JsEnterpriseAdminExtension::OnAppStop");
    auto task = [bundleName, this]() {
        auto env = jsRuntime_.GetNapiEnv();
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            EDMLOGE("OnAppStop scope is nullptr");
            return;
        }
        napi_value argv[] = { AbilityRuntime::CreateJsValue(env, bundleName) };
        CallObjectMethod("onAppStop", argv, JS_NAPI_ARGC_ONE);
        napi_close_handle_scope(env, scope);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnSystemUpdate(const UpdateInfo &updateInfo)
{
    EDMLOGI("JsEnterpriseAdminExtension::OnSystemUpdate");
    auto task = [updateInfo, this]() {
        auto env = jsRuntime_.GetNapiEnv();
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            EDMLOGE("OnSystemUpdate scope is nullptr");
            return;
        }
        napi_value argv[] = { CreateUpdateInfoObject(env, updateInfo) };
        CallObjectMethod("onSystemUpdate", argv, JS_NAPI_ARGC_ONE);
        napi_close_handle_scope(env, scope);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnAccountAdded(const int32_t accountId)
{
    EDMLOGI("JsEnterpriseAdminExtension::OnAccountAdded");
    auto task = [accountId, this]() {
        auto env = jsRuntime_.GetNapiEnv();
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            EDMLOGE("OnAccountAdded scope is nullptr");
            return;
        }
        napi_value argv[] = { AbilityRuntime::CreateJsValue(env, accountId) };
        CallObjectMethod("onAccountAdded", argv, JS_NAPI_ARGC_ONE);
        napi_close_handle_scope(env, scope);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnAccountSwitched(const int32_t accountId)
{
    EDMLOGI("JsEnterpriseAdminExtension::OnAccountSwitched");
    auto task = [accountId, this]() {
        auto env = jsRuntime_.GetNapiEnv();
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            EDMLOGE("OnAccountSwitched scope is nullptr");
            return;
        }
        napi_value argv[] = { AbilityRuntime::CreateJsValue(env, accountId) };
        CallObjectMethod("onAccountSwitched", argv, JS_NAPI_ARGC_ONE);
        napi_close_handle_scope(env, scope);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnAccountRemoved(const int32_t accountId)
{
    EDMLOGI("JsEnterpriseAdminExtension::OnAccountRemoved");
    auto task = [accountId, this]() {
        auto env = jsRuntime_.GetNapiEnv();
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            EDMLOGE("OnAccountRemoved scope is nullptr");
            return;
        }
        napi_value argv[] = { AbilityRuntime::CreateJsValue(env, accountId) };
        CallObjectMethod("onAccountRemoved", argv, JS_NAPI_ARGC_ONE);
        napi_close_handle_scope(env, scope);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnKioskModeEntering(const std::string &bundleName, int32_t accountId)
{
    EDMLOGI("JsEnterpriseAdminExtension::OnKioskModeEntering");
    auto task = [bundleName, accountId, this]() {
        auto env = jsRuntime_.GetNapiEnv();
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            EDMLOGE("OnKioskModeEntering scope is nullptr");
            return;
        }
        napi_value argv[] = { AbilityRuntime::CreateJsValue(env, bundleName),
                              AbilityRuntime::CreateJsValue(env, accountId) };
        CallObjectMethod("onKioskModeEntering", argv, JS_NAPI_ARGC_TWO);
        napi_close_handle_scope(env, scope);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnKioskModeExiting(const std::string &bundleName, int32_t accountId)
{
    EDMLOGI("JsEnterpriseAdminExtension::OnKioskModeExiting");
    auto task = [bundleName, accountId, this]() {
        auto env = jsRuntime_.GetNapiEnv();
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            EDMLOGE("OnKioskModeExiting scope is nullptr");
            return;
        }
        napi_value argv[] = { AbilityRuntime::CreateJsValue(env, bundleName),
                              AbilityRuntime::CreateJsValue(env, accountId) };
        CallObjectMethod("onKioskModeExiting", argv, JS_NAPI_ARGC_TWO);
        napi_close_handle_scope(env, scope);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnMarketAppsInstallStatusChanged(const std::string &bundleName, int32_t status)
{
    EDMLOGI("JsEnterpriseAdminExtension::OnMarketAppsInstallStatusChanged");
    auto task = [bundleName, status, this]() {
        auto env = jsRuntime_.GetNapiEnv();
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            EDMLOGE("OnMarketAppsInstallStatusChanged scope is nullptr");
            return;
        }
        napi_value argv[] = { AbilityRuntime::CreateJsValue(env, bundleName),
                              CreateInstallationResultObject(env, bundleName, status) };
        CallObjectMethod("onMarketAppInstallResult", argv, JS_NAPI_ARGC_TWO);
        napi_close_handle_scope(env, scope);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnLogCollected(bool isSuccess)
{
    EDMLOGI("JsEnterpriseAdminExtension::OnLogCollected");
    auto task = [isSuccess, this]() {
        auto env = jsRuntime_.GetNapiEnv();
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            EDMLOGE("OnLogCollected scope is nullptr");
            return;
        }
        napi_value argv[] = { CreateResultObject(env, isSuccess ? 0 : -1) };
        CallObjectMethod("onLogCollected", argv, JS_NAPI_ARGC_ONE);
        napi_close_handle_scope(env, scope);
    };
    handler_->PostTask(task);
}

void JsEnterpriseAdminExtension::OnKeyEvent(const std::string &event)
{
    EDMLOGI("JsEnterpriseAdminExtension::OnKeyEvent");
    OHOS::EDM::KeyEvent keyEventInfo;
    if (ParseKeyEventInfo(event, keyEventInfo)) {
        auto task = [keyEventInfo, this]() {
            auto env = jsRuntime_.GetNapiEnv();
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(env, &scope);
            if (scope == nullptr) {
                EDMLOGE("OnKeyEvent scope is nullptr");
                return;
            }
            napi_value argv[] = { CreateKeyEventInfoObject(env, keyEventInfo)};
            CallObjectMethod("onKeyEvent", argv, JS_NAPI_ARGC_ONE);
            napi_close_handle_scope(env, scope);
        };
        handler_->PostTask(task);
    };
}

bool JsEnterpriseAdminExtension::ParseKeyEventInfo(const std::string &jsonString, OHOS::EDM::KeyEvent &keyEventInfo)
{
    EDMLOGI("JsEnterpriseAdminExtension::ParseKeyEventInfo");
    cJSON* root = cJSON_Parse(jsonString.c_str());
    if (root == nullptr) {
        EDMLOGE("Failed to parse JSON string");
        return false;
    }
    
    cJSON *actionTime = cJSON_GetObjectItem(root, "actionTime");
    cJSON *keyCode = cJSON_GetObjectItem(root, "keyCode");
    cJSON *keyAction = cJSON_GetObjectItem(root, "keyAction");
    cJSON *keyItems = cJSON_GetObjectItem(root, "keyItems");
    
    if (!cJSON_IsNumber(actionTime) || !cJSON_IsNumber(keyCode) || !cJSON_IsNumber(keyAction) ||
        !cJSON_IsArray(keyItems)) {
        EDMLOGE("Invalid JSON structure");
        cJSON_Delete(root);
        return false;
    }
    keyEventInfo.actionTime = actionTime->valuedouble;
    keyEventInfo.keyCode = keyCode->valueint;
    if (keyAction->valueint == static_cast<int32_t>(OHOS::EDM::KeyAction::DOWN) ||
        keyAction->valueint == static_cast<int32_t>(OHOS::EDM::KeyAction::UP)) {
        keyEventInfo.keyAction = static_cast<OHOS::EDM::KeyAction>(keyAction->valueint);
    } else {
        keyEventInfo.keyAction = OHOS::EDM::KeyAction::UNKNOWN;
        EDMLOGW("Invalid keyAction value: %{public}d", keyAction->valueint);
    }

    cJSON *keyItem;
    cJSON_ArrayForEach(keyItem, keyItems) {
        cJSON *pressed = cJSON_GetObjectItem(keyItem, "pressed");
        cJSON *keyCodeItem = cJSON_GetObjectItem(keyItem, "keyCode");
        cJSON *downTime = cJSON_GetObjectItem(keyItem, "downTime");

        if (!cJSON_IsNumber(pressed) || !cJSON_IsNumber(keyCodeItem) || !cJSON_IsNumber(downTime)) {
            EDMLOGE("Invalid JSON structure");
            cJSON_Delete(root);
            return false;
        }
        KeyEventItem KeyItemStruct;
        KeyItemStruct.pressed = pressed->valueint;
        KeyItemStruct.keyCode = keyCodeItem->valueint;
        KeyItemStruct.downTime = downTime->valuedouble;

        keyEventInfo.keyItems.push_back(KeyItemStruct);
    }
    cJSON_Delete(root);
    return true;
}

napi_value JsEnterpriseAdminExtension::CreateKeyEventInfoObject(napi_env env, const OHOS::EDM::KeyEvent &keyEventInfo)
{
    napi_value nKeyEventInfo = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nKeyEventInfo));

    napi_value nActionTime = nullptr;
    NAPI_CALL(env, napi_create_int64(env, keyEventInfo.actionTime, &nActionTime));
    NAPI_CALL(env, napi_set_named_property(env, nKeyEventInfo, "actionTime", nActionTime));
    
    napi_value nKeyCode = nullptr;
    NAPI_CALL(env, napi_create_int32(env, keyEventInfo.keyCode, &nKeyCode));
    NAPI_CALL(env, napi_set_named_property(env, nKeyEventInfo, "keyCode", nKeyCode));

    napi_value nKeyAction = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(keyEventInfo.keyAction), &nKeyAction));
    NAPI_CALL(env, napi_set_named_property(env, nKeyEventInfo, "keyAction", nKeyAction));

    napi_value nKeyItems = nullptr;
    NAPI_CALL(env, napi_create_array_with_length(env, keyEventInfo.keyItems.size(), &nKeyItems));

    for (size_t i = 0; i < keyEventInfo.keyItems.size(); ++i) {
        const KeyEventItem &keyItem = keyEventInfo.keyItems[i];

        napi_value nKeyItem = nullptr;
        NAPI_CALL(env, napi_create_object(env, &nKeyItem));

        napi_value nPressed = nullptr;
        NAPI_CALL(env, napi_get_boolean(env, keyItem.pressed, &nPressed));
        NAPI_CALL(env, napi_set_named_property(env, nKeyItem, "pressed", nPressed));

        napi_value nKeyCodeItem = nullptr;
        NAPI_CALL(env, napi_create_int32(env, keyItem.keyCode, &nKeyCodeItem));
        NAPI_CALL(env, napi_set_named_property(env, nKeyItem, "keyCode", nKeyCodeItem));

        napi_value nDownTime = nullptr;
        NAPI_CALL(env, napi_create_int64(env, keyItem.downTime, &nDownTime));
        NAPI_CALL(env, napi_set_named_property(env, nKeyItem, "downTime", nDownTime));

        NAPI_CALL(env, napi_set_element(env, nKeyItems, i, nKeyItem));
    }
    NAPI_CALL(env, napi_set_named_property(env, nKeyEventInfo, "keyItems", nKeyItems));
    return nKeyEventInfo;
}

napi_value JsEnterpriseAdminExtension::CreateUpdateInfoObject(napi_env env, const UpdateInfo &updateInfo)
{
    napi_value nSystemUpdateInfo = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nSystemUpdateInfo));

    napi_value nVersionName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, updateInfo.version.c_str(), NAPI_AUTO_LENGTH, &nVersionName));
    NAPI_CALL(env, napi_set_named_property(env, nSystemUpdateInfo, "versionName", nVersionName));

    napi_value nFirstReceivedTime = nullptr;
    NAPI_CALL(env, napi_create_int64(env, updateInfo.firstReceivedTime, &nFirstReceivedTime));
    NAPI_CALL(env, napi_set_named_property(env, nSystemUpdateInfo, "firstReceivedTime", nFirstReceivedTime));

    napi_value nPackageType = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, updateInfo.packageType.c_str(), NAPI_AUTO_LENGTH, &nPackageType));
    NAPI_CALL(env, napi_set_named_property(env, nSystemUpdateInfo, "packageType", nPackageType));

    return nSystemUpdateInfo;
}

napi_value JsEnterpriseAdminExtension::CreateInstallationResultObject(napi_env env,
    const std::string &bundleName, int32_t status)
{
    napi_value nInstallationResult = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nInstallationResult));

    std::string message = bundleName + (status == 0 ? " installed successfully." : " installed failed.");
    napi_value nMessage = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, message.c_str(), NAPI_AUTO_LENGTH, &nMessage));
    NAPI_CALL(env, napi_set_named_property(env, nInstallationResult, "message", nMessage));

    napi_value nResult = nullptr;
    NAPI_CALL(env, napi_create_int32(env, status, &nResult));
    NAPI_CALL(env, napi_set_named_property(env, nInstallationResult, "result", nResult));

    return nInstallationResult;
}

napi_value JsEnterpriseAdminExtension::CreateResultObject(napi_env env, int32_t success)
{
    napi_value nResult = nullptr;
    NAPI_CALL(env, napi_create_int32(env, success, &nResult));
    return nResult;
}

napi_value JsEnterpriseAdminExtension::CallObjectMethod(const char* name, napi_value* argv, size_t argc)
{
    EDMLOGI("JsEnterpriseAdminExtension::CallObjectMethod(%{public}s), begin", name);

    if (!jsObj_) {
        EDMLOGW("Not found EnterpriseAdminExtension.js");
        return nullptr;
    }

    AbilityRuntime::HandleScope handleScope(jsRuntime_);
    auto env = jsRuntime_.GetNapiEnv();

    napi_value value = jsObj_->GetNapiValue();
    if (value == nullptr) {
        EDMLOGE("Failed to get EnterpriseAdminExtension object");
        return nullptr;
    }
    napi_value method = nullptr;
    napi_get_named_property(env, value, name, &method);

    if (method == nullptr) {
        EDMLOGE("Failed to get '%{public}s' from EnterpriseAdminExtension object", name);
        return nullptr;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, method, &valueType);
    if (valueType != napi_function) {
        EDMLOGE("'%{public}s' is not function", name);
        return nullptr;
    }

    EDMLOGI("JsEnterpriseAdminExtension::CallFunction(%{public}s), success", name);
    napi_value result = nullptr;
    napi_status status = napi_call_function(env, value, method, argc, argv, &result);
    if (status != napi_ok) {
        EDMLOGE("Failed to call function");
    }
    return result;
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