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

#include "enterprise_admin_stub.h"

#include <accesstoken_kit.h>
#include <ipc_skeleton.h>

#include "edm_errors.h"
#include "edm_log.h"
#include "policy_changed_event.h"

namespace OHOS {
namespace EDM {

constexpr const int EDM_UID = 3057;

EnterpriseAdminStub::EnterpriseAdminStub()
{
    EDMLOGD("EnterpriseAdminStub()");
    InitHandleFuncMap();
}

EnterpriseAdminStub::~EnterpriseAdminStub()
{
    EDMLOGD("~EnterpriseAdminStub()");
}

void EnterpriseAdminStub::InitHandleFuncMap()
{
    InitAdminHandleFuncs();
    InitBundleHandleFuncs();
    InitAppHandleFuncs();
    InitAccountHandleFuncs();
    InitKioskHandleFuncs();
    InitOtherHandleFuncs();
}

void EnterpriseAdminStub::InitAdminHandleFuncs()
{
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) { return OnAdminInner(code, data, reply); };
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_ADMIN_DISABLED] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) { return OnAdminInner(code, data, reply); };
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_DEVICE_ADMIN_ENABLED] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) {
            return OnDeviceAdminInner(code, data, reply);
        };
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_DEVICE_ADMIN_DISABLED] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) {
            return OnDeviceAdminInner(code, data, reply);
        };
}

void EnterpriseAdminStub::InitBundleHandleFuncs()
{
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_BUNDLE_ADDED] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) { return OnBundleInner(code, data, reply); };
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_BUNDLE_REMOVED] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) { return OnBundleInner(code, data, reply); };
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_BUNDLE_UPDATED] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) { return OnBundleInner(code, data, reply); };
}

void EnterpriseAdminStub::InitAppHandleFuncs()
{
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_APP_START] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) { return OnAppInner(code, data, reply); };
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_APP_STOP] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) { return OnAppInner(code, data, reply); };
}

void EnterpriseAdminStub::InitAccountHandleFuncs()
{
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_ACCOUNT_ADDED] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) { return OnAccountInner(code, data, reply); };
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_ACCOUNT_SWITCHED] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) { return OnAccountInner(code, data, reply); };
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_ACCOUNT_REMOVED] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) { return OnAccountInner(code, data, reply); };
}

void EnterpriseAdminStub::InitKioskHandleFuncs()
{
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_KIOSK_MODE_ENTERING] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) {
            return OnKioskModeInner(code, data, reply);
        };
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_KIOSK_MODE_EXITING] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) {
            return OnKioskModeInner(code, data, reply);
        };
}

void EnterpriseAdminStub::InitOtherHandleFuncs()
{
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_SYSTEM_UPDATE] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) {
            return OnSystemUpdateInner(code, data, reply);
        };
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_MARKET_INSTALL_STATUS_CHANGED] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) {
            return OnMarketAppsInstallStatusChangedInner(code, data, reply);
        };
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_LOG_COLLECTED] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) {
            return OnLogCollectedInner(code, data, reply);
        };
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_KEY_EVENT] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) { return OnKeyEventInner(code, data, reply); };
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_STARTUP_GUIDE_COMPLETED] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) {
            return OnStartupGuideCompletedInner(code, data, reply);
        };
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_DEVICE_BOOT_COMPLETED] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) {
            return OnDeviceBootCompletedInner(code, data, reply);
        };
    handleFuncMap_[IEnterpriseAdmin::COMMAND_ON_POLICIES_CHANGED] = 
        [this](uint32_t code, MessageParcel& data, MessageParcel& reply) {
            return OnAdminPolicyChangedInner(code, data, reply);
        };
}

int32_t EnterpriseAdminStub::CallFuncByCode(uint32_t code, MessageParcel& data, MessageParcel& reply,
    MessageOption &option)
{
    auto it = handleFuncMap_.find(code);
    if (it == handleFuncMap_.end()) {
        EDMLOGE("EnterpriseAdminStub code %{public}u is not exist.", code);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    EDMLOGI("EnterpriseAdminStub::CallFuncByCode %{public}u start.", code);
    if (!it->second(code, data, reply)) {
        EDMLOGE("EnterpriseAdminStub::CallFuncByCode %{public}u failed.", code);
        return CALL_FUN_FAILED;
    }
    return ERR_NONE;
}

bool EnterpriseAdminStub::OnAdminInner(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    return OnAdmin(code);
}

bool EnterpriseAdminStub::OnBundleInner(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    std::string bundleName = data.ReadString();
    int32_t accountId = data.ReadInt32();
    return OnBundle(code, bundleName, accountId);
}

bool EnterpriseAdminStub::OnAppInner(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    std::string bundleName = data.ReadString();
    return OnApp(code, bundleName);
}

bool EnterpriseAdminStub::OnSystemUpdateInner(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    UpdateInfo updateInfo;
    updateInfo.version = data.ReadString();
    updateInfo.firstReceivedTime = data.ReadInt64();
    updateInfo.packageType = data.ReadString();
    return OnSystemUpdate(updateInfo);
}

bool EnterpriseAdminStub::OnAccountInner(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    int32_t accountId = data.ReadInt32();
    return OnAccount(code, accountId);
}

bool EnterpriseAdminStub::OnKioskModeInner(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    std::string bundleName = data.ReadString();
    int32_t accountId = data.ReadInt32();
    return OnKioskMode(code, bundleName, accountId);
}

bool EnterpriseAdminStub::OnMarketAppsInstallStatusChangedInner(uint32_t code, MessageParcel& data,
    MessageParcel& reply)
{
    std::string bundleName = data.ReadString();
    int32_t status = data.ReadInt32();
    return OnMarketAppsInstallStatusChanged(bundleName, status);
}

bool EnterpriseAdminStub::OnDeviceAdminInner(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    std::string bundleName = data.ReadString();
    return OnDeviceAdmin(code, bundleName);
}

bool EnterpriseAdminStub::OnLogCollectedInner(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    bool isSuccess = data.ReadBool();
    return OnLogCollected(isSuccess);
}

bool EnterpriseAdminStub::OnKeyEventInner(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    std::string event = data.ReadString();
    return OnKeyEvent(event);
}

bool EnterpriseAdminStub::OnStartupGuideCompletedInner(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    int32_t type = data.ReadInt32();
    return OnStartupGuideCompleted(type);
}

bool EnterpriseAdminStub::OnDeviceBootCompletedInner(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    return OnDeviceBootCompleted();
}

bool EnterpriseAdminStub::OnAdminPolicyChangedInner(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    PolicyChangedEvent event;
    PolicyChangedEvent::Unmarshalling(data, event);
    return OnAdminPolicyChanged(event);
}

int32_t EnterpriseAdminStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
    MessageOption &option)
{
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (GetDescriptor() != remoteDescriptor) {
        EDMLOGE("EnterpriseAdminStub::OnRemoteRequest failed, descriptor is not matched!");
        return DESCRIPTOR_NOT_MATCHED;
    }

    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::ATokenTypeEnum tokenType =
        Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType != Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        EDMLOGE("EnterpriseAdminStub::OnRemoteRequest failed, caller tokenType is not matched");
        return CALLER_TOKEN_TYPE_ERR;
    }
    int uid = GetCallingUid();
    if (uid != EDM_UID) {
        EDMLOGE("EnterpriseAdminStub::OnRemoteRequest failed, caller uid is not matched");
        return CALLER_UID_ERR;
    }
    return CallFuncByCode(code, data, reply, option);
}
} // namespace EDM
} // namespace OHOS
