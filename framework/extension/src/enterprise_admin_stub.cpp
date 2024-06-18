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

#include "edm_log.h"

namespace OHOS {
namespace EDM {

constexpr const int EDM_UID = 3057;

EnterpriseAdminStub::EnterpriseAdminStub()
{
    EDMLOGD("EnterpriseAdminStub()");
}

EnterpriseAdminStub::~EnterpriseAdminStub()
{
    EDMLOGD("~EnterpriseAdminStub()");
}


int32_t EnterpriseAdminStub::CallFuncByCode(uint32_t code, MessageParcel& data, MessageParcel& reply,
    MessageOption &option)
{
    switch (code) {
        case COMMAND_ON_ADMIN_ENABLED:
            OnAdminEnabledInner(data, reply);
            return ERR_NONE;
        case COMMAND_ON_ADMIN_DISABLED:
            OnAdminDisabledInner(data, reply);
            return ERR_NONE;
        case COMMAND_ON_BUNDLE_ADDED:
            OnBundleAddedInner(data, reply);
            return ERR_NONE;
        case COMMAND_ON_BUNDLE_REMOVED:
            OnBundleRemovedInner(data, reply);
            return ERR_NONE;
        case COMMAND_ON_APP_START:
            OnAppStartInner(data, reply);
            return ERR_NONE;
        case COMMAND_ON_APP_STOP:
            OnAppStopInner(data, reply);
            return ERR_NONE;
        case COMMAND_ON_SYSTEM_UPDATE:
            OnSystemUpdateInner(data, reply);
            return ERR_NONE;
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

void EnterpriseAdminStub::OnAdminEnabledInner(MessageParcel& data, MessageParcel& reply)
{
    EDMLOGI("EnterpriseAdminStub::OnAdminEnabled");
    OnAdminEnabled();
}

void EnterpriseAdminStub::OnAdminDisabledInner(MessageParcel& data, MessageParcel& reply)
{
    EDMLOGI("EnterpriseAdminStub::OnAdminDisabled");
    OnAdminDisabled();
}

void EnterpriseAdminStub::OnBundleAddedInner(MessageParcel& data, MessageParcel& reply)
{
    EDMLOGI("EnterpriseAdminStub::OnBundleAdded");
    std::string bundleName = data.ReadString();
    OnBundleAdded(bundleName);
}

void EnterpriseAdminStub::OnBundleRemovedInner(MessageParcel& data, MessageParcel& reply)
{
    EDMLOGI("EnterpriseAdminStub::OnBundleRemoved");
    std::string bundleName = data.ReadString();
    OnBundleRemoved(bundleName);
}

void EnterpriseAdminStub::OnAppStartInner(MessageParcel& data, MessageParcel& reply)
{
    EDMLOGI("EnterpriseAdminStub::OnAppStart");
    std::string bundleName = data.ReadString();
    OnAppStart(bundleName);
}

void EnterpriseAdminStub::OnAppStopInner(MessageParcel& data, MessageParcel& reply)
{
    EDMLOGI("EnterpriseAdminStub::OnAppStop");
    std::string bundleName = data.ReadString();
    OnAppStop(bundleName);
}

void EnterpriseAdminStub::OnSystemUpdateInner(MessageParcel& data, MessageParcel& reply)
{
    EDMLOGI("EnterpriseAdminStub::OnSystemUpdate");
    UpdateInfo updateInfo;
    updateInfo.version = data.ReadString();
    updateInfo.firstReceivedTime = data.ReadInt64();
    updateInfo.packageType = data.ReadString();
    OnSystemUpdate(updateInfo);
}

int32_t EnterpriseAdminStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
    MessageOption &option)
{
    auto remoteDescriptor = data.ReadInterfaceToken();
    EDMLOGI("EnterpriseAdminStub code %{public}u", code);
    if (GetDescriptor() != remoteDescriptor) {
        EDMLOGE("EnterpriseAdminStub::OnRemoteRequest failed, descriptor is not matched!");
        return ERR_INVALID_STATE;
    }

    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::ATokenTypeEnum tokenType =
        Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType != Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        EDMLOGE("EnterpriseAdminStub::OnRemoteRequest failed, caller tokenType is not matched");
        return ERR_INVALID_STATE;
    }
    int uid = GetCallingUid();
    if (uid != EDM_UID) {
        EDMLOGE("EnterpriseAdminStub::OnRemoteRequest failed, caller uid is not matched");
        return ERR_INVALID_STATE;
    }
    return CallFuncByCode(code, data, reply, option);
}
} // namespace EDM
} // namespace OHOS
