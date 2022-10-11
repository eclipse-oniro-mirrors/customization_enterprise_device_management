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

#include "enterprise_admin_stub.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
EnterpriseAdminStub::EnterpriseAdminStub()
{
    AddCallFuncMap();
    EDMLOGD("EnterpriseAdminStub()");
}

EnterpriseAdminStub::~EnterpriseAdminStub()
{
    EDMLOGD("~EnterpriseAdminStub()");
}

void EnterpriseAdminStub::AddCallFuncMap()
{
    memberFuncMap_[COMMAND_ON_ADMIN_ENABLED] = &EnterpriseAdminStub::OnAdminEnabledInner;
    memberFuncMap_[COMMAND_ON_ADMIN_DISABLED] = &EnterpriseAdminStub::OnAdminDisabledInner;
    memberFuncMap_[COMMAND_ON_BUNDLE_ADDED] = &EnterpriseAdminStub::OnBundleAddedInner;
    memberFuncMap_[COMMAND_ON_BUNDLE_REMOVED] = &EnterpriseAdminStub::OnBundleRemovedInner;
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

int32_t EnterpriseAdminStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
    MessageOption &option)
{
    auto remoteDescriptor = data.ReadInterfaceToken();
    EDMLOGI("EnterpriseAdminStub code %{public}u", code);
    if (GetDescriptor() != remoteDescriptor) {
        EDMLOGE("EnterpriseAdminStub::OnRemoteRequest failed, descriptor is not matched!");
        return ERR_INVALID_STATE;
    }
    auto func = memberFuncMap_.find(code);
    if (func != memberFuncMap_.end()) {
        auto memberFunc = func->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(data, reply);
            return ERR_NONE;
        }
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    return ERR_TRANSACTION_FAILED;
}
} // namespace EDM
} // namespace OHOS
