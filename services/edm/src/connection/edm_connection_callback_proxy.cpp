/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "edm_connection_callback_proxy.h"

#include "edm_errors.h"
#include "edm_log.h"
#include "message_parcel.h"

namespace OHOS {
namespace EDM {
void EdmConnectionCallbackProxy::OnConnect(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remote)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!data.WriteInterfaceToken(IEdmConnectionCallback::GetDescriptor())) {
        EDMLOGE("OnConnect write interface token failed");
        return;
    }
    if (!element.Marshalling(data)) {
        EDMLOGE("OnConnect write element failed");
        return;
    }
    if (!data.WriteRemoteObject(remote)) {
        EDMLOGE("OnConnect write remote failed");
        return;
    }
    int32_t ret = Remote()->SendRequest(static_cast<uint32_t>(EdmConnectionCallbackCode::ON_CONNECT),
        data, reply, option);
    if (ret != ERR_OK) {
        EDMLOGE("OnConnect send request failed ret=%{public}d", ret);
    }
}

void EdmConnectionCallbackProxy::OnDisconnect(const AppExecFwk::ElementName &element)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!data.WriteInterfaceToken(IEdmConnectionCallback::GetDescriptor())) {
        EDMLOGE("OnDisconnect write interface token failed");
        return;
    }
    if (!element.Marshalling(data)) {
        EDMLOGE("OnDisconnect write element failed");
        return;
    }
    int32_t ret = Remote()->SendRequest(static_cast<uint32_t>(EdmConnectionCallbackCode::ON_DISCONNECT),
        data, reply, option);
    if (ret != ERR_OK) {
        EDMLOGE("OnDisconnect send request failed ret=%{public}d", ret);
    }
}

void EdmConnectionCallbackProxy::OnFailed(int32_t code)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!data.WriteInterfaceToken(IEdmConnectionCallback::GetDescriptor())) {
        EDMLOGE("OnFailed write interface token failed");
        return;
    }
    if (!data.WriteInt32(code)) {
        EDMLOGE("OnFailed write code failed");
        return;
    }
    int32_t ret = Remote()->SendRequest(static_cast<uint32_t>(EdmConnectionCallbackCode::ON_FAILED),
        data, reply, option);
    if (ret != ERR_OK) {
        EDMLOGE("OnFailed send request failed ret=%{public}d", ret);
    }
}
} // namespace EDM
} // namespace OHOS
