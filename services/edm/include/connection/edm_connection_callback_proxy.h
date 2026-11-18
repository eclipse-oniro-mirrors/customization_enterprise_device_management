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

#ifndef SERVICES_EDM_INCLUDE_CONNECTION_EDM_CONNECTION_CALLBACK_PROXY_H
#define SERVICES_EDM_INCLUDE_CONNECTION_EDM_CONNECTION_CALLBACK_PROXY_H

#include "i_edm_connection_callback.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace EDM {
class EdmConnectionCallbackProxy : public IRemoteProxy<IEdmConnectionCallback> {
public:
    explicit EdmConnectionCallbackProxy(const sptr<IRemoteObject> &remote)
        : IRemoteProxy<IEdmConnectionCallback>(remote) {}
    ~EdmConnectionCallbackProxy() override = default;

    void OnConnect(const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remote) override;
    void OnDisconnect(const AppExecFwk::ElementName &element) override;
    void OnFailed(int32_t code) override;

private:
    static inline BrokerDelegator<EdmConnectionCallbackProxy> delegator_;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_CONNECTION_EDM_CONNECTION_CALLBACK_PROXY_H
