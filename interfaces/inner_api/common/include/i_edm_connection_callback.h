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

#ifndef INTERFACES_INNER_API_COMMON_INCLUDE_I_EDM_CONNECTION_CALLBACK_H
#define INTERFACES_INNER_API_COMMON_INCLUDE_I_EDM_CONNECTION_CALLBACK_H

#include "iremote_broker.h"
#include "element_name.h"
#include "iremote_object.h"

namespace OHOS {
namespace EDM {
class IEdmConnectionCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.edm.IEdmConnectionCallback");
    virtual ~IEdmConnectionCallback() = default;
    virtual void OnConnect(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remote) = 0;
    virtual void OnDisconnect(const AppExecFwk::ElementName &element) = 0;
    virtual void OnFailed(int32_t code) = 0;
};

enum class EdmConnectionCallbackCode : uint32_t {
    ON_CONNECT = 1,
    ON_DISCONNECT = 2,
    ON_FAILED = 3,
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_COMMON_INCLUDE_I_EDM_CONNECTION_CALLBACK_H
