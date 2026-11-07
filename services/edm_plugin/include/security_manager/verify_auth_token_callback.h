/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_SECURITY_MANAGER_VERIFY_AUTH_TOKEN_CALLBACK_H
#define SERVICES_EDM_PLUGIN_INCLUDE_SECURITY_MANAGER_VERIFY_AUTH_TOKEN_CALLBACK_H

#include <condition_variable>
#include <cstdint>
#include <mutex>

#include "user_access_ctrl_client_callback.h"

namespace OHOS {
namespace EDM {

class VerifyAuthTokenCallback final : public UserIam::UserAuth::VerifyTokenCallback {
public:
    VerifyAuthTokenCallback() = default;
    virtual ~VerifyAuthTokenCallback() = default;
    void OnResult(int32_t result, const UserIam::UserAuth::Attributes &extraInfo) override;
    int32_t WaitResult(int64_t timeoutMs);
    uint64_t GetCredentialId() const;

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool done_ = false;
    int32_t result_ = -1;
    uint64_t credentialId_ = 0;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_SECURITY_MANAGER_VERIFY_AUTH_TOKEN_CALLBACK_H
