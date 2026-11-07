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

#include "verify_auth_token_callback.h"

#include <chrono>
#include <utility>

#include "attributes.h"
#include "edm_log.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace EDM {

void VerifyAuthTokenCallback::OnResult(int32_t result, const UserIam::UserAuth::Attributes &extraInfo)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (done_) {
            return;
        }
        result_ = result;
        if (result == static_cast<int32_t>(UserIam::UserAuth::SUCCESS)) {
            credentialId_ = 0;
            if (!extraInfo.GetUint64Value(UserIam::UserAuth::Attributes::ATTR_CREDENTIAL_ID, credentialId_)) {
                EDMLOGE("GetCredentialIdPlugin: credential id is absent in the verification result.");
                result_ = static_cast<int32_t>(UserIam::UserAuth::GENERAL_ERROR);
            }
        }
        done_ = true;
    }
    cv_.notify_one();
}

int32_t VerifyAuthTokenCallback::WaitResult(int64_t timeoutMs)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (!cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), [this] { return done_; })) {
        return -1;
    }
    return result_;
}

uint64_t VerifyAuthTokenCallback::GetCredentialId() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return credentialId_;
}
} // namespace EDM
} // namespace OHOS
