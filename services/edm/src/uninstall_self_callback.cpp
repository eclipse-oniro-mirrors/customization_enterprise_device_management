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

#include "uninstall_self_callback.h"

#include <chrono>

#include "edm_log.h"

namespace OHOS {
namespace EDM {
namespace {
constexpr int32_t UNINSTALL_RESULT_WAIT_TIMEOUT_MS = 30000;
}  // namespace

void UninstallSelfCallback::OnFinished(const int32_t resultCode, const std::string &resultMsg)
{
    bool expected = false;
    if (!finished_.compare_exchange_strong(expected, true)) {
        EDMLOGW("UninstallSelfCallback: OnFinished invoked repeatedly, ignore extra callback.");
        return;
    }
    resultCodeSignal_.set_value(resultCode);
    resultMsgSignal_.set_value(resultMsg);
}

void UninstallSelfCallback::OnStatusNotify(const int32_t progress)
{
    return;
}

bool UninstallSelfCallback::WaitFinished(int32_t &resultCode, std::string &resultMsg)
{
    if (resultCodeFuture_.wait_for(std::chrono::milliseconds(UNINSTALL_RESULT_WAIT_TIMEOUT_MS)) !=
        std::future_status::ready) {
        EDMLOGE("UninstallSelfCallback::WaitFinished wait uninstall result timeout.");
        return false;
    }
    resultCode = resultCodeFuture_.get();
    resultMsg = resultMsgFuture_.get();
    return true;
}
}  // namespace EDM
}  // namespace OHOS
