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

#ifndef EDM_UNIT_TEST_UTILS_H
#define EDM_UNIT_TEST_UTILS_H

#include <string>
#include <unistd.h>
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace EDM {
namespace TEST {
class Utils {
public:
    static constexpr int32_t EDM_UID = 3057;
    static constexpr int32_t ROOT_UID = 0;
    static constexpr int32_t USERIAM_UID = 1088;
    static void ExecCmdSync(const std::string &cmd);
    static void SetNativeTokenTypeAndPermissions(const char* permissions[], int size);
    static void SetEdmInitialEnv();
    static void ResetTokenTypeAndUid();
    static bool GetEdmServiceState();
    static bool IsOriginalUTEnv();
    static void SetEdmServiceEnable();
    static void SetEdmServiceDisable();
    static void SetBluetoothEnable();
    static void SetBluetoothDisable();

private:
    static uint64_t selfTokenId_;
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_UTILS_H
