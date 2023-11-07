/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef TEST_UNITTEST_EDM_PLUGIN_INCLUDE_NETWORK_EXECUTER_UTILS_MOCK_H
#define TEST_UNITTEST_EDM_PLUGIN_INCLUDE_NETWORK_EXECUTER_UTILS_MOCK_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "executer_utils.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {
namespace TEST {

class ExecuterUtilsMock final: public IPTABLES::ExecuterUtils {
public:
    MOCK_METHOD(ErrCode, Execute, (const std::string &rule, std::string &result), (override));
};

ErrCode PrintExecRule(const std::string &rule, std::string &result);

} // namespace TEST
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS

#endif // TEST_UNITTEST_EDM_PLUGIN_INCLUDE_NETWORK_EXECUTER_UTILS_MOCK_H

