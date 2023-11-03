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
#ifndef TEST_UNITTEST_EDM_PLUGIN_INCLUDE_NETWORKMANAGER_IPTABLES_SERVICES_TEST_H
#define TEST_UNITTEST_EDM_PLUGIN_INCLUDE_NETWORKMANAGER_IPTABLES_SERVICES_TEST_H

#define private public
#define protected public
#include "iptables_service.h"
#undef protected
#undef private

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#define private public
#define protected public
#include "rule_executer.h"
#undef protected
#undef private

#include "rule_executer_mock.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {
namespace TEST {
class IptablesSereviceTest : public testing::Test {
public:
    std::shared_ptr<RuleExecuterMock> ruleExecuterMock;
    std::shared_ptr<IptablesService> iptablesService;

protected:
    void SetUp() override;
    void TearDown() override;
};
} // namespace TEST
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS

#endif // TEST_UNITTEST_EDM_PLUGIN_INCLUDE_NETWORKMANAGER_IPTABLES_SERVICES_TEST_H