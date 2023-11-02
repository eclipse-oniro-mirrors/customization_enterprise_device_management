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

#define private public
#define protected public
#include "domain_dao.h"
#include "rule_executer.h"
#undef protected
#undef private

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rule_executer_mock.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::EDM::IPTABLES;

using ::testing::Return;
using ::testing::DoAll;
using ::testing::Invoke;

namespace OHOS {
namespace EDM {
namespace IPTABLES {
namespace TEST {

class DomainDaoTest : public testing::Test {
public:
    std::shared_ptr<RuleExecuterMock> ruleExecuterMock;

protected:
    void SetUp() override;
};

void DomainDaoTest::SetUp()
{
    ruleExecuterMock = std::make_shared<RuleExecuterMock>();
    RuleExecuter::instance_ = ruleExecuterMock;
}

HWTEST_F(DomainDaoTest, TestInit, TestSize.Level1)
{
    EXPECT_CALL(*ruleExecuterMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    DomainDao initOk{"chainName"};
    EXPECT_TRUE(initOk.Init() == ERR_OK);

    EXPECT_CALL(*ruleExecuterMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(-1)));
    DomainDao initFail{"chainName"};
    EXPECT_FALSE(initFail.Init() == ERR_OK);
}
} // namespace TEST
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS