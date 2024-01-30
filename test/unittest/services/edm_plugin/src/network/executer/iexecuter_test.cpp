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
#include "executer_utils.h"
#include "iexecuter.h"
#undef protected
#undef private

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "domain_chain_rule.h"
#include "executer_utils_mock.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::EDM::IPTABLES;

using ::testing::Return;
using ::testing::DoAll;
using ::testing::SetArgPointee;
using ::testing::SetArgReferee;
using ::testing::SaveArg;
using ::testing::Invoke;

namespace OHOS {
namespace EDM {
namespace IPTABLES {
namespace TEST {

class IExecuterMock final: public IExecuter {
public:
    ErrCode Init() override
    {
        return ERR_OK;
    }
};

class IExecuterTest : public testing::Test {
public:
    std::shared_ptr<ExecuterUtilsMock> executerUtilsMock;

protected:
    void SetUp() override;
};

void IExecuterTest::SetUp()
{
    executerUtilsMock = std::make_shared<ExecuterUtilsMock>();
    ExecuterUtils::instance_ = executerUtilsMock;
}

/**
 * @tc.name: TestInit
 * @tc.desc: Test Init func.
 * @tc.type: FUNC
 */
HWTEST_F(IExecuterTest, TestInit, TestSize.Level1)
{
    std::shared_ptr<IExecuter> executer = std::make_shared<IExecuterMock>();
    EXPECT_TRUE(executer->Init() == ERR_OK);
}

/**
 * @tc.name: TestInit
 * @tc.desc: Test CreateChain func.
 * @tc.type: FUNC
 */
HWTEST_F(IExecuterTest, TestCreateChain, TestSize.Level1)
{
    std::shared_ptr<IExecuter> executer = std::make_shared<IExecuterMock>();

    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(executer->CreateChain() == ERR_OK);

    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(-1)));
    EXPECT_FALSE(executer->CreateChain() == ERR_OK);
}

/**
 * @tc.name: TestAdd
 * @tc.desc: Test Add func.
 * @tc.type: FUNC
 */
HWTEST_F(IExecuterTest, TestAdd, TestSize.Level1)
{
    std::shared_ptr<IExecuter> executer = std::make_shared<IExecuterMock>();

    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(executer->Add(nullptr) != ERR_OK);

    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(-1)));
    EXPECT_TRUE(executer->Add(nullptr) != ERR_OK);

    DomainFilterRule domainFilterRule{Action::ALLOW, "9999", "www.example.com"};
    std::shared_ptr<ChainRule> rule = std::make_shared<DomainChainRule>(domainFilterRule);
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(executer->Add(rule) == ERR_OK);

    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(-1)));
    EXPECT_FALSE(executer->Add(rule) == ERR_OK);

    domainFilterRule = {Action::DENY, "9999", "www.example.com"};
    rule = std::make_shared<DomainChainRule>(domainFilterRule);
    EXPECT_CALL(*executerUtilsMock, Execute)
        .Times(2)
        .WillOnce(DoAll(Invoke(PrintExecRule), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(executer->Add(rule) == ERR_OK);
}

/**
 * @tc.name: TestRemove
 * @tc.desc: Test Remove func.
 * @tc.type: FUNC
 */
HWTEST_F(IExecuterTest, TestRemove, TestSize.Level1)
{
    std::shared_ptr<IExecuter> executer = std::make_shared<IExecuterMock>();

    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(executer->Remove(nullptr) == ERR_OK);

    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(-1)));
    EXPECT_TRUE(executer->Remove(nullptr) != ERR_OK);

    DomainFilterRule domainFilterRule{Action::ALLOW, "9999", "www.example.com"};
    std::shared_ptr<ChainRule> rule = std::make_shared<DomainChainRule>(domainFilterRule);
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(executer->Remove(rule) == ERR_OK);

    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(-1)));
    EXPECT_FALSE(executer->Remove(rule) == ERR_OK);

    domainFilterRule = {Action::DENY, "9999", "www.example.com"};
    rule = std::make_shared<DomainChainRule>(domainFilterRule);
    EXPECT_CALL(*executerUtilsMock, Execute)
        .Times(2)
        .WillOnce(DoAll(Invoke(PrintExecRule), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(executer->Remove(rule) == ERR_OK);
}

/**
 * @tc.name: TestGetAll
 * @tc.desc: Test GetAll func.
 * @tc.type: FUNC
 */
HWTEST_F(IExecuterTest, TestGetAll, TestSize.Level1)
{
    std::shared_ptr<IExecuter> executer = std::make_shared<IExecuterMock>();
    std::vector<std::string> list;

    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(executer->GetAll(list) == ERR_OK);

    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(-1)));
    EXPECT_TRUE(executer->GetAll(list) != ERR_OK);

    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    std::string result =
        "Chain edm_deny_output (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination\n"
        "1        0     0 DROP       udp  --  *      *       0.0.0.0/0            10.1.1.1             "
        "source IP range 192.168.1.1-192.188.22.66 udp spt:8080 dpt:8080";
    EXPECT_CALL(*executerUtilsMock, Execute)
        .WillRepeatedly(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(result), Return(ERR_OK)));
    EXPECT_TRUE(executer->GetAll(list) == ERR_OK);
    EXPECT_TRUE(list.size() == 1);
}

/**
 * @tc.name: TestExecWithOption
 * @tc.desc: Test ExecWithOption func.
 * @tc.type: FUNC
 */
HWTEST_F(IExecuterTest, TestExecWithOption, TestSize.Level1)
{
    std::shared_ptr<IExecuter> executer = std::make_shared<IExecuterMock>();
    std::ostringstream oss{};
    DomainFilterRule domainFilterRule{Action::ALLOW, "9999", "www.example.com"};
    std::shared_ptr<ChainRule> rule = std::make_shared<DomainChainRule>(domainFilterRule);

    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(executer->ExecWithOption(oss, rule) == ERR_OK);

    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(-1)));
    EXPECT_TRUE(executer->ExecWithOption(oss, rule) != ERR_OK);

    domainFilterRule = {Action::DENY, "9999", "www.example.com"};
    rule = std::make_shared<DomainChainRule>(domainFilterRule);
    EXPECT_CALL(*executerUtilsMock, Execute)
        .Times(2)
        .WillOnce(DoAll(Invoke(PrintExecRule), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(executer->ExecWithOption(oss, rule) == ERR_OK);
}
} // namespace TEST
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS