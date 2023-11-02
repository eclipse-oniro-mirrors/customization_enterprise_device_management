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
#include "idao.h"
#include "rule_executer.h"
#undef protected
#undef private

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "domain_chain_rule.h"
#include "rule_executer_mock.h"

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

class IDaoMock final: public IDao {
public:
    ErrCode Init() override { return ERR_OK; }
};

class IDaoTest : public testing::Test {
public:
    std::shared_ptr<RuleExecuterMock> ruleExecuterMock;

protected:
    void SetUp() override;
};

void IDaoTest::SetUp()
{
    ruleExecuterMock = std::make_shared<RuleExecuterMock>();
    RuleExecuter::instance_ = ruleExecuterMock;
}

HWTEST_F(IDaoTest, TestInit, TestSize.Level1)
{
    std::shared_ptr<IDao> dao = std::make_shared<IDaoMock>();
    EXPECT_TRUE(dao->Init() == ERR_OK);
}

HWTEST_F(IDaoTest, TestCreateChain, TestSize.Level1)
{
    std::shared_ptr<IDao> dao = std::make_shared<IDaoMock>();

    EXPECT_CALL(*ruleExecuterMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(dao->CreateChain() == ERR_OK);

    EXPECT_CALL(*ruleExecuterMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(-1)));
    EXPECT_FALSE(dao->CreateChain() == ERR_OK);
}

HWTEST_F(IDaoTest, TestAdd, TestSize.Level1)
{
    std::shared_ptr<IDao> dao = std::make_shared<IDaoMock>();

    EXPECT_CALL(*ruleExecuterMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(dao->Add(nullptr) != ERR_OK);

    EXPECT_CALL(*ruleExecuterMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(-1)));
    EXPECT_TRUE(dao->Add(nullptr) != ERR_OK);

    DomainFilterRule domainFilterRule{Action::ALLOW, "9999", "www.example.com"};
    std::shared_ptr<ChainRule> rule = std::make_shared<DomainChainRule>(domainFilterRule);
    EXPECT_CALL(*ruleExecuterMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(dao->Add(rule) == ERR_OK);

    EXPECT_CALL(*ruleExecuterMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(-1)));
    EXPECT_FALSE(dao->Add(rule) == ERR_OK);

    domainFilterRule = {Action::DENY, "9999", "www.example.com"};
    rule = std::make_shared<DomainChainRule>(domainFilterRule);
    EXPECT_CALL(*ruleExecuterMock, Execute)
        .Times(2)
        .WillOnce(DoAll(Invoke(PrintExecRule), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(dao->Add(rule) == ERR_OK);
}

HWTEST_F(IDaoTest, TestRemove, TestSize.Level1)
{
    std::shared_ptr<IDao> dao = std::make_shared<IDaoMock>();

    EXPECT_CALL(*ruleExecuterMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(dao->Remove(nullptr) == ERR_OK);

    EXPECT_CALL(*ruleExecuterMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(-1)));
    EXPECT_TRUE(dao->Remove(nullptr) != ERR_OK);

    DomainFilterRule domainFilterRule{Action::ALLOW, "9999", "www.example.com"};
    std::shared_ptr<ChainRule> rule = std::make_shared<DomainChainRule>(domainFilterRule);
    EXPECT_CALL(*ruleExecuterMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(dao->Remove(rule) == ERR_OK);

    EXPECT_CALL(*ruleExecuterMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(-1)));
    EXPECT_FALSE(dao->Remove(rule) == ERR_OK);

    domainFilterRule = {Action::DENY, "9999", "www.example.com"};
    rule = std::make_shared<DomainChainRule>(domainFilterRule);
    EXPECT_CALL(*ruleExecuterMock, Execute)
        .Times(2)
        .WillOnce(DoAll(Invoke(PrintExecRule), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(dao->Remove(rule) == ERR_OK);
}

HWTEST_F(IDaoTest, TestGetAll, TestSize.Level1)
{
    std::shared_ptr<IDao> dao = std::make_shared<IDaoMock>();
    std::vector<std::string> list;

    EXPECT_CALL(*ruleExecuterMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(dao->GetAll(list) == ERR_OK);

    EXPECT_CALL(*ruleExecuterMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(-1)));
    EXPECT_TRUE(dao->GetAll(list) != ERR_OK);

    EXPECT_CALL(*ruleExecuterMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    std::string result =
        "Chain edm_deny_output (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination\n"
        "1        0     0 DROP       udp  --  *      *       0.0.0.0/0            10.1.1.1             source IP range 192.168.1.1-192.188.22.66 udp spt:8080 dpt:8080";
    EXPECT_CALL(*ruleExecuterMock, Execute)
        .WillRepeatedly(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(result), Return(ERR_OK)));
    EXPECT_TRUE(dao->GetAll(list) == ERR_OK);
    EXPECT_TRUE(list.size() == 1);
}

HWTEST_F(IDaoTest, TestExecWithOption, TestSize.Level1)
{
    std::shared_ptr<IDao> dao = std::make_shared<IDaoMock>();
    std::ostringstream oss{};
    DomainFilterRule domainFilterRule{Action::ALLOW, "9999", "www.example.com"};
    std::shared_ptr<ChainRule> rule = std::make_shared<DomainChainRule>(domainFilterRule);

    EXPECT_CALL(*ruleExecuterMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(dao->ExecWithOption(oss, rule) == ERR_OK);

    EXPECT_CALL(*ruleExecuterMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(-1)));
    EXPECT_TRUE(dao->ExecWithOption(oss, rule) != ERR_OK);

    domainFilterRule = {Action::DENY, "9999", "www.example.com"};
    rule = std::make_shared<DomainChainRule>(domainFilterRule);
    EXPECT_CALL(*ruleExecuterMock, Execute)
        .Times(2)
        .WillOnce(DoAll(Invoke(PrintExecRule), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    EXPECT_TRUE(dao->ExecWithOption(oss, rule) == ERR_OK);
}
} // namespace TEST
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS