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
#include "iptables_rule_plugin.h"
#undef private
#include <gtest/gtest.h>

#include "edm_ipc_interface_code.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class IptablesRulePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);

    void ResetIptablesRule();
};

void IptablesRulePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void IptablesRulePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

void IptablesRulePluginTest::ResetIptablesRule()
{
    IPTABLES::RemoveFilter removeFilter;
    removeFilter.direction = IPTABLES::Direction::INPUT;
    MessageParcel removeData;
    MessageParcel removeReply;
    IPTABLES::IptablesUtils::WriteRemoveFilterConfig(removeFilter, removeData);
    HandlePolicyData handlePolicyData{"TestString", false};
    std::uint32_t removeFuncCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::IPTABLES_RULE);
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    plugin->OnHandlePolicy(removeFuncCode, removeData, removeReply, handlePolicyData, DEFAULT_USER_ID);

    IPTABLES::RemoveFilter remoutOutFilter;
    remoutOutFilter.direction = IPTABLES::Direction::OUTPUT;
    MessageParcel removeOutData;
    IPTABLES::IptablesUtils::WriteRemoveFilterConfig(remoutOutFilter, removeOutData);
    plugin->OnHandlePolicy(removeFuncCode, removeOutData, removeReply, handlePolicyData, DEFAULT_USER_ID);
}

/**
 * @tc.name: TestIptablesRulePluginErrorFuncCode
 * @tc.desc: Test IptablesRulePlugin::OnSetPolicy error funccode.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestIptablesRulePluginErrorFuncCode, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, EdmInterfaceCode::IPTABLES_RULE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestIptablesRulePluginSetFunction
 * @tc.desc: Test IptablesRulePlugin::OnHandlePolicy set function.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestIptablesRulePluginSetFunction, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    IPTABLES::AddFilter addFilter;
    MessageParcel data;
    MessageParcel reply;
    IPTABLES::IptablesUtils::WriteAddFilterConfig(addFilter, data);
    HandlePolicyData handlePolicyData{"TestString", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::IPTABLES_RULE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestIptablesRulePluginRemoveFunction
 * @tc.desc: Test IptablesRulePlugin::OnHandlePolicy remove function.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestIptablesRulePluginRemoveFunction, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    IPTABLES::RemoveFilter filter;
    MessageParcel data;
    MessageParcel reply;
    IPTABLES::IptablesUtils::WriteRemoveFilterConfig(filter, data);
    HandlePolicyData handlePolicyData{"TestString", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::IPTABLES_RULE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestIptablesRulePlugingGetPolicy
 * @tc.desc: Test OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestIptablesRulePlugingGetPolicy, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    std::string policyData{"TestString"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddIptablesFilterRule
 * @tc.desc: Test IptablesRulePlugin::OnHandlePolicy test AddIptablesFilterRule
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestAddIptablesFilterRule, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    IPTABLES::AddFilter addFilter;
    addFilter.action = IPTABLES::Action::DENY;
    addFilter.direction = IPTABLES::Direction::INPUT;
    addFilter.method = IPTABLES::AddMethod::INSERT;
    addFilter.protocol = IPTABLES::Protocol::ICMP;
    addFilter.ruleNo = 1;
    addFilter.uid = "20230000";
    addFilter.srcAddr = "192.192.192.192-202.202.202.202";
    addFilter.destAddr = "203.203.203.203";
    addFilter.srcPort = "999";
    addFilter.destPort = "888";
    MessageParcel data;
    MessageParcel reply;
    IPTABLES::IptablesUtils::WriteAddFilterConfig(addFilter, data);
    HandlePolicyData handlePolicyData{"TestString", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::IPTABLES_RULE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);

    ResetIptablesRule();
}

/**
 * @tc.name: TestRemoveIptablesFilterRule
 * @tc.desc: Test IptablesRulePlugin::OnHandlePolicy test RemoveIptablesFilterRule.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestRemoveIptablesFilterRule, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    IPTABLES::RemoveFilter filter;
    filter.action = IPTABLES::Action::DENY;
    filter.direction = IPTABLES::Direction::INPUT;
    filter.protocol = IPTABLES::Protocol::TCP;
    filter.srcAddr = "192.192.192.192";
    filter.srcPort = "9090";
    filter.destAddr = "192.192.192.1929999";
    filter.destPort = "errorport";
    MessageParcel data;
    MessageParcel reply;
    IPTABLES::IptablesUtils::WriteRemoveFilterConfig(filter, data);
    HandlePolicyData handlePolicyData{"TestString", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::IPTABLES_RULE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestExecRemoveFilterIptablesCommand
 * @tc.desc: Test IptablesRulePlugin::OnHandlePolicy test ExecRemoveFilterIptablesCommand.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestExecRemoveFilterIptablesCommand, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    IPTABLES::RemoveFilter filter;
    filter.direction = IPTABLES::Direction::INVALID;
    MessageParcel data;
    MessageParcel reply;
    IPTABLES::IptablesUtils::WriteRemoveFilterConfig(filter, data);
    HandlePolicyData handlePolicyData{"TestString", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::IPTABLES_RULE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicyExecRemoveFilterBySimpleCommand
 * @tc.desc: Test IptablesRulePlugin::OnHandlePolicy test ExecRemoveFilterBySimpleCommand.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestOnHandlePolicyExecRemoveFilterBySimpleCommand, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    IPTABLES::RemoveFilter filter;
    filter.direction = IPTABLES::Direction::INPUT;
    MessageParcel data;
    MessageParcel reply;
    IPTABLES::IptablesUtils::WriteRemoveFilterConfig(filter, data);
    HandlePolicyData handlePolicyData{"TestString", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::IPTABLES_RULE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestExecRemoveFilterBySimpleCommand
 * @tc.desc: Test IptablesRulePlugin ExecRemoveFilterBySimpleCommand.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestExecRemoveFilterBySimpleCommand, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    std::string command;
    ErrCode ret = plugin->ExecRemoveFilterBySimpleCommand(IPTABLES::Direction::INPUT);
    ASSERT_TRUE(ret == ERR_OK);
    ret = plugin->ExecRemoveFilterBySimpleCommand(IPTABLES::Direction::OUTPUT);
    ASSERT_TRUE(ret == ERR_OK);
    ret = plugin->ExecRemoveFilterBySimpleCommand(IPTABLES::Direction::INVALID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestExecRemoveFilterByDetailedCommand
 * @tc.desc: Test IptablesRulePlugin::OnHandlePolicy test ExecRemoveFilterByDetailedCommand.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestExecRemoveFilterByDetailedCommand, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    IPTABLES::RemoveFilter filter;
    filter.action = IPTABLES::Action::DENY;
    filter.direction = IPTABLES::Direction::INPUT;
    filter.protocol = IPTABLES::Protocol::TCP;
    filter.srcAddr = "192.192.192.192";
    filter.srcPort = "9090";
    filter.destAddr = "192.192.192.1929999";
    filter.destPort = "errorport";
    MessageParcel data;
    MessageParcel reply;
    IPTABLES::IptablesUtils::WriteRemoveFilterConfig(filter, data);
    HandlePolicyData handlePolicyData{"TestString", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::IPTABLES_RULE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestConvertChainCommand
 * @tc.desc: Test IptablesRulePlugin::OnHandlePolicy test ConvertChainCommand.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestConvertChainCommand, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    std::string command;
    bool ret = plugin->ConvertChainCommand(IPTABLES::Action::ALLOW, IPTABLES::Direction::INPUT, command);
    ASSERT_TRUE(ret);
    ret = plugin->ConvertChainCommand(IPTABLES::Action::ALLOW, IPTABLES::Direction::OUTPUT, command);
    ASSERT_TRUE(ret);
    ret = plugin->ConvertChainCommand(IPTABLES::Action::DENY, IPTABLES::Direction::INPUT, command);
    ASSERT_TRUE(ret);
    ret = plugin->ConvertChainCommand(IPTABLES::Action::DENY, IPTABLES::Direction::OUTPUT, command);
    ASSERT_TRUE(ret);
    ret = plugin->ConvertChainCommand(IPTABLES::Action::INVALID, IPTABLES::Direction::INVALID, command);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestConvertProtocolCommand
 * @tc.desc: Test IptablesRulePlugin::ConvertProtocolCommand
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestConvertProtocolCommand, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    std::string command1;
    plugin->ConvertProtocolCommand(IPTABLES::Protocol::ALL, command1);
    ASSERT_TRUE(command1 == " -p all");

    std::string command2;
    plugin->ConvertProtocolCommand(IPTABLES::Protocol::TCP, command2);
    ASSERT_TRUE(command2 == " -p tcp");

    std::string command3;
    plugin->ConvertProtocolCommand(IPTABLES::Protocol::UDP, command3);
    ASSERT_TRUE(command3 == " -p udp");

    std::string command4;
    plugin->ConvertProtocolCommand(IPTABLES::Protocol::ICMP, command4);
    ASSERT_TRUE(command4 == " -p icmp");

    std::string command5;
    plugin->ConvertProtocolCommand(IPTABLES::Protocol::INVALID, command5);
    ASSERT_TRUE(command5.empty());
}

/**
 * @tc.name: TestConvertActionCommand
 * @tc.desc: Test IptablesRulePlugin::ConvertActionCommand
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestConvertActionCommand, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    std::string command1;
    bool ret = plugin->ConvertActionCommand(IPTABLES::Action::ALLOW, command1);
    ASSERT_TRUE(command1 == " -j ACCEPT");
    ASSERT_TRUE(ret);

    std::string command2;
    ret = plugin->ConvertActionCommand(IPTABLES::Action::DENY, command2);
    ASSERT_TRUE(command2 == " -j REJECT");
    ASSERT_TRUE(ret);
    std::string command3;
    ret = plugin->ConvertActionCommand(IPTABLES::Action::INVALID, command3);
    ASSERT_TRUE(command3.empty());
    ASSERT_FALSE(ret);
}
/**
 * @tc.name: TestConvertIpAddressCommand
 * @tc.desc: Test IptablesRulePlugin::ConvertIpAddressCommand
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestConvertIpAddressCommand, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    std::string command1;
    std::string value;
    plugin->ConvertIpAddressCommand(value, true, command1);
    ASSERT_TRUE(command1.empty());

    std::string command2;
    value = "192.168.1.1";
    plugin->ConvertIpAddressCommand(value, true, command2);
    ASSERT_TRUE(command2 == (" -s " + value));

    std::string command3;
    value = "192.168.1.1-192.168.2.30";
    plugin->ConvertIpAddressCommand(value, true, command3);
    ASSERT_TRUE(command3 == (" -m iprange --src-range " + value));

    std::string command4;
    value = "192.168.1.1";
    plugin->ConvertIpAddressCommand(value, false, command4);
    ASSERT_TRUE(command4 == (" -d " + value));

    std::string command5;
    value = "192.168.1.1-192.168.2.30";
    plugin->ConvertIpAddressCommand(value, false, command5);
    ASSERT_TRUE(command5 == (" -m iprange --dst-range " + value));
}

/**
 * @tc.name: TestConvertPortCommand
 * @tc.desc: Test IptablesRulePlugin::ConvertPortCommand
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestConvertPortCommand, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    std::string command1;
    std::string value;
    plugin->ConvertPortCommand(value, true, command1);
    ASSERT_TRUE(command1.empty());

    std::string command2;
    value = "8989";
    plugin->ConvertPortCommand(value, true, command2);
    ASSERT_TRUE(command2 == (" --sport " + value));

    std::string command3;
    value = "8989";
    plugin->ConvertPortCommand(value, false, command3);
    ASSERT_TRUE(command3 == (" --dport " + value));
}
/**
 * @tc.name: TestConvertUidCommand
 * @tc.desc: Test IptablesRulePlugin::ConvertUidCommand
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestConvertUidCommand, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    std::string command1;
    std::string uid;
    plugin->ConvertUidCommand(uid, command1);
    ASSERT_TRUE(command1.empty());

    std::string command2;
    uid = "8989";
    plugin->ConvertUidCommand(uid, command2);
    ASSERT_TRUE(command2 == (" -m owner --uid-owner " + uid));
}

/**
 * @tc.name: TestConvertRuleNoCommand
 * @tc.desc: Test IptablesRulePlugin::ConvertRuleNoCommand
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestConvertRuleNoCommand, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    std::string command1;
    uint32_t ruleNo = 10000;
    plugin->ConvertRuleNoCommand(IPTABLES::AddMethod::APPEND, ruleNo, command1);
    ASSERT_TRUE(command1.empty());

    plugin->ConvertRuleNoCommand(IPTABLES::AddMethod::INSERT, ruleNo, command1);
    ASSERT_TRUE(command1 == (" " + std::to_string(ruleNo)));
}

/**
 * @tc.name: TestConvertAddFilterToIptablesCommand
 * @tc.desc: Test IptablesRulePlugin::ConvertAddFilterToIptablesCommand must specify action and direction
 * @tc.type: FUNC
 */
HWTEST_F(IptablesRulePluginTest, TestConvertAddFilterToIptablesCommand, TestSize.Level1)
{
    std::shared_ptr<IptablesRulePlugin> plugin = std::make_shared<IptablesRulePlugin>();
    IPTABLES::AddFilter addFilter;
    addFilter.method = IPTABLES::AddMethod::APPEND;
    std::string command;
    bool ret = plugin->ConvertAddFilterToIptablesCommand(addFilter, command);
    ASSERT_FALSE(ret);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS