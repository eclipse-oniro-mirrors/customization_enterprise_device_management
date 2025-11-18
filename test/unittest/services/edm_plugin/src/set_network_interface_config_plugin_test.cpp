/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "set_network_interface_config_plugin.h"

#include <gtest/gtest.h>

#include "edm_data_ability_utils_mock.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "utils.h"
#include "network_address.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class SetNetworkInterfaceConfigPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void SetNetworkInterfaceConfigPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void SetNetworkInterfaceConfigPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}


/**
 * @tc.name: TestSetEthernetConfigSuccess_001
 * @tc.desc: Test SetNetworkInterfaceConfigPlugin::OnHandlePolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(SetNetworkInterfaceConfigPluginTest, TestSetEthernetConfigSuccess_001, TestSize.Level1)
{
    std::shared_ptr<SetNetworkInterfaceConfigPlugin> plugin = std::make_shared<SetNetworkInterfaceConfigPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::SET_NETWORK_INTERFACE_CONFIG);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    InterfaceConfig config = {IpSetMode::STATIC, "192.168.1.50", "192.168.1.1",
        "255.255.255.0", "192.168.1.1"};
    data.WriteString("eth0");
    data.WriteInt32(static_cast<int32_t>(config.ipSetMode));
    data.WriteString(config.ipAddress);
    data.WriteString(config.gateway);
    data.WriteString(config.netMask);
    data.WriteString(config.dnsServers);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK || EdmReturnErrCode::ETHERNET_CONFIGURATION_FAILED);
}

/**
 * @tc.name: TestSetEthernetConfigSuccess_002
 * @tc.desc: Test SetNetworkInterfaceConfigPlugin::OnHandlePolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(SetNetworkInterfaceConfigPluginTest, TestSetEthernetConfigSuccess_002, TestSize.Level1)
{
    std::shared_ptr<SetNetworkInterfaceConfigPlugin> plugin = std::make_shared<SetNetworkInterfaceConfigPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::SET_NETWORK_INTERFACE_CONFIG);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    InterfaceConfig config = {IpSetMode::DHCP, "192.168.1.50", "192.168.1.1",
        "255.255.255.0", "192.168.1.1"};
    data.WriteString("eth0");
    data.WriteInt32(static_cast<int32_t>(config.ipSetMode));
    data.WriteString(config.ipAddress);
    data.WriteString(config.gateway);
    data.WriteString(config.netMask);
    data.WriteString(config.dnsServers);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::ETHERNET_CONFIGURATION_FAILED);
}

/**
 * @tc.name: TestSetEthernetConfigFailed_001
 * @tc.desc: Test SetNetworkInterfaceConfigPlugin::OnHandlePolicy function failed.
 * @tc.type: FUNC
 */
HWTEST_F(SetNetworkInterfaceConfigPluginTest, TestSetEthernetConfigFailed_001, TestSize.Level1)
{
    std::shared_ptr<SetNetworkInterfaceConfigPlugin> plugin = std::make_shared<SetNetworkInterfaceConfigPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET,
        EdmInterfaceCode::SET_NETWORK_INTERFACE_CONFIG);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    InterfaceConfig config = {IpSetMode::DHCP, "192.168.1.50", "192.168.1.1",
        "255.255.255.0", "192.168.1.1"};
    data.WriteString("eth0");
    data.WriteInt32(static_cast<int32_t>(config.ipSetMode));
    data.WriteString(config.ipAddress);
    data.WriteString(config.gateway);
    data.WriteString(config.netMask);
    data.WriteString(config.dnsServers);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestSetEthernetConfigFailed_002
 * @tc.desc: Test SetNetworkInterfaceConfigPlugin::OnHandlePolicy function failed.
 * @tc.type: FUNC
 */
HWTEST_F(SetNetworkInterfaceConfigPluginTest, TestSetEthernetConfigFailed_002, TestSize.Level1)
{
    std::shared_ptr<SetNetworkInterfaceConfigPlugin> plugin = std::make_shared<SetNetworkInterfaceConfigPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::SET_NETWORK_INTERFACE_CONFIG);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    InterfaceConfig config = {IpSetMode::INVALID, "192.168.1.50", "192.168.1.1",
        "255.255.255.0", "192.168.1.1"};
    data.WriteString("eth0");
    data.WriteInt32(static_cast<int32_t>(config.ipSetMode));
    data.WriteString(config.ipAddress);
    data.WriteString(config.gateway);
    data.WriteString(config.netMask);
    data.WriteString(config.dnsServers);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestSetEthernetConfigFailed_003
 * @tc.desc: Test SetNetworkInterfaceConfigPlugin::OnHandlePolicy function failed.
 * @tc.type: FUNC
 */
HWTEST_F(SetNetworkInterfaceConfigPluginTest, TestSetEthernetConfigFailed_003, TestSize.Level1)
{
    std::shared_ptr<SetNetworkInterfaceConfigPlugin> plugin = std::make_shared<SetNetworkInterfaceConfigPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::SET_NETWORK_INTERFACE_CONFIG);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    InterfaceConfig config = {IpSetMode::STATIC, "192.168.1.50", "192.168.1.1",
        "255.255.255.0", "192.168.1.1,aaaaa"};
    data.WriteString("eth0");
    data.WriteInt32(static_cast<int32_t>(config.ipSetMode));
    data.WriteString(config.ipAddress);
    data.WriteString(config.gateway);
    data.WriteString(config.netMask);
    data.WriteString(config.dnsServers);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS