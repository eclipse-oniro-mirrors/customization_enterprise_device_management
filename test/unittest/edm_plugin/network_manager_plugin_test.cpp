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

#include <gtest/gtest.h>
#include "disabled_network_interface_plugin.h"
#include "get_all_network_interfaces_plugin.h"
#include "get_ip_address_plugin.h"
#include "get_mac_plugin.h"
#include "iplugin_manager.h"
#include "iplugin_template.h"
#include "map_string_serializer.h"
#include "policy_info.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string VALID_NETWORK_INTERFACE = "lo";
const std::string INVALID_NETWORK_INTERFACE = "fail";

class NetworkManagerPluginTest : public testing::Test {
protected:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);
};

void NetworkManagerPluginTest::SetUpTestCase(void)
{
    Utils::SetEdmInitialEnv();
}

void NetworkManagerPluginTest::TearDownTestCase(void)
{
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestGetAllNetworkInterfaces
 * @tc.desc: Test GetAllNetworkInterfacesPlugin.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerPluginTest, TestGetAllNetworkInterfaces, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = GetAllNetworkInterfacesPlugin::GetPlugin();
    std::string policyData{"TestGetAllNetworkInterfaces"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetIpAddress
 * @tc.desc: Test GetIpAddressPlugin.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerPluginTest, TestGetIpAddress, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = GetIpAddressPlugin::GetPlugin();
    std::string policyData{"TestGetIpAddress"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetMac
 * @tc.desc: Test GetMacPlugin.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerPluginTest, TestGetMac, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = GetMacPlugin::GetPlugin();
    std::string policyData{"TestGetMac"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestIsNetworkInterfaceDisabled
 * @tc.desc: Test IsNetworkInterfaceDisabled fail.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerPluginTest, TestIsNetworkInterfaceDisabledFail, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisabledNetworkInterfacePlugin::GetPlugin();
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    // NetworkInterface is not exist.
    data.WriteString(INVALID_NETWORK_INTERFACE);
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestIsNetworkInterfaceDisabled
 * @tc.desc: Test IsNetworkInterfaceDisabled success.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerPluginTest, TestIsNetworkInterfaceDisabledSuc, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisabledNetworkInterfacePlugin::GetPlugin();
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    // NetworkInterface is exist.
    data.WriteString(VALID_NETWORK_INTERFACE);
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestNetworkInterfaceNotExist
 * @tc.desc: Test SetNetworkInterfaceDisabled when NetworkInterface is not exist.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerPluginTest, TestNetworkInterfaceNotExist, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisabledNetworkInterfacePlugin::GetPlugin();
    bool isChanged = false;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, DISABLED_NETWORK_INTERFACE);
    // data is empty.
    MessageParcel data;
    MessageParcel reply;
    std::string policyStr;
    ErrCode ret = plugin->OnHandlePolicy(code, data, policyStr, isChanged, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
    // NetworkInterface is invalid.
    std::vector<std::string> key { INVALID_NETWORK_INTERFACE };
    std::vector<std::string> value { "true" };
    data.WriteStringVector(key);
    data.WriteStringVector(value);
    ret = plugin->OnHandlePolicy(code, data, policyStr, isChanged, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestNetworkInterfaceDisabled
 * @tc.desc: Test SetNetworkInterfaceDisabled when set network interface disabled.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerPluginTest, TestNetworkInterfaceDisabled, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisabledNetworkInterfacePlugin::GetPlugin();
    bool isChanged = false;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, DISABLED_NETWORK_INTERFACE);
    MessageParcel data;
    MessageParcel reply;
    std::string policyStr;
    // set network interface disabled.
    std::vector<std::string> key { VALID_NETWORK_INTERFACE };
    std::vector<std::string> value { "true" };
    data.WriteStringVector(key);
    data.WriteStringVector(value);
    ErrCode ret = plugin->OnHandlePolicy(code, data, policyStr, isChanged, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    // get policy.
    data.WriteString(VALID_NETWORK_INTERFACE);
    ret = plugin->OnGetPolicy(policyStr, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadBool());
    // set network interface enabled.
    value = { "false" };
    data.WriteStringVector(key);
    data.WriteStringVector(value);
    ret = plugin->OnHandlePolicy(code, data, policyStr, isChanged, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    // get policy.
    data.WriteString(VALID_NETWORK_INTERFACE);
    ret = plugin->OnGetPolicy(policyStr, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_FALSE(reply.ReadBool());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS