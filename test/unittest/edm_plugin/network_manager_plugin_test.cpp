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
#include "get_all_network_interfaces_plugin.h"
#include "get_ip_address_plugin.h"
#include "get_mac_plugin.h"
#include "iplugin_template.h"
#include "iplugin_manager.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class NetworkManagerPluginTest : public testing::Test {
protected:
    void SetUp() override {}

    void TearDown() override {}
};

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
} // namespace TEST
} // namespace EDM
} // namespace OHOS