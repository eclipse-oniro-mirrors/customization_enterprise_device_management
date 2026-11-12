/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "install_market_apps_plugin.h"

#include <gtest/gtest.h>
#include "utils.h"
#include <message_parcel.h>

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "iplugin.h"
#include "install_market_apps_serializer.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class InstallMarketAppsPluginTest : public testing::Test {};

/**
 * @tc.name: TestOnSetPolicy
 * @tc.desc: Test InstallMarketAppsPlugin::OnSetPolicy is not supported.
 * @tc.type: FUNC
 */
HWTEST_F(InstallMarketAppsPluginTest, TestOnSetPolicy, TestSize.Level1)
{
    InstallMarketAppsPlugin plugin;
    InstallMarketAppsInfo info;
    ErrCode ret = plugin.OnSetPolicy(info);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test InstallMarketAppsPlugin::OnGetPolicy reports unsupported in the reply too.
 * @tc.type: FUNC
 */
HWTEST_F(InstallMarketAppsPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    InstallMarketAppsPlugin plugin;
    std::string value;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin.OnGetPolicy(value, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestPluginAttributes
 * @tc.desc: Test InstallMarketAppsPlugin code and policy name.
 * @tc.type: FUNC
 */
HWTEST_F(InstallMarketAppsPluginTest, TestPluginAttributes, TestSize.Level1)
{
    auto plugin = InstallMarketAppsPlugin::GetPlugin();
    ASSERT_NE(plugin, nullptr);
    EXPECT_EQ(plugin->GetCode(), EdmInterfaceCode::INSTALL_MARKET_APPS);
    EXPECT_EQ(plugin->GetPolicyName(), "INSTALL_MARKET_APPS");
}

/**
 * @tc.name: TestSingletonIsStable
 * @tc.desc: Test GetPlugin returns the same instance on repeated calls.
 * @tc.type: FUNC
 */
HWTEST_F(InstallMarketAppsPluginTest, TestSingletonIsStable, TestSize.Level1)
{
    auto first = InstallMarketAppsPlugin::GetPlugin();
    auto second = InstallMarketAppsPlugin::GetPlugin();
    EXPECT_EQ(first.get(), second.get());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
