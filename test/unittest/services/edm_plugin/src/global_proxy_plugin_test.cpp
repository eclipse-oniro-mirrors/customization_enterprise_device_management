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

#include "edm_ipc_interface_code.h"
#include "global_proxy_plugin.h"
#include "iplugin_manager.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {


class GlobalProxyPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void GlobalProxyPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void GlobalProxyPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestSetGlobalHttpProxyParamError
 * @tc.desc: Test SetGlobalHttpProxy
 * @tc.type: FUNC
 */
HWTEST_F(GlobalProxyPluginTest, TestSetGlobalHttpProxyParamError, TestSize.Level1)
{
    GlobalProxyPlugin plugin;
    NetManagerStandard::HttpProxy httpProxy;
    httpProxy.SetPort(9090);
    httpProxy.SetHost("192.168.1.1");
    std::list<std::string> list = {"192.168.2.2", "baidu.com"};
    httpProxy.SetExclusionList(list);
    ErrCode ret = plugin.OnSetPolicy(httpProxy);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetGlobalHttpProxyAnyParam
 * @tc.desc: Test SetGlobalHttpProxy
 * @tc.type: FUNC
 */
HWTEST_F(GlobalProxyPluginTest, TestSetGlobalHttpProxyAnyParam, TestSize.Level1)
{
    GlobalProxyPlugin plugin;
    NetManagerStandard::HttpProxy httpProxy;
    httpProxy.SetPort(1234);
    httpProxy.SetHost("any host");
    std::list<std::string> list = {"any list", "any list2"};
    httpProxy.SetExclusionList(list);
    ErrCode ret = plugin.OnSetPolicy(httpProxy);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetGlobalHttpProxyEmpty
 * @tc.desc: Test SetGlobalHttpProxy
 * @tc.type: FUNC
 */
HWTEST_F(GlobalProxyPluginTest, TestSetGlobalHttpProxyEmpty, TestSize.Level1)
{
    GlobalProxyPlugin plugin;
    NetManagerStandard::HttpProxy httpProxy;
    ErrCode ret = plugin.OnSetPolicy(httpProxy);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetGlobalHttpProxy
 * @tc.desc: Test GetGlobalHttpProxy
 * @tc.type: FUNC
 */
HWTEST_F(GlobalProxyPluginTest, TestGetGlobalHttpProxy, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = GlobalProxyPlugin::GetPlugin();
    MessageParcel data;
    MessageParcel reply;
    std::string policyStr;
    ErrCode ret = plugin->OnGetPolicy(policyStr, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS