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

#include <fcntl.h>
#include <unistd.h>
#include <gtest/gtest.h>

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "iplugin.h"
#include "message_parcel.h"
#include "set_wall_paper_plugin.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class SetWallPaperPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void SetWallPaperPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void SetWallPaperPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestOnSetPolicyInvalidFd
 * @tc.desc: Test SetWallPaperPlugin::OnSetPolicy skips fd release when the fd is absent.
 * @tc.type: FUNC
 */
HWTEST_F(SetWallPaperPluginTest, TestOnSetPolicyInvalidFd, TestSize.Level1)
{
    SetWallPaperPlugin plugin;
    WallPaperParam data;
    data.isHomeWallPaper = true;
    data.fd = -1;
    ErrCode ret = plugin.OnSetPolicy(data);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    EXPECT_EQ(data.fd, -1);
}

/**
 * @tc.name: TestOnSetPolicyValidFd
 * @tc.desc: Test SetWallPaperPlugin::OnSetPolicy closes the incoming fd and resets it to -1.
 * @tc.type: FUNC
 */
HWTEST_F(SetWallPaperPluginTest, TestOnSetPolicyValidFd, TestSize.Level1)
{
    SetWallPaperPlugin plugin;
    int32_t fd = ::open("/dev/null", O_RDONLY);
    if (fd < 0) {
        GTEST_SKIP() << "open /dev/null failed";
    }
    WallPaperParam data;
    data.isHomeWallPaper = false;
    data.fd = fd;
    ErrCode ret = plugin.OnSetPolicy(data);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    EXPECT_EQ(data.fd, -1);
    if (::fcntl(fd, F_GETFL) != -1) {
        ::close(fd);
    }
}

/**
 * @tc.name: TestPluginAttributes
 * @tc.desc: Test SetWallPaperPlugin policy code and policy name.
 * @tc.type: FUNC
 */
HWTEST_F(SetWallPaperPluginTest, TestPluginAttributes, TestSize.Level1)
{
    auto plugin = SetWallPaperPlugin::GetPlugin();
    ASSERT_NE(plugin, nullptr);
    EXPECT_EQ(plugin->GetCode(), EdmInterfaceCode::SET_WALL_PAPER);
    EXPECT_EQ(plugin->GetPolicyName(), PolicyName::POLICY_SET_WALL_PAPER);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
