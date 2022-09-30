/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <string>
#include <vector>
#include "cmd_utils.h"
#include "func_code.h"
#include "iplugin_mock.h"
#include "policy_info.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class IPluginTest : public testing::Test {
protected:
    void SetUp() override {}

    void TearDown() override {}
};

/**
 * @tc.name: TestIsGlobalPolicy
 * @tc.desc: Test IsGlobalPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(IPluginTest, TestIsGlobalPolicy, TestSize.Level1)
{
    IPluginMock iplugin1;
    EXPECT_TRUE(iplugin1.IsGlobalPolicy());
    iplugin1.MockSetPolicyName("test");
    std::string mergeJsonData;
    ErrCode err = iplugin1.MergePolicyData("com.edm.test.demo", mergeJsonData);
    EXPECT_TRUE(err == ERR_OK);
    MessageParcel reply;
    err = iplugin1.WritePolicyToParcel("name:test", reply);
    EXPECT_TRUE(err == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS