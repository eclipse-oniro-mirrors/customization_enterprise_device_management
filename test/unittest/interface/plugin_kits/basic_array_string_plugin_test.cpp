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

#include "basic_array_string_plugin.h"
#include "array_string_serializer.h"

#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
static constexpr int32_t USER_ID = 100;

class TestBasicArrayStringPlugin : public BasicArrayStringPlugin {
public:
    TestBasicArrayStringPlugin() : BasicArrayStringPlugin() {}
    using BasicArrayStringPlugin::OnBasicSetPolicy;
    using BasicArrayStringPlugin::BasicGetPolicy;
    using BasicArrayStringPlugin::OnBasicRemovePolicy;
    using BasicArrayStringPlugin::OnBasicAdminRemove;
    using BasicArrayStringPlugin::RemoveOtherModulePolicy;

    void SetMaxListSize(uint32_t size) { maxListSize_ = size; }
    void SetMockFailedData(std::vector<std::string> failedData) { mockFailedData_ = failedData; }
    ErrCode SetOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
        std::vector<std::string> &failedData) override
    {
        failedData = mockFailedData_;
        return ERR_OK;
    }
private:
    std::vector<std::string> mockFailedData_ = {};
};

class BasicArrayStringPluginTest : public testing::Test {
protected:
    void SetUp() override {}

    void TearDown() override {}
};
/**
 * @tc.name: TestOnBasicSetPolicy001
 * @tc.desc: Test BasicArrayStringPlugin::OnBasicSetPolicy func with data empty.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayStringPluginTest, TestOnBasicSetPolicy001, TestSize.Level1)
{
    TestBasicArrayStringPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    std::vector<std::string> data        = {};
    std::vector<std::string> currentData = {"1", "2", "3"};
    std::vector<std::string> mergeData   = {"1", "2", "3"};
    ErrCode ret = basicPlugin.OnBasicSetPolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnBasicSetPolicy002
 * @tc.desc: Test BasicArrayStringPlugin::OnBasicSetPolicy func with data over maxListSize_.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayStringPluginTest, TestOnBasicSetPolicy002, TestSize.Level1)
{
    TestBasicArrayStringPlugin basicPlugin;
    basicPlugin.SetMaxListSize(5);
    std::vector<std::string> data        = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"};
    std::vector<std::string> currentData = {};
    std::vector<std::string> mergeData   = {};
    ErrCode ret = basicPlugin.OnBasicSetPolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnBasicSetPolicy003
 * @tc.desc: Test BasicArrayStringPlugin::OnBasicSetPolicy func with afterMerge over maxListSize_.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayStringPluginTest, TestOnBasicSetPolicy003, TestSize.Level1)
{
    TestBasicArrayStringPlugin basicPlugin;
    basicPlugin.SetMaxListSize(5);
    std::vector<std::string> data        = {"4", "5", "6"};
    std::vector<std::string> currentData = {"1", "2", "3"};
    std::vector<std::string> mergeData   = {"1", "2", "3", "7", "8"};
    ErrCode ret = basicPlugin.OnBasicSetPolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnBasicSetPolicy004
 * @tc.desc: Test BasicArrayStringPlugin::OnBasicSetPolicy func with SetOtherModulePolicy and save.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayStringPluginTest, TestOnBasicSetPolicy004, TestSize.Level1)
{
    TestBasicArrayStringPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    std::vector<std::string> data        = {"3", "4"};
    std::vector<std::string> currentData = {"1", "2"};
    std::vector<std::string> mergeData   = {"1", "2"};
    ErrCode ret = basicPlugin.OnBasicSetPolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnBasicSetPolicy005
 * @tc.desc: Test BasicArrayStringPlugin::OnBasicSetPolicy func with failedData.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayStringPluginTest, TestOnBasicSetPolicy005, TestSize.Level1)
{
    TestBasicArrayStringPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    basicPlugin.SetMockFailedData({"4"});
    std::vector<std::string> data        = {"4", "5"};
    std::vector<std::string> currentData = {"1", "2", "3"};
    std::vector<std::string> mergeData   = {"1", "2", "3"};
    ErrCode ret = basicPlugin.OnBasicSetPolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnBasicSetPolicy006
 * @tc.desc: Test BasicArrayStringPlugin::OnBasicSetPolicy func with no SetOtherModulePolicy and no failedData.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayStringPluginTest, TestOnBasicSetPolicy006, TestSize.Level1)
{
    TestBasicArrayStringPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    std::vector<std::string> data        = {"1", "2"};
    std::vector<std::string> currentData = {};
    std::vector<std::string> mergeData   = {"1", "2"};
    ErrCode ret = basicPlugin.OnBasicSetPolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestBasicGetPolicy001
 * @tc.desc: Test BasicArrayStringPlugin::BasicGetPolicy func suc.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayStringPluginTest, TestBasicGetPolicy001, TestSize.Level1)
{
    TestBasicArrayStringPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    std::string policyData = "[\"1\", \"2\", \"3\"]";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = basicPlugin.BasicGetPolicy(policyData, data, reply, USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnBasicRemovePolicy001
 * @tc.desc: Test BasicArrayStringPlugin::OnBasicRemovePolicy func with data empty.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayStringPluginTest, TestOnBasicRemovePolicy001, TestSize.Level1)
{
    TestBasicArrayStringPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    std::vector<std::string> data        = {};
    std::vector<std::string> currentData = {"1", "2", "3"};
    std::vector<std::string> mergeData   = {"1", "2"};
    ErrCode ret = basicPlugin.OnBasicRemovePolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnBasicRemovePolicy002
 * @tc.desc: Test BasicArrayStringPlugin::OnBasicRemovePolicy func with data over maxListSize_.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayStringPluginTest, TestOnBasicRemovePolicy002, TestSize.Level1)
{
    TestBasicArrayStringPlugin basicPlugin;
    basicPlugin.SetMaxListSize(5);
    std::vector<std::string> data        = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "1"};
    std::vector<std::string> currentData = {};
    std::vector<std::string> mergeData   = {};
    ErrCode ret = basicPlugin.OnBasicRemovePolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnBasicRemovePolicy003
 * @tc.desc: Test BasicArrayStringPlugin::OnBasicRemovePolicy func with SetOtherModulePolicy and save.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayStringPluginTest, TestOnBasicRemovePolicy003, TestSize.Level1)
{
    TestBasicArrayStringPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    std::vector<std::string> data        = {"3", "4"};
    std::vector<std::string> currentData = {"1", "2"};
    std::vector<std::string> mergeData   = {"1", "2"};
    ErrCode ret = basicPlugin.OnBasicRemovePolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnBasicRemovePolicy004
 * @tc.desc: Test BasicArrayStringPlugin::OnBasicRemovePolicy func with failedData.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayStringPluginTest, TestOnBasicRemovePolicy004, TestSize.Level1)
{
    TestBasicArrayStringPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    basicPlugin.SetMockFailedData({"4"});
    std::vector<std::string> data        = {"4", "5"};
    std::vector<std::string> currentData = {"1", "2", "3"};
    std::vector<std::string> mergeData   = {"1", "2"};
    ErrCode ret = basicPlugin.OnBasicRemovePolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnBasicRemovePolicy005
 * @tc.desc: Test BasicArrayStringPlugin::OnBasicRemovePolicy func with no SetOtherModulePolicy and no failedData.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayStringPluginTest, TestOnBasicRemovePolicy005, TestSize.Level1)
{
    TestBasicArrayStringPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    std::vector<std::string> data        = {"1", "2"};
    std::vector<std::string> currentData = {};
    std::vector<std::string> mergeData   = {"1", "2"};
    ErrCode ret = basicPlugin.OnBasicRemovePolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
