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

#include "basic_array_int_plugin.h"
#include "array_int_serializer.h"

#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
static constexpr int32_t USER_ID = 100;

class TestBasicArrayIntPlugin : public BasicArrayIntPlugin {
public:
    TestBasicArrayIntPlugin() : BasicArrayIntPlugin() {}
    using BasicArrayIntPlugin::OnBasicSetPolicy;
    using BasicArrayIntPlugin::BasicGetPolicy;
    using BasicArrayIntPlugin::OnBasicRemovePolicy;
    using BasicArrayIntPlugin::OnBasicAdminRemove;
    using BasicArrayIntPlugin::RemoveOtherModulePolicy;

    void SetMaxListSize(uint32_t size) { maxListSize_ = size; }
    void SetMockFailedData(std::vector<int32_t> failedData) { mockFailedData_ = failedData; }
    ErrCode SetOtherModulePolicy(const std::vector<int32_t> &data, int32_t userId,
        std::vector<int32_t> &failedData) override
    {
        failedData = mockFailedData_;
        return ERR_OK;
    }
private:
    std::vector<int32_t> mockFailedData_ = {};
};

class BasicArrayIntPluginTest : public testing::Test {
protected:
    void SetUp() override {}

    void TearDown() override {}
};
/**
 * @tc.name: TestOnBasicSetPolicy001
 * @tc.desc: Test BasicArrayIntPlugin::OnBasicSetPolicy func with data empty.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayIntPluginTest, TestOnBasicSetPolicy001, TestSize.Level1)
{
    TestBasicArrayIntPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    std::vector<int32_t> data        = {};
    std::vector<int32_t> currentData = {1, 2, 3};
    std::vector<int32_t> mergeData   = {1, 2, 3};
    ErrCode ret = basicPlugin.OnBasicSetPolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnBasicSetPolicy002
 * @tc.desc: Test BasicArrayIntPlugin::OnBasicSetPolicy func with data over maxListSize_.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayIntPluginTest, TestOnBasicSetPolicy002, TestSize.Level1)
{
    TestBasicArrayIntPlugin basicPlugin;
    basicPlugin.SetMaxListSize(5);
    std::vector<int32_t> data        = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    std::vector<int32_t> currentData = {};
    std::vector<int32_t> mergeData   = {};
    ErrCode ret = basicPlugin.OnBasicSetPolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnBasicSetPolicy003
 * @tc.desc: Test BasicArrayIntPlugin::OnBasicSetPolicy func with afterMerge over maxListSize_.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayIntPluginTest, TestOnBasicSetPolicy003, TestSize.Level1)
{
    TestBasicArrayIntPlugin basicPlugin;
    basicPlugin.SetMaxListSize(5);
    std::vector<int32_t> data        = {4, 5, 6};
    std::vector<int32_t> currentData = {1, 2, 3};
    std::vector<int32_t> mergeData   = {1, 2, 3, 7, 8};
    ErrCode ret = basicPlugin.OnBasicSetPolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnBasicSetPolicy004
 * @tc.desc: Test BasicArrayIntPlugin::OnBasicSetPolicy func with SetOtherModulePolicy and save.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayIntPluginTest, TestOnBasicSetPolicy004, TestSize.Level1)
{
    TestBasicArrayIntPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    std::vector<int32_t> data        = {3, 4};
    std::vector<int32_t> currentData = {1, 2};
    std::vector<int32_t> mergeData   = {1, 2};
    ErrCode ret = basicPlugin.OnBasicSetPolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnBasicSetPolicy005
 * @tc.desc: Test BasicArrayIntPlugin::OnBasicSetPolicy func with failedData.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayIntPluginTest, TestOnBasicSetPolicy005, TestSize.Level1)
{
    TestBasicArrayIntPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    basicPlugin.SetMockFailedData({4});
    std::vector<int32_t> data        = {4, 5};
    std::vector<int32_t> currentData = {1, 2, 3};
    std::vector<int32_t> mergeData   = {1, 2, 3};
    ErrCode ret = basicPlugin.OnBasicSetPolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnBasicSetPolicy006
 * @tc.desc: Test BasicArrayIntPlugin::OnBasicSetPolicy func with no SetOtherModulePolicy and no failedData.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayIntPluginTest, TestOnBasicSetPolicy006, TestSize.Level1)
{
    TestBasicArrayIntPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    std::vector<int32_t> data        = {1, 2};
    std::vector<int32_t> currentData = {};
    std::vector<int32_t> mergeData   = {1, 2, 3};
    ErrCode ret = basicPlugin.OnBasicSetPolicy(data, currentData, mergeData, 100);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestBasicGetPolicy001
 * @tc.desc: Test BasicArrayIntPlugin::BasicGetPolicy func suc.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayIntPluginTest, TestBasicGetPolicy001, TestSize.Level1)
{
    TestBasicArrayIntPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    std::string policyData = "[1, 2, 3]";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = basicPlugin.BasicGetPolicy(policyData, data, reply, USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnBasicRemovePolicy001
 * @tc.desc: Test BasicArrayIntPlugin::OnBasicRemovePolicy func with data empty.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayIntPluginTest, TestOnBasicRemovePolicy001, TestSize.Level1)
{
    TestBasicArrayIntPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    std::vector<int32_t> data        = {};
    std::vector<int32_t> currentData = {1, 2, 3};
    std::vector<int32_t> mergeData   = {1, 2, 3};
    ErrCode ret = basicPlugin.OnBasicRemovePolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnBasicRemovePolicy002
 * @tc.desc: Test BasicArrayIntPlugin::OnBasicRemovePolicy func with data over maxListSize_.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayIntPluginTest, TestOnBasicRemovePolicy002, TestSize.Level1)
{
    TestBasicArrayIntPlugin basicPlugin;
    basicPlugin.SetMaxListSize(5);
    std::vector<int32_t> data        = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    std::vector<int32_t> currentData = {};
    std::vector<int32_t> mergeData   = {};
    ErrCode ret = basicPlugin.OnBasicRemovePolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnBasicRemovePolicy003
 * @tc.desc: Test BasicArrayIntPlugin::OnBasicRemovePolicy func with SetOtherModulePolicy and save.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayIntPluginTest, TestOnBasicRemovePolicy003, TestSize.Level1)
{
    TestBasicArrayIntPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    std::vector<int32_t> data        = {3, 4};
    std::vector<int32_t> currentData = {1, 2};
    std::vector<int32_t> mergeData   = {1, 2};
    ErrCode ret = basicPlugin.OnBasicRemovePolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnBasicRemovePolicy004
 * @tc.desc: Test BasicArrayIntPlugin::OnBasicRemovePolicy func with failedData.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayIntPluginTest, TestOnBasicRemovePolicy004, TestSize.Level1)
{
    TestBasicArrayIntPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    basicPlugin.SetMockFailedData({4});
    std::vector<int32_t> data        = {4, 5};
    std::vector<int32_t> currentData = {1, 2, 3};
    std::vector<int32_t> mergeData   = {1, 2, 3};
    ErrCode ret = basicPlugin.OnBasicRemovePolicy(data, currentData, mergeData, USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnBasicRemovePolicy005
 * @tc.desc: Test BasicArrayIntPlugin::OnBasicRemovePolicy func with no SetOtherModulePolicy and no failedData.
 * @tc.type: FUNC
 */
HWTEST_F(BasicArrayIntPluginTest, TestOnBasicRemovePolicy005, TestSize.Level1)
{
    TestBasicArrayIntPlugin basicPlugin;
    basicPlugin.SetMaxListSize(200);
    std::vector<int32_t> data        = {1, 2};
    std::vector<int32_t> currentData = {};
    std::vector<int32_t> mergeData   = {1, 2, 3};
    ErrCode ret = basicPlugin.OnBasicRemovePolicy(data, currentData, mergeData, 100);
    EXPECT_EQ(ret, ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
