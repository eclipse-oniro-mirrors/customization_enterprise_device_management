/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "set_watermark_image_plugin.h"
#include "utils.h"
#include "watermark_image_serializer.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class SetWatermarkImagePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void SetWatermarkImagePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void SetWatermarkImagePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestSetSingleWatermarkImageEmpty
 * @tc.desc: Test SetWatermarkImagePlugin::SetSingleWatermarkImage function when param is null.
 * @tc.type: FUNC
 */
HWTEST_F(SetWatermarkImagePluginTest, TestSetSingleWatermarkImageEmpty, TestSize.Level1)
{
    SetWatermarkImagePlugin plugin;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::WATERMARK_IMAGE);
    MessageParcel data;
    data.WriteString(EdmConstants::SecurityManager::SET_SINGLE_WATERMARK_TYPE);
    MessageParcel reply;
    HandlePolicyData policyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, 100);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestSetSingleWatermarkImageMax
 * @tc.desc: Test SetWatermarkImagePlugin::SetSingleWatermarkImage function when policy over max num.
 * @tc.type: FUNC
 */
HWTEST_F(SetWatermarkImagePluginTest, TestSetSingleWatermarkImageMax, TestSize.Level1)
{
    SetWatermarkImagePlugin plugin;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::WATERMARK_IMAGE);
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;

    data.WriteString(EdmConstants::SecurityManager::SET_SINGLE_WATERMARK_TYPE);
    data.WriteString("testBundleName");
    data.WriteInt32(100);
    data.WriteInt32(400);
    data.WriteInt32(400);
    int32_t size = 200;
    data.WriteInt32(size);
    void* pixels = malloc(size);
    ASSERT_TRUE(pixels != nullptr);
    data.WriteRawData(pixels, size);

    std::map<std::pair<std::string, int32_t>, WatermarkImageType> currentData;
    for (int32_t i = 101; i <= 200; i++) {
        currentData[{"testBundleName", i}] = WatermarkImageType{"testFileName", 100, 100};
    }
    auto serializer = WatermarkImageSerializer::GetInstance();
    serializer->Serialize(currentData, policyData.policyData);

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, 100);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestSetSingleWatermarkImage
 * @tc.desc: Test SetWatermarkImagePlugin::SetSingleWatermarkImage function.
 * @tc.type: FUNC
 */
HWTEST_F(SetWatermarkImagePluginTest, TestSetSingleWatermarkImage, TestSize.Level1)
{
    SetWatermarkImagePlugin plugin;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::WATERMARK_IMAGE);
    MessageParcel data;
    data.WriteString(EdmConstants::SecurityManager::SET_SINGLE_WATERMARK_TYPE);
    data.WriteString("testBundleName");
    data.WriteInt32(100);
    data.WriteInt32(400);
    data.WriteInt32(400);
    int32_t size = 200;
    data.WriteInt32(size);
    void* pixels = malloc(size);
    ASSERT_TRUE(pixels != nullptr);
    data.WriteRawData(pixels, size);
    MessageParcel reply;
    HandlePolicyData policyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, 100);
    std::string deviceType = system::GetParameter("const.product.devicetype", "");
    if (deviceType != "2in1") {
        ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    } else {
        ASSERT_TRUE(ret == ERR_OK);
        ASSERT_FALSE(policyData.policyData.empty());
    }
}

/**
 * @tc.name: TestCancelWatermarkImageEmpty
 * @tc.desc: Test SetWatermarkImagePlugin::CancelWatermarkImage function when param is null.
 * @tc.type: FUNC
 */
HWTEST_F(SetWatermarkImagePluginTest, TestCancelWatermarkImageEmpty, TestSize.Level1)
{
    SetWatermarkImagePlugin plugin;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::WATERMARK_IMAGE);
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, 100);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS