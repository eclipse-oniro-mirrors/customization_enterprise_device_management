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
#include <regex>
#include <set>
#include <vector>
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
    std::vector<uint8_t> pixels(size, 1);
    data.WriteRawData(pixels.data(), size);
    MessageParcel reply;
    HandlePolicyData policyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, 100);
    ASSERT_EQ(ret, ERR_OK);
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

/**
 * @tc.name: TestCancelWatermarkImage
 * @tc.desc: Test SetWatermarkImagePlugin::CancelWatermarkImage function.
 * @tc.type: FUNC
 */
HWTEST_F(SetWatermarkImagePluginTest, TestCancelWatermarkImage, TestSize.Level1)
{
    SetWatermarkImagePlugin plugin;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::WATERMARK_IMAGE);
    MessageParcel data;
    data.WriteString("testBundleName");
    data.WriteInt32(100);
    MessageParcel reply;
    HandlePolicyData policyData;
    std::map<std::pair<std::string, int32_t>, WatermarkImageType> currentData;
    currentData[{"testBundleName", 100}] = WatermarkImageType{"testFileName", 400, 400};
    auto serializer = WatermarkImageSerializer::GetInstance();
    serializer->Serialize(currentData, policyData.policyData);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, 100);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policyData.policyData.empty());
}

/**
 * @tc.name: TestGenerateUniqueFileNameFormat
 * @tc.desc: Test SetWatermarkImagePlugin::GenerateUniqueFileName returns correct format.
 * @tc.type: FUNC
 */
HWTEST_F(SetWatermarkImagePluginTest, TestGenerateUniqueFileNameFormat, TestSize.Level1)
{
    SetWatermarkImagePlugin plugin;
    std::string fileName = plugin.GenerateUniqueFileName();
    
    ASSERT_FALSE(fileName.empty());
    ASSERT_TRUE(fileName.find("edm_") == 0);
    
    std::regex pattern("^edm_[0-9]+_[0-9]+$");
    ASSERT_TRUE(std::regex_match(fileName, pattern));
}

/**
 * @tc.name: TestGenerateUniqueFileNameContainsTimestamp
 * @tc.desc: Test SetWatermarkImagePlugin::GenerateUniqueFileName contains timestamp.
 * @tc.type: FUNC
 */
HWTEST_F(SetWatermarkImagePluginTest, TestGenerateUniqueFileNameContainsTimestamp, TestSize.Level1)
{
    SetWatermarkImagePlugin plugin;
    std::string fileName = plugin.GenerateUniqueFileName();
    
    ASSERT_FALSE(fileName.empty());
    ASSERT_TRUE(fileName.find("edm_") == 0);
    
    size_t firstUnderscore = fileName.find('_');
    size_t secondUnderscore = fileName.find('_', firstUnderscore + 1);
    ASSERT_NE(secondUnderscore, std::string::npos);
    
    std::string timestampStr = fileName.substr(firstUnderscore + 1, secondUnderscore - firstUnderscore - 1);
    ASSERT_FALSE(timestampStr.empty());
    
    for (char c : timestampStr) {
        ASSERT_TRUE(std::isdigit(c));
    }
    
    int64_t timestamp = std::stoll(timestampStr);
    ASSERT_GT(timestamp, 0);
}

/**
 * @tc.name: TestGenerateUniqueFileNameRandomInRange
 * @tc.desc: Test SetWatermarkImagePlugin::GenerateUniqueFileName random number is in valid range.
 * @tc.type: FUNC
 */
HWTEST_F(SetWatermarkImagePluginTest, TestGenerateUniqueFileNameRandomInRange, TestSize.Level1)
{
    SetWatermarkImagePlugin plugin;
    
    for (int i = 0; i < 100; i++) {
        std::string fileName = plugin.GenerateUniqueFileName();
        ASSERT_FALSE(fileName.empty());
        
        size_t lastUnderscore = fileName.rfind('_');
        ASSERT_NE(lastUnderscore, std::string::npos);
        
        std::string randomStr = fileName.substr(lastUnderscore + 1);
        ASSERT_FALSE(randomStr.empty());
        
        for (char c : randomStr) {
            ASSERT_TRUE(std::isdigit(c));
        }
        
        int32_t randomNum = std::stoi(randomStr);
        ASSERT_GE(randomNum, 0);
        ASSERT_LE(randomNum, 9999);
    }
}

/**
 * @tc.name: TestGenerateUniqueFileNameUniqueness
 * @tc.desc: Test SetWatermarkImagePlugin::GenerateUniqueFileName generates unique names.
 * @tc.type: FUNC
 */
HWTEST_F(SetWatermarkImagePluginTest, TestGenerateUniqueFileNameUniqueness, TestSize.Level1)
{
    SetWatermarkImagePlugin plugin;
    std::set<std::string> fileNames;
    const int testCount = 1000;
    
    for (int i = 0; i < testCount; i++) {
        std::string fileName = plugin.GenerateUniqueFileName();
        ASSERT_FALSE(fileName.empty());
        fileNames.insert(fileName);
    }
    
    ASSERT_EQ(fileNames.size(), testCount);
}

/**
 * @tc.name: TestGenerateUniqueFileNameMultipleCalls
 * @tc.desc: Test SetWatermarkImagePlugin::GenerateUniqueFileName with multiple calls.
 * @tc.type: FUNC
 */
HWTEST_F(SetWatermarkImagePluginTest, TestGenerateUniqueFileNameMultipleCalls, TestSize.Level1)
{
    SetWatermarkImagePlugin plugin;
    
    std::string fileName1 = plugin.GenerateUniqueFileName();
    std::string fileName2 = plugin.GenerateUniqueFileName();
    std::string fileName3 = plugin.GenerateUniqueFileName();
    
    ASSERT_FALSE(fileName1.empty());
    ASSERT_FALSE(fileName2.empty());
    ASSERT_FALSE(fileName3.empty());
    
    ASSERT_NE(fileName1, fileName2);
    ASSERT_NE(fileName2, fileName3);
    ASSERT_NE(fileName1, fileName3);
    
    ASSERT_TRUE(fileName1.find("edm_") == 0);
    ASSERT_TRUE(fileName2.find("edm_") == 0);
    ASSERT_TRUE(fileName3.find("edm_") == 0);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS