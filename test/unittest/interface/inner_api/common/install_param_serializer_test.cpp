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

#include <fcntl.h>
#include <gtest/gtest.h>
#include <unistd.h>

#include "install_param_serializer.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

const std::string TEST_HAP_FILE_PATH = "/data/test/resource/enterprise_device_management/hap/right.hap";
const int32_t TEST_USER_ID = 100;
const int32_t TEST_INSTALL_FLAG = 1;

class InstallParamSerializerTest : public testing::Test {
public:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

void InstallParamSerializerTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void InstallParamSerializerTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

static void WriteValidParcel(MessageParcel &data)
{
    std::vector<std::string> hapFilePaths = { "/data/test/right.hap", "/data/test/right2.hap" };
    data.WriteStringVector(hapFilePaths);

    int32_t fd = open(TEST_HAP_FILE_PATH.c_str(), O_RDONLY);
    if (fd < 0) {
        fd = open(TEST_HAP_FILE_PATH.c_str(), O_CREAT | O_RDONLY, S_IRUSR | S_IWUSR);
    }
    int32_t fdCount = (fd >= 0) ? 1 : 0;
    data.WriteInt32(fdCount);
    if (fd >= 0) {
        data.WriteFileDescriptor(fd);
        close(fd);
    }

    data.WriteInt32(TEST_USER_ID);
    data.WriteInt32(TEST_INSTALL_FLAG);

    std::vector<std::string> keys = { "key1", "key2" };
    std::vector<std::string> values = { "value1", "value2" };
    data.WriteStringVector(keys);
    data.WriteStringVector(values);
}

/**
 * @tc.name: TestGetPolicySuc
 * @tc.desc: Test InstallParamSerializer::GetPolicy with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(InstallParamSerializerTest, TestGetPolicySuc, TestSize.Level1)
{
    auto serializer = InstallParamSerializer::GetInstance();
    MessageParcel data;
    WriteValidParcel(data);
    InstallParam result;
    bool ret = serializer->GetPolicy(data, result);
    ASSERT_TRUE(ret);
    ASSERT_EQ(result.hapFilePaths.size(), 2u);
    ASSERT_EQ(result.hapFilePaths[0], "/data/test/right.hap");
    ASSERT_EQ(result.hapFilePaths[1], "/data/test/right2.hap");
    ASSERT_EQ(result.userId, TEST_USER_ID);
    ASSERT_EQ(result.installFlag, TEST_INSTALL_FLAG);
    ASSERT_EQ(result.parameters.size(), 2u);
    ASSERT_EQ(result.parameters["key1"], "value1");
    ASSERT_EQ(result.parameters["key2"], "value2");
    for (auto fd : result.hapFds) {
        if (fd >= 0) {
            close(fd);
        }
    }
}

/**
 * @tc.name: TestGetPolicyFailWithMismatchedKeysValues
 * @tc.desc: Test InstallParamSerializer::GetPolicy when keys and values size mismatch.
 * @tc.type: FUNC
 */
HWTEST_F(InstallParamSerializerTest, TestGetPolicyFailWithMismatchedKeysValues, TestSize.Level1)
{
    auto serializer = InstallParamSerializer::GetInstance();
    MessageParcel data;
    std::vector<std::string> hapFilePaths = { "/data/test/right.hap" };
    data.WriteStringVector(hapFilePaths);
    data.WriteInt32(0);
    data.WriteInt32(TEST_USER_ID);
    data.WriteInt32(TEST_INSTALL_FLAG);
    std::vector<std::string> keys = { "key1", "key2" };
    std::vector<std::string> values = { "value1" };
    data.WriteStringVector(keys);
    data.WriteStringVector(values);
    InstallParam result;
    bool ret = serializer->GetPolicy(data, result);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestGetPolicyWithEmptyFds
 * @tc.desc: Test InstallParamSerializer::GetPolicy when fdCount is 0.
 * @tc.type: FUNC
 */
HWTEST_F(InstallParamSerializerTest, TestGetPolicyWithEmptyFds, TestSize.Level1)
{
    auto serializer = InstallParamSerializer::GetInstance();
    MessageParcel data;
    std::vector<std::string> hapFilePaths = { "/data/test/right.hap" };
    data.WriteStringVector(hapFilePaths);
    data.WriteInt32(0);
    data.WriteInt32(TEST_USER_ID);
    data.WriteInt32(TEST_INSTALL_FLAG);
    std::vector<std::string> keys;
    std::vector<std::string> values;
    data.WriteStringVector(keys);
    data.WriteStringVector(values);
    InstallParam result;
    bool ret = serializer->GetPolicy(data, result);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(result.hapFds.empty());
    ASSERT_EQ(result.hapFilePaths.size(), 1u);
    ASSERT_EQ(result.userId, TEST_USER_ID);
    ASSERT_TRUE(result.parameters.empty());
}

/**
 * @tc.name: TestGetPolicyWithMultipleFds
 * @tc.desc: Test InstallParamSerializer::GetPolicy when multiple fds are written.
 * @tc.type: FUNC
 */
HWTEST_F(InstallParamSerializerTest, TestGetPolicyWithMultipleFds, TestSize.Level1)
{
    auto serializer = InstallParamSerializer::GetInstance();
    MessageParcel data;
    std::vector<std::string> hapFilePaths = { "/data/test/right.hap" };
    data.WriteStringVector(hapFilePaths);

    int32_t fd1 = open(TEST_HAP_FILE_PATH.c_str(), O_RDONLY);
    if (fd1 < 0) {
        fd1 = open(TEST_HAP_FILE_PATH.c_str(), O_CREAT | O_RDONLY, S_IRUSR | S_IWUSR);
    }
    int32_t fd2 = open(TEST_HAP_FILE_PATH.c_str(), O_RDONLY);
    if (fd2 < 0) {
        fd2 = open(TEST_HAP_FILE_PATH.c_str(), O_CREAT | O_RDONLY, S_IRUSR | S_IWUSR);
    }
    int32_t fdCount = 0;
    if (fd1 >= 0 && fd2 >= 0) {
        fdCount = 2;
    } else if (fd1 >= 0) {
        fdCount = 1;
        close(fd2);
        fd2 = -1;
    }
    data.WriteInt32(fdCount);
    if (fd1 >= 0) {
        data.WriteFileDescriptor(fd1);
        close(fd1);
    }
    if (fd2 >= 0) {
        data.WriteFileDescriptor(fd2);
        close(fd2);
    }

    data.WriteInt32(TEST_USER_ID);
    data.WriteInt32(TEST_INSTALL_FLAG);
    std::vector<std::string> keys;
    std::vector<std::string> values;
    data.WriteStringVector(keys);
    data.WriteStringVector(values);

    InstallParam result;
    bool ret = serializer->GetPolicy(data, result);
    ASSERT_TRUE(ret);
    ASSERT_EQ(static_cast<int32_t>(result.hapFds.size()), fdCount);
    for (auto fd : result.hapFds) {
        if (fd >= 0) {
            close(fd);
        }
    }
}

/**
 * @tc.name: TestGetPolicyWithEmptyParameters
 * @tc.desc: Test InstallParamSerializer::GetPolicy when parameters are empty.
 * @tc.type: FUNC
 */
HWTEST_F(InstallParamSerializerTest, TestGetPolicyWithEmptyParameters, TestSize.Level1)
{
    auto serializer = InstallParamSerializer::GetInstance();
    MessageParcel data;
    std::vector<std::string> hapFilePaths;
    data.WriteStringVector(hapFilePaths);
    data.WriteInt32(0);
    data.WriteInt32(TEST_USER_ID);
    data.WriteInt32(TEST_INSTALL_FLAG);
    std::vector<std::string> emptyKeys;
    std::vector<std::string> emptyValues;
    data.WriteStringVector(emptyKeys);
    data.WriteStringVector(emptyValues);
    InstallParam result;
    bool ret = serializer->GetPolicy(data, result);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(result.hapFilePaths.empty());
    ASSERT_TRUE(result.hapFds.empty());
    ASSERT_TRUE(result.parameters.empty());
}

/**
 * @tc.name: TestDeserialize
 * @tc.desc: Test InstallParamSerializer::Deserialize always returns true.
 * @tc.type: FUNC
 */
HWTEST_F(InstallParamSerializerTest, TestDeserialize, TestSize.Level1)
{
    auto serializer = InstallParamSerializer::GetInstance();
    InstallParam config;
    bool ret = serializer->Deserialize("{}", config);
    ASSERT_TRUE(ret);
    ret = serializer->Deserialize("", config);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestSerialize
 * @tc.desc: Test InstallParamSerializer::Serialize always returns true.
 * @tc.type: FUNC
 */
HWTEST_F(InstallParamSerializerTest, TestSerialize, TestSize.Level1)
{
    auto serializer = InstallParamSerializer::GetInstance();
    InstallParam config;
    config.userId = TEST_USER_ID;
    config.installFlag = TEST_INSTALL_FLAG;
    std::string jsonString;
    bool ret = serializer->Serialize(config, jsonString);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestWritePolicy
 * @tc.desc: Test InstallParamSerializer::WritePolicy always returns true.
 * @tc.type: FUNC
 */
HWTEST_F(InstallParamSerializerTest, TestWritePolicy, TestSize.Level1)
{
    auto serializer = InstallParamSerializer::GetInstance();
    MessageParcel reply;
    InstallParam result;
    bool ret = serializer->WritePolicy(reply, result);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test InstallParamSerializer::MergePolicy always returns true.
 * @tc.type: FUNC
 */
HWTEST_F(InstallParamSerializerTest, TestMergePolicy, TestSize.Level1)
{
    auto serializer = InstallParamSerializer::GetInstance();
    std::vector<InstallParam> data;
    InstallParam result;
    bool ret = serializer->MergePolicy(data, result);
    ASSERT_TRUE(ret);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
