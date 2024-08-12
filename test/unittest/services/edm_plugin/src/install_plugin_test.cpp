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

#include "install_plugin_test.h"

#include "uninstall_plugin.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string HAP_FILE_PATH = "/data/test/resource/enterprise_device_management/hap/right.hap";
const std::string INVALID_HAP_FILE_PATH = "/data/test/resource/enterprise_device_management/hap/../right.hap";

void InstallPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void InstallPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicySuc
 * @tc.desc: Test InstallPlugin::OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, TestOnSetPolicySuc, TestSize.Level1)
{
    InstallPlugin plugin;
    InstallParam param = {{HAP_FILE_PATH}, DEFAULT_USER_ID, 0};
    MessageParcel reply;
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == ERR_OK);
    UninstallPlugin uninstallPlugin;
    UninstallParam uninstallParam = {"com.example.l3jsdemo", DEFAULT_USER_ID, false};
    MessageParcel uninstallReply;
    ret = uninstallPlugin.OnSetPolicy(uninstallParam, uninstallReply);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyFailWithInvalidFilePath
 * @tc.desc: Test InstallPlugin::OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, TestOnSetPolicyFailWithInvalidFilePath, TestSize.Level1)
{
    InstallPlugin plugin;
    InstallParam param = {{INVALID_HAP_FILE_PATH}, DEFAULT_USER_ID, 0};
    MessageParcel reply;
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
}

/**
 * @tc.name: TestOnGetPolicyFailWithLongName
 * @tc.desc: Test InstallPlugin::OnGetPolicy when data is long.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, TestOnGetPolicyFailWithLongName, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string policyData;
    MessageParcel reply;
    MessageParcel data;
    int32_t userId = DEFAULT_USER_ID;
    std::string strFileName(5000, 'a');
    data.WriteString(strFileName);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, userId);
    ASSERT_TRUE(ret == EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
    ASSERT_TRUE(reply.ReadString() == "invalid hapFilePath");
}

/**
 * @tc.name: TestOnGetPolicyFailWithInvalidFile01
 * @tc.desc: Test InstallPlugin::OnGetPolicy when data is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, TestOnGetPolicyFailWithInvalidFile01, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string policyData;
    MessageParcel reply;
    MessageParcel data;
    int32_t userId = DEFAULT_USER_ID;
    std::string strFileName = "../aaa.hap";
    data.WriteString(strFileName);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, userId);
    ASSERT_TRUE(ret == EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
}

/**
 * @tc.name: TestOnGetPolicyFailWithInvalidFile02
 * @tc.desc: Test InstallPlugin::OnGetPolicy when data is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, TestOnGetPolicyFailWithInvalidFile02, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string policyData;
    MessageParcel reply;
    MessageParcel data;
    int32_t userId = DEFAULT_USER_ID;
    std::string strFileName = "./aaa.hap";
    data.WriteString(strFileName);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, userId);
    ASSERT_TRUE(ret == EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
}

/**
 * @tc.name: TestOnGetPolicyFailWithInvalidFile03
 * @tc.desc: Test InstallPlugin::OnGetPolicy when data is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, TestOnGetPolicyFailWithInvalidFile03, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string policyData;
    MessageParcel reply;
    MessageParcel data;
    int32_t userId = DEFAULT_USER_ID;
    std::string strFileName = "/aaa.hap";
    data.WriteString(strFileName);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, userId);
    ASSERT_TRUE(ret == EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
}

/**
 * @tc.name: TestOnGetPolicyFailWithInvalidFile04
 * @tc.desc: Test InstallPlugin::OnGetPolicy when data is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, TestOnGetPolicyFailWithInvalidFile04, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string policyData;
    MessageParcel reply;
    MessageParcel data;
    int32_t userId = DEFAULT_USER_ID;
    std::string strFileName = "aaa.hap";
    data.WriteString(strFileName);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, userId);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS