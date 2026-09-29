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

#define protected public
#define private public
#include "get_external_storage_device_infos_plugin.h"
#undef private
#undef protected

#include <gtest/gtest.h>

#include "edm_ipc_interface_code.h"
#include "external_storage_device_info.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class GetExternalStorageDeviceInfosPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void GetExternalStorageDeviceInfosPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void GetExternalStorageDeviceInfosPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test GetExternalStorageDeviceInfosPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(GetExternalStorageDeviceInfosPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::shared_ptr<IPlugin> plugin = std::make_shared<GetExternalStorageDeviceInfosPlugin>();
    std::string policyData;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    if (ret == ERR_OK) {
        ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
        uint32_t size = reply.ReadUint32();
        ASSERT_TRUE(size >= 0);
    } else {
        ASSERT_TRUE(ret == EdmReturnErrCode::EXECUTE_TIME_OUT);
        ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::EXECUTE_TIME_OUT);
    }
}

/**
 * @tc.name: TestPluginConstruction
 * @tc.desc: Test GetExternalStorageDeviceInfosPlugin construction and policy code.
 * @tc.type: FUNC
 */
HWTEST_F(GetExternalStorageDeviceInfosPluginTest, TestPluginConstruction, TestSize.Level1)
{
    auto plugin = std::make_shared<GetExternalStorageDeviceInfosPlugin>();
    ASSERT_TRUE(plugin != nullptr);
    ASSERT_TRUE(plugin->policyCode_ ==
        static_cast<uint32_t>(EdmInterfaceCode::GET_EXTERNAL_STORAGE_DEVICE_INFOS));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
