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

#include <gtest/gtest.h>

#include <string>

#include "hisysevent_adapter.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

class HiSysEventAdapterTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: HiSysEventAdapter_ReportEdmEvent_FuncEventType_NoCrash
 * @tc.desc: Test ReportEdmEvent with EDM_FUNC_EVENT type does not crash.
 * @tc.type: FUNC
 */
HWTEST_F(HiSysEventAdapterTest, ReportEdmEvent_FuncEventType_NoCrash, TestSize.Level1)
{
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "DisableAdmin");
    EXPECT_TRUE(true);
}

/**
 * @tc.name: HiSysEventAdapter_ReportEdmEvent_EmptyApiName_NoCrash
 * @tc.desc: Test ReportEdmEvent with empty apiName does not crash.
 * @tc.type: FUNC
 */
HWTEST_F(HiSysEventAdapterTest, ReportEdmEvent_EmptyApiName_NoCrash, TestSize.Level1)
{
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_FAILED, "", "UT test error message");
    EXPECT_TRUE(true);
}

/**
 * @tc.name: HiSysEventAdapter_ReportEdmEventManagerAdmin_NormalParams_NoCrash
 * @tc.desc: Test ReportEdmEventManagerAdmin with normal parameters does not crash.
 * @tc.type: FUNC
 */
HWTEST_F(HiSysEventAdapterTest, ReportEdmEventManagerAdmin_NormalParams_NoCrash, TestSize.Level1)
{
    HiSysEventAdapter::ReportEdmEventManagerAdmin("com.test.bundle", 1, 0, "UT test extra info");
    EXPECT_TRUE(true);
}

/**
 * @tc.name: HiSysEventAdapter_ReportInstalledBundleInfo_LongString_ReturnValue
 * @tc.desc: Test ReportInstalledBundleInfo with long string returns a valid bool value.
 * @tc.type: FUNC
 */
HWTEST_F(HiSysEventAdapterTest, ReportInstalledBundleInfo_LongString_ReturnValue, TestSize.Level1)
{
    std::string longInfo = "[{\"mdmName\":\"com.admin.long\",\"installedName\":\"com.app.long\","
        "\"installedType\":1,\"installedTime\":1234567890}]";
    bool ret = HiSysEventAdapter::ReportInstalledBundleInfo(longInfo);
    EXPECT_TRUE(ret);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
