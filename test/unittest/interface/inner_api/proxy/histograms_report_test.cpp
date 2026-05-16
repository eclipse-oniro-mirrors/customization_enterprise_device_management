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
#include "histograms_report.h"
#include "func_code.h"
#include "edm_ipc_interface_code.h"
#include "edm_constants.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {

class HistogramsReportTest : public testing::Test {
public:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

void HistogramsReportTest::SetUpTestSuite(void) {}

void HistogramsReportTest::TearDownTestSuite(void) {}

/**
 * @tc.name: ReportBoolean_ValidSetCode_ReturnVoid
 * @tc.desc: Test ReportBoolean function with valid SET code.
 * @tc.type: FUNC
 */
HWTEST_F(HistogramsReportTest, ReportBoolean_ValidSetCode_ReturnVoid, TestSize.Level1)
{
    uint32_t code = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET), EdmInterfaceCode::ADD_OS_ACCOUNT);
    EXPECT_TRUE(HistogramsReport::ReportBoolean(code));
}

/**
 * @tc.name: ReportBoolean_ValidRemoveCode_ReturnVoid
 * @tc.desc: Test ReportBoolean function with valid REMOVE code.
 * @tc.type: FUNC
 */
HWTEST_F(HistogramsReportTest, ReportBoolean_ValidRemoveCode_ReturnVoid, TestSize.Level1)
{
    uint32_t code = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::REMOVE),
        EdmInterfaceCode::MANAGE_AUTO_START_APPS);
    EXPECT_TRUE(HistogramsReport::ReportBoolean(code));
}

/**
 * @tc.name: ReportBoolean_GetTypeCode_ReturnVoid
 * @tc.desc: Test ReportBoolean function with GET type code, should not find report name.
 * @tc.type: FUNC
 */
HWTEST_F(HistogramsReportTest, ReportBoolean_GetTypeCode_ReturnVoid, TestSize.Level1)
{
    uint32_t code = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::GET),
        EdmInterfaceCode::MANAGE_AUTO_START_APPS);
    EXPECT_FALSE(HistogramsReport::ReportBoolean(code));
}

/**
 * @tc.name: ReportBoolean_UnknownTypeCode_ReturnVoid
 * @tc.desc: Test ReportBoolean function with UNKNOWN type code.
 * @tc.type: FUNC
 */
HWTEST_F(HistogramsReportTest, ReportBoolean_UnknownTypeCode_ReturnVoid, TestSize.Level1)
{
    uint32_t code = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::UNKNOWN),
        EdmInterfaceCode::ADD_OS_ACCOUNT);
    EXPECT_FALSE(HistogramsReport::ReportBoolean(code));
}

/**
 * @tc.name: ReportBoolean_NotExistPolicyCode_ReturnVoid
 * @tc.desc: Test ReportBoolean function with non-existent policy code.
 * @tc.type: FUNC
 */
HWTEST_F(HistogramsReportTest, ReportBoolean_NotExistPolicyCode_ReturnVoid, TestSize.Level1)
{
    uint32_t code = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET), 9999);
    EXPECT_FALSE(HistogramsReport::ReportBoolean(code));
}

/**
 * @tc.name: ReportBoolean_SpecialPolicyCode_ReturnVoid
 * @tc.desc: Test ReportBoolean function with special policy code (POLICY_CODE_END + START_COLLECT_LOG) SET type.
 * @tc.type: FUNC
 */
HWTEST_F(HistogramsReportTest, ReportBoolean_SpecialPolicyCode_ReturnVoid, TestSize.Level1)
{
    uint32_t specialCode = EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::START_COLLECT_LOG;
    uint32_t code = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET), specialCode);
    EXPECT_TRUE(HistogramsReport::ReportBoolean(code));
}

/**
 * @tc.name: ReportBoolean_SpecialPolicyCodeRemove_ReturnVoid
 * @tc.desc: Test ReportBoolean function with special policy code REMOVE type.
 * @tc.type: FUNC
 */
HWTEST_F(HistogramsReportTest, ReportBoolean_SpecialPolicyCodeRemove_ReturnVoid, TestSize.Level1)
{
    uint32_t specialCode = EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::START_COLLECT_LOG;
    uint32_t code = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::REMOVE), specialCode);
    EXPECT_TRUE(HistogramsReport::ReportBoolean(code));
}

/**
 * @tc.name: ReportBoolean_RemoveTypeNotExistCode_ReturnVoid
 * @tc.desc: Test ReportBoolean function with REMOVE type and non-existent code.
 * @tc.type: FUNC
 */
HWTEST_F(HistogramsReportTest, ReportBoolean_RemoveTypeNotExistCode_ReturnVoid, TestSize.Level1)
{
    uint32_t code = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::REMOVE), 9999);
    EXPECT_FALSE(HistogramsReport::ReportBoolean(code));
}

/**
 * @tc.name: ReportBoolean_RemoveTypeCodeNotInRemoveMap_ReturnVoid
 * @tc.desc: Test ReportBoolean function with REMOVE type and code that exists in SET map but not in REMOVE map.
 * @tc.type: FUNC
 */
HWTEST_F(HistogramsReportTest, ReportBoolean_RemoveTypeCodeNotInRemoveMap_ReturnVoid, TestSize.Level1)
{
    uint32_t code = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::REMOVE), EdmInterfaceCode::ADD_OS_ACCOUNT);
    EXPECT_FALSE(HistogramsReport::ReportBoolean(code));
}
} // namespace EDM
} // namespace OHOS