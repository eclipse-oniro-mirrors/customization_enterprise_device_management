/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef EDM_UNIT_TEST_DEVICE_INFO_PLUGIN_TEST_H
#define EDM_UNIT_TEST_DEVICE_INFO_PLUGIN_TEST_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>

#include "edm_os_account_manager_impl_mock.h"
#include "external_manager_factory_mock.h"
#include "get_device_info_plugin.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
namespace TEST {
class GetDeviceInfoPluginMock : public GetDeviceInfoPlugin {
public:
    MOCK_METHOD(std::shared_ptr<IExternalManagerFactory>, GetExternalManagerFactory, (), (override));
};

class DeviceInfoPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
    std::shared_ptr<IPlugin> plugin_;
    std::shared_ptr<GetDeviceInfoPluginMock> pluginMock_ = std::make_shared<GetDeviceInfoPluginMock>();
    std::shared_ptr<EdmOsAccountManagerImplMock> osAccountMgrMock_ = std::make_shared<EdmOsAccountManagerImplMock>();
    std::shared_ptr<ExternalManagerFactoryMock> factoryMock_ = std::make_shared<ExternalManagerFactoryMock>();
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_DEVICE_INFO_PLUGIN_TEST_H