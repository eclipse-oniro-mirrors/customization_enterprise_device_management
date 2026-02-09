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

#ifndef EDM_UNIT_TEST_SERVICE_EDM_INCLUDE_MOCK_EXTERNAL_MODULE_ADAPTER_MOCK_H
#define EDM_UNIT_TEST_SERVICE_EDM_INCLUDE_MOCK_EXTERNAL_MODULE_ADAPTER_MOCK_H

#include <gmock/gmock.h>

#include "iexternal_module_adapter.h"

namespace OHOS {
namespace EDM {
class ExternalModuleAdapterMock : public IExternalModuleAdapter {
public:
    ~ExternalModuleAdapterMock() override = default;

    MOCK_METHOD(ErrCode, NotifyUpgradePackages, (const UpgradePackageInfo &, std::string &), (override));

    MOCK_METHOD(ErrCode, SetUpdatePolicy, (const UpdatePolicy &, std::string &), (override));

    MOCK_METHOD(std::string, GetCallingBundleName, (), (override));
};
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_SERVICE_EDM_INCLUDE_MOCK_EXTERNAL_MODULE_ADAPTER_MOCK_H
