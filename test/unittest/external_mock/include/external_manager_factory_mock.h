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

#ifndef EDM_UNIT_TEST_EXTERNAL_INCLUDE_MOCK_EXTERNAL_MANAGER_FACTORY_MOCK_H
#define EDM_UNIT_TEST_EXTERNAL_INCLUDE_MOCK_EXTERNAL_MANAGER_FACTORY_MOCK_H

#include <gmock/gmock.h>

#include "iexternal_manager_factory.h"

namespace OHOS {
namespace EDM {
class ExternalManagerFactoryMock : public IExternalManagerFactory {
public:
    ~ExternalManagerFactoryMock() override = default;
    MOCK_METHOD(std::shared_ptr<IEdmAppManager>, CreateAppManager, (), (override));
    MOCK_METHOD(std::shared_ptr<IEdmBundleManager>, CreateBundleManager, (), (override));
    MOCK_METHOD(std::shared_ptr<IEdmOsAccountManager>, CreateOsAccountManager, (), (override));
    MOCK_METHOD(std::shared_ptr<IEdmAccessTokenManager>, CreateAccessTokenManager, (), (override));
};
} // namespace EDM
} // namespace OHOS

#endif // EDM_UNIT_TEST_EXTERNAL_INCLUDE_MOCK_EXTERNAL_MANAGER_FACTORY_MOCK_H