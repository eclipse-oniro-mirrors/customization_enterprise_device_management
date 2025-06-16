/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CUSTOMIZATION_ENTERPRISE_DEVICE_MANAGEMENT_APP_DISTRIBUTION_TYPE_H
#define CUSTOMIZATION_ENTERPRISE_DEVICE_MANAGEMENT_APP_DISTRIBUTION_TYPE_H

namespace OHOS {
namespace EDM {
enum class AppDistributionType {
    APP_GALLERY = 1,
    ENTERPRISE = 2,
    ENTERPRISE_NORMAL = 3,
    ENTERPRISE_MDM = 4,
    INTERNALTESTING = 5,
    CROWDTESTING = 6,
};
}
}

#endif //CUSTOMIZATION_ENTERPRISE_DEVICE_MANAGEMENT_APP_DISTRIBUTION_TYPE_H
