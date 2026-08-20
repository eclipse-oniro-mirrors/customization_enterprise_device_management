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

#ifndef INTERFACES_INNER_API_PLUGIN_KITS_INCLUDE_IEDM_FORM_MANAGER_H
#define INTERFACES_INNER_API_PLUGIN_KITS_INCLUDE_IEDM_FORM_MANAGER_H

#include "want.h"

namespace OHOS {
namespace EDM {
class IEdmFormManager {
public:
    static IEdmFormManager *GetInstance();

    virtual ~IEdmFormManager() = default;

    virtual ErrCode RequestPublishFormCrossUser(AAFwk::Want &want, int32_t userId, int64_t &formId)
    {
        return -1;
    }

    static IEdmFormManager *iInstance_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_PLUGIN_KITS_INCLUDE_IEDM_FORM_MANAGER_H
