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

#ifndef SERVICES_EDM_INCLUDE_BACKUP_ERROR_MAPPER_H
#define SERVICES_EDM_INCLUDE_BACKUP_ERROR_MAPPER_H

#include <cstdint>
#include <string>

#include "edm_errors.h"

namespace OHOS {
namespace EDM {

class BackupErrorMapper {
public:
    static uint32_t ToBackupResultCode(ErrCode internal);

    static uint32_t PassThroughApCode(int32_t apCode);

    static std::string GetErrorMessage(uint32_t resultCode);
};

} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_BACKUP_ERROR_MAPPER_H
