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

#ifndef SERVICES_EDM_INCLUDE_DATABASE_EDM_RDB_OPEN_CALLBACK_H
#define SERVICES_EDM_INCLUDE_DATABASE_EDM_RDB_OPEN_CALLBACK_H

#include "rdb_open_callback.h"

namespace OHOS {
namespace EDM {
class EdmRdbOpenCallback : public NativeRdb::RdbOpenCallback {
public:
    EdmRdbOpenCallback() = default;
    ~EdmRdbOpenCallback() = default;
    int OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int OnUpgrade(NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion) override;
};
}  // namespace EDM
}  // namespace OHOS

#endif  // SERVICES_EDM_INCLUDE_DATABASE_EDM_RDB_OPEN_CALLBACK_H