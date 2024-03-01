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

#include "edm_rdb_open_callback.h"

#include "edm_rdb_filed_const.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
constexpr int32_t EDM_RDB_VERSION_TWO = 2;
int32_t EdmRdbOpenCallback::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    EDMLOGD("EdmRdbOpenCallback OnCreate : database create.");
    return NativeRdb::E_OK;
}

int32_t EdmRdbOpenCallback::OnUpgrade(NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    EDMLOGD("EdmRdbOpenCallback OnUpgrade : database upgrade. currentVersion = %{public}d, newVersion = %{public}d",
        currentVersion, targetVersion);
    if (currentVersion < EDM_RDB_VERSION_TWO && targetVersion >= EDM_RDB_VERSION_TWO) {
        rdbStore.ExecuteSql("ALTER TABLE " + EdmRdbFiledConst::ADMIN_POLICIES_RDB_TABLE_NAME + " ADD COLUMN " +
            EdmRdbFiledConst::FILED_IS_DEBUG + " INTEGER DEFAULT 0;");
    }
    return NativeRdb::E_OK;
}
} // namespace EDM
} // namespace OHOS