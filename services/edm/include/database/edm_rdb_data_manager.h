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

#ifndef SERVICES_EDM_INCLUDE_DATABASE_EDM_RDB_DATA_MANAGER_H
#define SERVICES_EDM_INCLUDE_DATABASE_EDM_RDB_DATA_MANAGER_H

#include "rdb_helper.h"

namespace OHOS {
namespace EDM {
class EdmRdbDataManager {
public:
    EdmRdbDataManager() = default;
    ~EdmRdbDataManager() = default;
    static std::shared_ptr<EdmRdbDataManager> GetInstance();
    bool CreateTable(const std::string &createTableSql);
    bool Insert(const std::string &tableName, const NativeRdb::ValuesBucket &valuesBucket);
    bool Delete(const NativeRdb::AbsRdbPredicates &predicates);
    bool Update(const NativeRdb::ValuesBucket &valuesBucket, const NativeRdb::AbsRdbPredicates &predicates);
    std::shared_ptr<NativeRdb::ResultSet> Query(const NativeRdb::AbsRdbPredicates &predicates,
        const std::vector<std::string> &columns);
private:
    static std::shared_ptr<NativeRdb::RdbStore> GetRdbStore();
    static std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
    static std::shared_ptr<EdmRdbDataManager> instance_;
    static std::mutex mutexLock_;
};
}  // namespace EDM
}  // namespace OHOS

#endif  // SERVICES_EDM_INCLUDE_DATABASE_EDM_RDB_DATA_MANAGER_H