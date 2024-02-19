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

#ifndef SERVICES_EDM_INCLUDE_DATABASE_ADMIN_FILED_CONST_H
#define SERVICES_EDM_INCLUDE_DATABASE_ADMIN_FILED_CONST_H

#include <string>

namespace OHOS {
namespace EDM {
namespace EdmRdbFiledConst {
const std::string FILED_ID = "id";
const std::string FILED_USER_ID = "user_id";
const std::string FILED_ADMIN_TYPE = "admin_type";
const std::string FILED_PACKAGE_NAME = "package_name";
const std::string FILED_CLASS_NAME = "class_name";
const std::string FILED_ENT_NAME = "ent_name";
const std::string FILED_ENT_DESC = "ent_desc";
const std::string FILED_PERMISSIONS = "permissions";
const std::string FILED_SUBSCRIBE_EVENTS = "subscribe_events";
const std::string FILED_PARENT_ADMIN = "parent_admin";
const std::string FILED_IS_DEBUG = "is_debug";

const std::string FILED_ADMIN_NAME = "admin_name";
const std::string FILED_POLICY_NAME = "policy_name";
const std::string FILED_POLICY_VALUE = "policy_value";

constexpr int32_t FILED_COLUMN_INDEX_ZERO = 0;
constexpr int32_t FILED_COLUMN_INDEX_ONE = 1;
constexpr int32_t FILED_COLUMN_INDEX_TWO = 2;
constexpr int32_t FILED_COLUMN_INDEX_THREE = 3;
constexpr int32_t FILED_COLUMN_INDEX_FOUR = 4;
constexpr int32_t FILED_COLUMN_INDEX_FIVE = 5;
constexpr int32_t FILED_COLUMN_INDEX_SIX = 6;
constexpr int32_t FILED_COLUMN_INDEX_SEVEN = 7;
constexpr int32_t FILED_COLUMN_INDEX_EIGHT = 8;
constexpr int32_t FILED_COLUMN_INDEX_NINE = 9;
constexpr int32_t FILED_COLUMN_INDEX_TEN = 10;

const std::string EDM_SERVICE_DATABASE_PATH = "/data/service/el1/public/edm";
const std::string EDM_RDB_NAME = "/edmdb.db";
const std::string ADMIN_POLICIES_RDB_TABLE_NAME = "admin_policies";
const std::string DEVICE_ADMIN_POLICIES_RDB_TABLE_NAME = "device_admin_policies";
const std::string DEVICE_COMBINED_POLICIES_RDB_TABLE_NAME = "device_combined_policies";
constexpr int32_t EDM_RDB_VERSION = 2;
} // namespace EdmRdbFiledConst
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_DATABASE_ADMIN_FILED_CONST_H