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

#ifndef ENTERPRISE_DEVICE_MANAGEMENT_DISALLOWED_BLUETOOTH_PROTOCOLS_PLUGIN_H
#define ENTERPRISE_DEVICE_MANAGEMENT_DISALLOWED_BLUETOOTH_PROTOCOLS_PLUGIN_H

#include "bluetooth_protocol_models.h"
#include "plugin_singleton.h"

namespace OHOS {
namespace EDM {
class DisallowedBluetoothProtocolsPlugin : public PluginSingleton<DisallowedBluetoothProtocolsPlugin,
    BluetoothProtocolPolicy> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<DisallowedBluetoothProtocolsPlugin,
        BluetoothProtocolPolicy>> ptr) override;
    ErrCode OnSetPolicy(BluetoothProtocolPolicy &data, BluetoothProtocolPolicy &currentData,
        BluetoothProtocolPolicy &mergeData, int32_t userId);
    ErrCode OnRemovePolicy(BluetoothProtocolPolicy &data, BluetoothProtocolPolicy &currentData,
        BluetoothProtocolPolicy &mergeData, int32_t userId);
    ErrCode OnAdminRemove(const std::string &adminName, BluetoothProtocolPolicy &policyData,
        BluetoothProtocolPolicy &mergeData, int32_t userId);
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;
    void OnChangedPolicyDone(bool isGlobalChanged);

private:
    void NotifyBluetoothProtocolsChanged();
    bool ReadMergeDataFromFile(BluetoothProtocolPolicy &mergeData);
    bool WriteMergeDataToFile(const BluetoothProtocolPolicy &mergeData);
    void ConvertProtocolListToInt(const std::vector<std::string> &protocolList, std::vector<int32_t> &protocols);
    void GetSendOnlyProtocols(const BluetoothProtocolPolicy &mergeDataFromFile, int32_t accountId,
        std::vector<int32_t> &protocols);
    void GetReceiveOnlyProtocols(const BluetoothProtocolPolicy &mergeDataFromFile, int32_t accountId,
        std::vector<int32_t> &protocols);
    void GetReceiveSendProtocols(const BluetoothProtocolPolicy &mergeDataFromFile, int32_t accountId,
        std::vector<int32_t> &protocols);
    bool CreateBluetoothConfigDir(const std::string dir);
    void RemoveProtocolsFromPolicy(const std::map<int32_t, std::vector<std::string>> &source,
        std::map<int32_t, std::vector<std::string>> &target);
    void RemoveUnusedProtocolsFromFile(const std::map<int32_t, std::vector<std::string>> &data,
        const std::map<int32_t, std::vector<std::string>> &mergeData,
        std::map<int32_t, std::vector<std::string>> &mergeDataFromFile);
    bool ValidateBluetoothProtocolPolicy(const BluetoothProtocolPolicy &policy);
};
} // namespace EDM
} // namespace OHOS

#endif //ENTERPRISE_DEVICE_MANAGEMENT_DISALLOWED_BLUETOOTH_PROTOCOLS_PLUGIN_H
