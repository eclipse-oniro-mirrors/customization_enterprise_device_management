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

#ifndef EDM_UNIT_TEST_SERVICE_EDM_INCLUDE_MOCK_UNINSTALL_SELF_BUNDLE_MOCK_H
#define EDM_UNIT_TEST_SERVICE_EDM_INCLUDE_MOCK_UNINSTALL_SELF_BUNDLE_MOCK_H

#include <cstdint>
#include <string>
#include <vector>

#include "bundle_installer_interface.h"
#include "bundle_mgr_interface.h"
#include "bundle_stream_installer_interface.h"
#include "install_param.h"
#include "ipc_object_stub.h"
#include "iremote_stub.h"
#include "message_parcel.h"
#include "status_receiver_interface.h"

namespace OHOS {
namespace EDM {
namespace TEST {
/**
 * Fake IBundleInstaller used by UninstallSelfByBundle tests.
 * Uninstall() reports the configured result code through the status receiver synchronously,
 * which matches the real BMS contract (the final result is delivered via IStatusReceiver).
 */
class FakeBundleInstaller : public IRemoteStub<AppExecFwk::IBundleInstaller> {
public:
    FakeBundleInstaller() = default;
    ~FakeBundleInstaller() override = default;

    bool Install(const std::string &, const AppExecFwk::InstallParam &,
        const sptr<AppExecFwk::IStatusReceiver> &) override
    {
        return false;
    }

    bool Recover(const std::string &, const AppExecFwk::InstallParam &,
        const sptr<AppExecFwk::IStatusReceiver> &) override
    {
        return false;
    }

    bool Install(const std::vector<std::string> &, const AppExecFwk::InstallParam &,
        const sptr<AppExecFwk::IStatusReceiver> &) override
    {
        return false;
    }

    bool Uninstall(const std::string &, const AppExecFwk::InstallParam &installParam,
        const sptr<AppExecFwk::IStatusReceiver> &statusReceiver) override
    {
        ++uninstallCallCount_;
        lastUserId_ = installParam.userId;
        if (!returnValue_) {
            return false;
        }
        int32_t code = resultCode_;
        if (!resultSequence_.empty()) {
            size_t index = static_cast<size_t>(uninstallCallCount_ - 1);
            code = index < resultSequence_.size() ? resultSequence_[index] : resultSequence_.back();
        }
        if (statusReceiver != nullptr) {
            statusReceiver->OnFinished(code, resultMsg_);
        }
        return true;
    }

    bool Uninstall(const AppExecFwk::UninstallParam &,
        const sptr<AppExecFwk::IStatusReceiver> &) override
    {
        return false;
    }

    bool Uninstall(const std::string &, const std::string &, const AppExecFwk::InstallParam &,
        const sptr<AppExecFwk::IStatusReceiver> &) override
    {
        return false;
    }

    ErrCode InstallSandboxApp(const std::string &, int32_t, int32_t, int32_t &) override
    {
        return ERR_OK;
    }

    ErrCode UninstallSandboxApp(const std::string &, int32_t, int32_t) override
    {
        return ERR_OK;
    }

    sptr<AppExecFwk::IBundleStreamInstaller> CreateStreamInstaller(const AppExecFwk::InstallParam &,
        const sptr<AppExecFwk::IStatusReceiver> &, const std::vector<std::string> &) override
    {
        return nullptr;
    }

    bool DestoryBundleStreamInstaller(uint32_t) override
    {
        return false;
    }

    ErrCode StreamInstall(const std::vector<std::string> &, const AppExecFwk::InstallParam &,
        const sptr<AppExecFwk::IStatusReceiver> &) override
    {
        return ERR_OK;
    }

    void SetReturnValue(bool returnValue)
    {
        returnValue_ = returnValue;
    }

    void SetResult(int32_t resultCode, const std::string &resultMsg = "")
    {
        resultCode_ = resultCode;
        resultMsg_ = resultMsg;
    }
    
    void SetResultSequence(const std::vector<int32_t> &sequence)
    {
        resultSequence_ = sequence;
    }

    int32_t GetUninstallCallCount() const
    {
        return uninstallCallCount_;
    }

    int32_t GetLastUserId() const
    {
        return lastUserId_;
    }

private:
    bool returnValue_ = true;
    int32_t resultCode_ = ERR_OK;
    std::string resultMsg_;
    std::vector<int32_t> resultSequence_;
    int32_t uninstallCallCount_ = 0;
    int32_t lastUserId_ = AppExecFwk::Constants::UNSPECIFIED_USERID;
};

/**
 * Fake IBundleMgr that only serves GetBundleInstaller, used to drive UninstallSelfByBundle.
 */
class FakeBundleMgr : public IRemoteStub<AppExecFwk::IBundleMgr> {
public:
    explicit FakeBundleMgr(const sptr<AppExecFwk::IBundleInstaller> &installer) : installer_(installer) {}
    ~FakeBundleMgr() override = default;

    sptr<AppExecFwk::IBundleInstaller> GetBundleInstaller() override
    {
        return installer_;
    }

private:
    sptr<AppExecFwk::IBundleInstaller> installer_;
};

/**
 * Remote object whose descriptor does not match IBundleMgr, so iface_cast<IBundleMgr> returns nullptr.
 * Used to drive the "remote object is not a bundle mgr" branch of UninstallOnceByBundle.
 */
class FakeNotBundleMgrRemoteObject : public IPCObjectStub {
public:
    FakeNotBundleMgrRemoteObject() : IPCObjectStub(u"ohos.edm.test.NotBundleMgr") {}
    ~FakeNotBundleMgrRemoteObject() override = default;
};

/**
 * Fake remote object used as the EDC SA endpoint. SendRequest writes the configured
 * int32 result into the reply parcel so UninstallSelfByEdc can parse it.
 */
class FakeEdcRemoteObject : public IPCObjectStub {
public:
    FakeEdcRemoteObject() : IPCObjectStub(u"hmos.edc.IEnterpriseDeviceConfiguration") {}
    ~FakeEdcRemoteObject() override = default;

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        lastCode_ = code;
        returnValue_ = reply.WriteInt32(edcResult_);
        return sendRequestResult_;
    }

    void SetSendRequestResult(int32_t result)
    {
        sendRequestResult_ = result;
    }

    void SetEdcResult(int32_t result)
    {
        edcResult_ = result;
    }

    uint32_t GetLastCode() const
    {
        return lastCode_;
    }

    bool GetReturnValue() const
    {
        return returnValue_;
    }

private:
    int32_t sendRequestResult_ = ERR_OK;
    int32_t edcResult_ = ERR_OK;
    uint32_t lastCode_ = 0;
    bool returnValue_ = false;
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_SERVICE_EDM_INCLUDE_MOCK_UNINSTALL_SELF_BUNDLE_MOCK_H
