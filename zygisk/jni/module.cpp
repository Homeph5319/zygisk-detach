#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include "parcel.hpp"
#include "zygisk.hpp"

#define LOGD(fmt, ...) \
    __android_log_print(ANDROID_LOG_DEBUG, "zygisk-detach", "[%d] " fmt, __LINE__, ##__VA_ARGS__)

#define ARR_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define STR_LEN(a) (ARR_LEN(a) - 1)
#define VENDING_PROC "com.android.vending"
#define LIBBINDER "libbinder.so"

#define PM_DESCRIPTOR_DESC u"android.content.pm.IPackageManager"

static char* DETACH_TXT;
static size_t HEADERS_LEN = 0;
static uint32_t getApplicationEnabledSetting_code = 0;

static inline void detach(PParcel* pparcel, uint32_t code) {
    auto parcel = FakeParcel(pparcel->data);
    if (pparcel->data_size < HEADERS_LEN + 4) return;
    parcel.skip(HEADERS_LEN);  // header

    auto descLen = parcel.readInt32();
    auto desc = parcel.readString16(descLen);

    if (code != getApplicationEnabledSetting_code ||
        STR_LEN(PM_DESCRIPTOR_DESC) != descLen ||
        memcmp(desc, PM_DESCRIPTOR_DESC, descLen * sizeof(char16_t)) != 0) {
        return;
    }
    parcel.skip(2);

    auto pkgLen = parcel.readInt32();
    auto pkg = parcel.readString16(pkgLen);

    auto pkgLenB = (uint8_t)(pkgLen * 2 - 1);
    size_t i = 0;
    uint8_t dlen;
    while ((dlen = DETACH_TXT[i])) {
        const char* dptr = DETACH_TXT + i + sizeof(dlen);
        i += sizeof(dlen) + dlen;
        if (dlen != pkgLenB) continue;
        if (memcmp(dptr, pkg, dlen) == 0) {
            *pkg = 0;
            return;
        }
    }
}

int (*transact_orig)(void*, int32_t, uint32_t, void*, void*, uint32_t);

int transact_hook(void* self, int32_t handle, uint32_t code, void* pdata, void* preply, uint32_t flags) {
    auto parcel = (PParcel*)pdata;
    detach(parcel, code);
    return transact_orig(self, handle, code, pdata, preply, flags);
}

static uint32_t getStaticIntFieldJni(JNIEnv* env, const char* cls_name, const char* field_name) {
    jclass cls = env->FindClass(cls_name);
    if (cls == nullptr) {
        env->ExceptionClear();
        LOGD("ERROR getStaticIntFieldJni: Could not get class '%s'", cls_name);
        return 0;
    }
    jfieldID field = env->GetStaticFieldID(cls, field_name, "I");
    if (field == nullptr) {
        env->ExceptionClear();
        LOGD("ERROR getStaticIntFieldJni: Could not get field %s.%s", cls_name, field_name);
        return 0;
    }
    jint val = env->GetStaticIntField(cls, field);
    return val;
}

static size_t read_companion(int fd) {
    off_t size;
    if (read(fd, &size, sizeof(size)) < 0) {
        LOGD("ERROR read: %s", strerror(errno));
        return 0;
    }
    if (size <= 0) {
        LOGD("ERROR read_companion: size=%ld", size);
        return 0;
    }
    DETACH_TXT = (char*)malloc(size + 1);

    off_t size_read = 0;
    while (size_read < size) {
        ssize_t ret = read(fd, DETACH_TXT, size - size_read);
        if (ret < 0) {
            LOGD("ERROR read: %s", strerror(errno));
            return 0;
        } else {
            size_read += ret;
        }
    }
    DETACH_TXT[size] = 0;
    return (size_t)size;
}

static bool getBinder(ino_t* inode, dev_t* dev) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char mapbuf[256], flags[8];
    while (fgets(mapbuf, sizeof(mapbuf), fp)) {
        unsigned int dev_major, dev_minor;
        int cur = 0;
        sscanf(mapbuf, "%*s %s %*x %x:%x %lu %*s%n", flags, &dev_major, &dev_minor, inode, &cur);
        if (cur < (int)STR_LEN(LIBBINDER)) continue;
        if (memcmp(&mapbuf[cur - STR_LEN(LIBBINDER)], LIBBINDER, STR_LEN(LIBBINDER)) == 0 && flags[2] == 'x') {
            *dev = makedev(dev_major, dev_minor);
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}

static bool run(const char* process, zygisk::Api* api, JNIEnv* env) {
    if (memcmp(process, VENDING_PROC, STR_LEN(VENDING_PROC)) != 0) return false;

    getApplicationEnabledSetting_code = getStaticIntFieldJni(env, STUB("android/content/pm/IPackageManager"),
                                                             TRSCTN("getApplicationEnabledSetting"));
    if (getApplicationEnabledSetting_code == 0) return false;

    int fd = api->connectCompanion();
    size_t detach_len = read_companion(fd);
    close(fd);
    if (detach_len == 0) return false;

    int sdk = android_get_device_api_level();
    if (sdk <= 0) {
        LOGD("ERROR android_get_device_api_level: %d", sdk);
        return false;
    }
    HEADERS_LEN = getBinderHeadersLen(sdk);

    ino_t inode;
    dev_t dev;
    if (!getBinder(&inode, &dev)) {
        LOGD("ERROR: Could not get libbinder");
        return false;
    }

    api->pltHookRegister(dev, inode, "_ZN7android14IPCThreadState8transactEijRKNS_6ParcelEPS1_j",
                         (void**)&transact_hook, (void**)&transact_orig);
    if (!api->pltHookCommit()) {
        LOGD("ERROR: pltHookCommit");
        return false;
    }

    LOGD("Loaded: %s", process);
    return true;
}

class ZygiskDetach : public zygisk::ModuleBase {
   public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        const char* process = env->GetStringUTFChars(args->nice_name, nullptr);
        bool r = run(process, api, env);
        env->ReleaseStringUTFChars(args->nice_name, process);

        if (!r) api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

   private:
    zygisk::Api* api;
    JNIEnv* env;
};

static void companion_handler(int remote_fd) {
    off_t size = 0;
    int fd = open("/data/adb/zygisk-detach/detach.bin", O_RDONLY);
    if (fd == -1) {
        LOGD("ERROR open: %s", strerror(errno));
        goto bail;
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        LOGD("ERROR fstat: %s", strerror(errno));
        goto bail;
    }
    size = st.st_size;

bail:
    if (write(remote_fd, &size, sizeof(size)) < 0) {
        LOGD("ERROR write: %s", strerror(errno));
        size = 0;
    }
    if (fd > 0) {
        if (size > 0 && sendfile(remote_fd, fd, NULL, size) < 0) {
            LOGD("ERROR sendfile: %s", strerror(errno));
        }
        close(fd);
    }
}

REGISTER_ZYGISK_MODULE(ZygiskDetach)
REGISTER_ZYGISK_COMPANION(companion_handler)
