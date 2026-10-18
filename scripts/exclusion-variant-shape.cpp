// Read-only, representation-preserving INetFwPolicy2 exclusion probe.
// The default and --synthetic paths never acquire a firewall COM object.
// --read must be separately reviewed and run by the physical-console operator.
#include <windows.h>
#include <netfw.h>
#include <oleauto.h>
#include <cstdio>
#include <cstring>
#include <climits>

struct VariantShape {
    unsigned int type;
    unsigned int dimensions;
    unsigned long long elements;
    HRESULT shapeError;
    bool hasArray;
};

static VariantShape Shape(const VARIANT& value) {
    VariantShape result = { static_cast<unsigned int>(V_VT(&value)), 0, 0, S_OK, false };
    if (!(V_VT(&value) & VT_ARRAY)) return result;
    result.hasArray = true;
    SAFEARRAY* array = V_ARRAY(&value);
    if (!array) { result.shapeError = E_POINTER; return result; }
    result.dimensions = SafeArrayGetDim(array);
    if (result.dimensions == 0 || result.dimensions > 8) {
        result.shapeError = E_INVALIDARG;
        return result;
    }
    result.elements = 1;
    for (unsigned int dimension = 1; dimension <= result.dimensions; ++dimension) {
        long lower = 0, upper = 0;
        HRESULT lowerResult = SafeArrayGetLBound(array, dimension, &lower);
        HRESULT upperResult = SafeArrayGetUBound(array, dimension, &upper);
        if (FAILED(lowerResult) || FAILED(upperResult)) {
            result.shapeError = FAILED(lowerResult) ? lowerResult : upperResult;
            return result;
        }
        unsigned long long length = upper < lower ? 0ULL :
            static_cast<unsigned long long>(upper - lower) + 1ULL;
        if (length && result.elements > ULLONG_MAX / length) {
            result.shapeError = E_INVALIDARG;
            return result;
        }
        result.elements *= length;
    }
    return result;
}

static void PrintShape(int profile, HRESULT getterResult, const VARIANT& value) {
    VariantShape shape = Shape(value);
    std::printf("{\"ProfileBit\":%d,\"GetterHResult\":\"0x%08lX\","
                "\"VariantType\":%u,\"HasSafeArray\":%s,"
                "\"SafeArrayDimensions\":%u,\"SafeArrayElements\":",
                profile, static_cast<unsigned long>(getterResult), shape.type,
                shape.hasArray ? "true" : "false", shape.dimensions);
    if (shape.hasArray && SUCCEEDED(shape.shapeError))
        std::printf("%llu", shape.elements);
    else std::printf("null");
    std::printf(",\"ShapeHResult\":\"0x%08lX\"}",
                static_cast<unsigned long>(shape.shapeError));
}

static int Synthetic() {
    VARIANT value;
    VariantInit(&value);
    if (Shape(value).type != VT_EMPTY || Shape(value).hasArray) return 10;
    V_VT(&value) = VT_NULL;
    if (Shape(value).type != VT_NULL || Shape(value).hasArray) return 11;
    V_VT(&value) = VT_ARRAY | VT_I4;
    V_ARRAY(&value) = SafeArrayCreateVector(VT_I4, 0, 0);
    if (!V_ARRAY(&value)) return 12;
    VariantShape empty = Shape(value);
    if (!empty.hasArray || empty.elements != 0 || FAILED(empty.shapeError)) return 13;
    VariantClear(&value);
    V_VT(&value) = VT_ARRAY | VT_I4;
    V_ARRAY(&value) = SafeArrayCreateVector(VT_I4, 0, 2);
    if (!V_ARRAY(&value)) return 14;
    VariantShape populated = Shape(value);
    if (!populated.hasArray || populated.elements != 2 || FAILED(populated.shapeError)) return 15;
    VariantClear(&value);
    std::puts("Synthetic VARIANT empty/null/zero-array/two-array shape checks passed.");
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "--synthetic") == 0) return Synthetic();
    if (argc != 2 || std::strcmp(argv[1], "--read") != 0) {
        std::fputs("Specify --synthetic; --read requires separate operator authorization.\n", stderr);
        return 2;
    }
    HRESULT initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE) return 3;
    INetFwPolicy2* policy = nullptr;
    HRESULT created = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
        CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), reinterpret_cast<void**>(&policy));
    if (FAILED(created) || !policy) {
        if (SUCCEEDED(initialized)) CoUninitialize();
        return 4;
    }
    std::printf("{\"Schema\":\"ChildStream.ExclusionVariantShape.v1\",\"Profiles\":[");
    const int bits[] = { NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC };
    for (unsigned int i = 0; i < 3; ++i) {
        VARIANT value;
        VariantInit(&value);
        HRESULT result = policy->get_ExcludedInterfaces(
            static_cast<NET_FW_PROFILE_TYPE2>(bits[i]), &value);
        if (i) std::printf(",");
        PrintShape(bits[i], result, value);
        VariantClear(&value);
    }
    std::puts("]}");
    policy->Release();
    if (SUCCEEDED(initialized)) CoUninitialize();
    return 0;
}
