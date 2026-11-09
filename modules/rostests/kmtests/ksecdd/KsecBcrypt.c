/*
 * PROJECT:     LiberNT Kernel-Mode Test Suite
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Validate the kernel BCrypt primitive surface with known answers
 * COPYRIGHT:   Copyright 2026 Ahmed Arif
 */

#include <kmt_test.h>
#include <bcrypt.h>

#define TEST_TAG 'tCbK'

static const WCHAR AesCmacAlgorithm[] = L"AES-CMAC";
static const WCHAR Sp800108Algorithm[] = L"SP800_108_CTR_HMAC";

static const UCHAR Sha256Abc[] =
{
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

static const UCHAR HmacSha256QuickFox[] =
{
    0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24,
    0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
    0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59,
    0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8
};

static const UCHAR AesCmacEmpty[] =
{
    0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
    0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46
};

static const UCHAR Pbkdf2Sha256OneIteration[] =
{
    0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
    0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
    0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
    0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b
};

static const UCHAR Sp800108HmacSha256[] =
{
    0x3d, 0xb7, 0x7b, 0x1c, 0x21, 0x6e, 0x64, 0x41,
    0xc3, 0x01, 0xee, 0xf7, 0x0b, 0x5e, 0x39, 0x47,
    0xb8, 0x31, 0x83, 0x16, 0xd4, 0xa8, 0x2a, 0x7e,
    0x78, 0xbb, 0x56, 0xb8, 0xd2, 0xa3, 0x41, 0x8b
};

static const UCHAR GcmKey[] =
{
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};

static const UCHAR GcmNonce[] =
{
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xde, 0xca, 0xf8, 0x88
};

static const UCHAR GcmAad[] =
{
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2
};

static const UCHAR GcmPlainText[] =
{
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39
};

static const UCHAR GcmCipherText[] =
{
    0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
    0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
    0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
    0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
    0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
    0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
    0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
    0x3d, 0x58, 0xe0, 0x91
};

static const UCHAR GcmTag[] =
{
    0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
    0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47
};

static const UCHAR HkdfSalt[] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c
};

static const UCHAR HkdfInfo[] =
{
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9
};

static const UCHAR HkdfPrk[] =
{
    0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
    0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
    0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
    0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
};

static const UCHAR HkdfOkm[] =
{
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
    0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
    0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
    0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
    0x58, 0x65
};

static const UCHAR ChaChaKey[] =
{
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
};

static const UCHAR ChaChaNonce[] =
{
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
    0x44, 0x45, 0x46, 0x47
};

static const UCHAR ChaChaAad[] =
{
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7
};

static const UCHAR ChaChaPlainText[] =
{
    0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
    0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
    0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
    0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
    0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
    0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
    0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
    0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
    0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
    0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
    0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
    0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
    0x74, 0x2e
};

static const UCHAR ChaChaCipherText[] =
{
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
    0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
    0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
    0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
    0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
    0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
    0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
    0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
    0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
    0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
    0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
    0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
    0x61, 0x16
};

static const UCHAR ChaChaTag[] =
{
    0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
    0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
};

static VOID
CheckBytes(
    _In_ PCSTR Name,
    _In_reads_bytes_(Size) const UCHAR *Actual,
    _In_reads_bytes_(Size) const UCHAR *Expected,
    _In_ SIZE_T Size)
{
    ok(RtlCompareMemory(Actual, Expected, Size) == Size,
       "%s known-answer mismatch\n", Name);
}

static VOID
TestSha256(VOID)
{
    static const UCHAR Input[] = {'a', 'b', 'c'};
    BCRYPT_ALG_HANDLE Algorithm = NULL;
    BCRYPT_HASH_HANDLE Hash = NULL;
    PUCHAR Object = NULL;
    UCHAR Output[sizeof(Sha256Abc)];
    ULONG ObjectSize = 0, ResultSize = 0;
    NTSTATUS Status;

    Status = BCryptOpenAlgorithmProvider(&Algorithm,
                                         BCRYPT_SHA256_ALGORITHM,
                                         NULL,
                                         BCRYPT_HASH_REUSABLE_FLAG);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    Status = BCryptGetProperty(Algorithm, BCRYPT_OBJECT_LENGTH,
                               (PUCHAR)&ObjectSize, sizeof(ObjectSize),
                               &ResultSize, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_ulong(ResultSize, sizeof(ObjectSize));
    ok(ObjectSize != 0, "zero hash object size\n");
    Object = ExAllocatePoolWithTag(NonPagedPoolNx, ObjectSize, TEST_TAG);
    ok(Object != NULL, "hash object allocation failed\n");
    if (Object == NULL)
        goto Cleanup;

    Status = BCryptCreateHash(Algorithm, &Hash, Object, ObjectSize,
                              NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto Cleanup;
    Status = BCryptHashData(Hash, (PUCHAR)Input, sizeof(Input), 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = BCryptFinishHash(Hash, Output, sizeof(Output), 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    CheckBytes("SHA-256", Output, Sha256Abc, sizeof(Output));

    Status = BCryptHashData(Hash, (PUCHAR)Input, sizeof(Input), 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = BCryptFinishHash(Hash, Output, sizeof(Output), 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    CheckBytes("reusable SHA-256", Output, Sha256Abc, sizeof(Output));

Cleanup:
    if (Hash != NULL)
    {
        Status = BCryptDestroyHash(Hash);
        ok_eq_hex(Status, STATUS_SUCCESS);
    }
    if (Object != NULL)
        ExFreePoolWithTag(Object, TEST_TAG);
    Status = BCryptCloseAlgorithmProvider(Algorithm, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
}

static VOID
TestHmacSha256(VOID)
{
    static const UCHAR Key[] = {'k', 'e', 'y'};
    static const UCHAR Input[] = "The quick brown fox jumps over the lazy dog";
    BCRYPT_ALG_HANDLE Algorithm = NULL;
    BCRYPT_HASH_HANDLE Hash = NULL;
    UCHAR Output[sizeof(HmacSha256QuickFox)];
    NTSTATUS Status;

    Status = BCryptOpenAlgorithmProvider(&Algorithm, BCRYPT_SHA256_ALGORITHM,
                                         NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    Status = BCryptCreateHash(Algorithm, &Hash, NULL, 0,
                              (PUCHAR)Key, sizeof(Key), 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Status = BCryptHashData(Hash, (PUCHAR)Input, sizeof(Input) - 1, 0);
        ok_eq_hex(Status, STATUS_SUCCESS);
        Status = BCryptFinishHash(Hash, Output, sizeof(Output), 0);
        ok_eq_hex(Status, STATUS_SUCCESS);
        CheckBytes("HMAC-SHA-256", Output, HmacSha256QuickFox, sizeof(Output));
        Status = BCryptDestroyHash(Hash);
        ok_eq_hex(Status, STATUS_SUCCESS);
    }
    Status = BCryptCloseAlgorithmProvider(Algorithm, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
}

static VOID
TestAesCmac(VOID)
{
    static const UCHAR Key[] =
    {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    BCRYPT_ALG_HANDLE Algorithm = NULL;
    BCRYPT_HASH_HANDLE Hash = NULL;
    UCHAR Output[sizeof(AesCmacEmpty)];
    NTSTATUS Status;

    Status = BCryptOpenAlgorithmProvider(&Algorithm, AesCmacAlgorithm, NULL, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    Status = BCryptCreateHash(Algorithm, &Hash, NULL, 0,
                              (PUCHAR)Key, sizeof(Key), 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Status = BCryptHashData(Hash, NULL, 0, 0);
        ok_eq_hex(Status, STATUS_SUCCESS);
        Status = BCryptFinishHash(Hash, Output, sizeof(Output), 0);
        ok_eq_hex(Status, STATUS_SUCCESS);
        CheckBytes("AES-CMAC", Output, AesCmacEmpty, sizeof(Output));
        Status = BCryptDestroyHash(Hash);
        ok_eq_hex(Status, STATUS_SUCCESS);
    }
    Status = BCryptCloseAlgorithmProvider(Algorithm, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
}

static VOID
TestAesCbcDecrypt(VOID)
{
    static const UCHAR KeyBytes[] =
    {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    static const UCHAR InitialVector[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const UCHAR CipherText[] =
    {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d
    };
    static const UCHAR PlainText[] =
    {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    BCRYPT_ALG_HANDLE Algorithm = NULL;
    BCRYPT_KEY_HANDLE Key = NULL;
    UCHAR Iv[sizeof(InitialVector)], Output[sizeof(PlainText)];
    ULONG ResultSize = 0;
    NTSTATUS Status;

    Status = BCryptOpenAlgorithmProvider(&Algorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    Status = BCryptSetProperty(Algorithm, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                               sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = BCryptGenerateSymmetricKey(Algorithm, &Key, NULL, 0,
                                        (PUCHAR)KeyBytes, sizeof(KeyBytes), 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        RtlCopyMemory(Iv, InitialVector, sizeof(Iv));
        Status = BCryptDecrypt(Key, (PUCHAR)CipherText, sizeof(CipherText),
                               NULL, Iv, sizeof(Iv), Output, sizeof(Output),
                               &ResultSize, 0);
        ok_eq_hex(Status, STATUS_SUCCESS);
        ok_eq_ulong(ResultSize, sizeof(Output));
        CheckBytes("AES-CBC decrypt", Output, PlainText, sizeof(Output));
        Status = BCryptDestroyKey(Key);
        ok_eq_hex(Status, STATUS_SUCCESS);
    }
    Status = BCryptCloseAlgorithmProvider(Algorithm, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
}

static VOID
TestKdf(
    _In_ PCWSTR AlgorithmName,
    _In_ BOOLEAN Sp800)
{
    static const UCHAR Password[] = "password";
    static const UCHAR Salt[] = "salt";
    static const UCHAR Sp800Key[20] =
    {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b
    };
    static const UCHAR Label[] = "label";
    static const UCHAR Context[] = "context";
    BCRYPT_ALG_HANDLE Algorithm = NULL;
    BCRYPT_KEY_HANDLE Key = NULL;
    BCryptBuffer Buffers[3];
    BCryptBufferDesc Description;
    UCHAR Output[32];
    UINT64 Iterations = 1;
    ULONG ResultSize = 0;
    NTSTATUS Status;

    Status = BCryptOpenAlgorithmProvider(&Algorithm, AlgorithmName, NULL, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    Status = BCryptGenerateSymmetricKey(Algorithm, &Key, NULL, 0,
                                        (PUCHAR)(Sp800 ? Sp800Key : Password),
                                        Sp800 ? sizeof(Sp800Key) : sizeof(Password) - 1,
                                        0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto Cleanup;

    Buffers[0].BufferType = KDF_HASH_ALGORITHM;
    Buffers[0].pvBuffer = (PVOID)BCRYPT_SHA256_ALGORITHM;
    Buffers[0].cbBuffer = sizeof(BCRYPT_SHA256_ALGORITHM);
    if (Sp800)
    {
        Buffers[1].BufferType = KDF_LABEL;
        Buffers[1].pvBuffer = (PVOID)Label;
        Buffers[1].cbBuffer = sizeof(Label) - 1;
        Buffers[2].BufferType = KDF_CONTEXT;
        Buffers[2].pvBuffer = (PVOID)Context;
        Buffers[2].cbBuffer = sizeof(Context) - 1;
    }
    else
    {
        Buffers[1].BufferType = KDF_SALT;
        Buffers[1].pvBuffer = (PVOID)Salt;
        Buffers[1].cbBuffer = sizeof(Salt) - 1;
        Buffers[2].BufferType = KDF_ITERATION_COUNT;
        Buffers[2].pvBuffer = &Iterations;
        Buffers[2].cbBuffer = sizeof(Iterations);
    }
    Description.ulVersion = BCRYPTBUFFER_VERSION;
    Description.cBuffers = RTL_NUMBER_OF(Buffers);
    Description.pBuffers = Buffers;

    Status = BCryptKeyDerivation(Key, &Description, Output, sizeof(Output),
                                 &ResultSize, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_ulong(ResultSize, sizeof(Output));
    if (NT_SUCCESS(Status))
        CheckBytes(Sp800 ? "SP800-108-HMAC-SHA-256" : "PBKDF2-HMAC-SHA-256",
                   Output,
                   Sp800 ? Sp800108HmacSha256 : Pbkdf2Sha256OneIteration,
                   sizeof(Output));
    Status = BCryptDestroyKey(Key);
    ok_eq_hex(Status, STATUS_SUCCESS);

Cleanup:
    Status = BCryptCloseAlgorithmProvider(Algorithm, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
}

static VOID
TestAead(
    _In_ PCSTR Name,
    _In_ PCWSTR AlgorithmName,
    _In_ BOOLEAN Gcm,
    _In_reads_bytes_(KeySize) const UCHAR *KeyBytes,
    _In_ ULONG KeySize,
    _In_reads_bytes_(12) const UCHAR *Nonce,
    _In_reads_bytes_(AadSize) const UCHAR *Aad,
    _In_ ULONG AadSize,
    _In_reads_bytes_(TextSize) const UCHAR *PlainText,
    _In_reads_bytes_(TextSize) const UCHAR *CipherText,
    _In_ ULONG TextSize,
    _In_reads_bytes_(16) const UCHAR *ExpectedTag)
{
    BCRYPT_ALG_HANDLE Algorithm = NULL;
    BCRYPT_KEY_HANDLE Key = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO AuthInfo;
    BCRYPT_AUTH_TAG_LENGTHS_STRUCT TagLengths;
    UCHAR Buffer[128], Tag[16];
    ULONG ResultSize = 0;
    NTSTATUS Status;

    ok(TextSize <= sizeof(Buffer), "%s vector does not fit\n", Name);
    if (TextSize > sizeof(Buffer))
        return;

    Status = BCryptOpenAlgorithmProvider(&Algorithm, AlgorithmName, NULL,
                                         BCRYPT_PROV_DISPATCH);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    if (Gcm)
    {
        Status = BCryptSetProperty(Algorithm, BCRYPT_CHAINING_MODE,
                                   (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                   sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        ok_eq_hex(Status, STATUS_SUCCESS);
    }

    Status = BCryptGetProperty(Algorithm, BCRYPT_AUTH_TAG_LENGTH,
                               (PUCHAR)&TagLengths, sizeof(TagLengths),
                               &ResultSize, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_ulong(ResultSize, sizeof(TagLengths));
    if (NT_SUCCESS(Status))
    {
        ok_eq_ulong(TagLengths.dwMinLength, Gcm ? 12UL : 16UL);
        ok_eq_ulong(TagLengths.dwMaxLength, 16UL);
        ok_eq_ulong(TagLengths.dwIncrement, Gcm ? 1UL : 0UL);
    }

    Status = BCryptGenerateSymmetricKey(Algorithm, &Key, NULL, 0,
                                        (PUCHAR)KeyBytes, KeySize, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto Cleanup;

    BCRYPT_INIT_AUTH_MODE_INFO(AuthInfo);
    AuthInfo.pbNonce = (PUCHAR)Nonce;
    AuthInfo.cbNonce = 12;
    AuthInfo.pbAuthData = (PUCHAR)Aad;
    AuthInfo.cbAuthData = AadSize;
    AuthInfo.pbTag = Tag;
    AuthInfo.cbTag = sizeof(Tag);

    RtlCopyMemory(Buffer, PlainText, TextSize);
    Status = BCryptEncrypt(Key, Buffer, TextSize, &AuthInfo, NULL, 0,
                           Buffer, TextSize, &ResultSize, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_ulong(ResultSize, TextSize);
    CheckBytes(Name, Buffer, CipherText, TextSize);
    CheckBytes(Name, Tag, ExpectedTag, sizeof(Tag));

    Status = BCryptDecrypt(Key, Buffer, TextSize, &AuthInfo, NULL, 0,
                           Buffer, TextSize, &ResultSize, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_ulong(ResultSize, TextSize);
    CheckBytes(Name, Buffer, PlainText, TextSize);

    RtlCopyMemory(Buffer, CipherText, TextSize);
    Tag[0] ^= 0x01;
    Status = BCryptDecrypt(Key, Buffer, TextSize, &AuthInfo, NULL, 0,
                           Buffer, TextSize, &ResultSize, 0);
    ok_eq_hex(Status, STATUS_AUTH_TAG_MISMATCH);

    Status = BCryptEncrypt(Key, Buffer, TextSize, NULL, NULL, 0,
                           Buffer, TextSize, &ResultSize, 0);
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER);

    Status = BCryptDestroyKey(Key);
    ok_eq_hex(Status, STATUS_SUCCESS);

Cleanup:
    Status = BCryptCloseAlgorithmProvider(Algorithm, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
}

static VOID
TestHkdf(
    _In_ BOOLEAN FromPrk)
{
    BCRYPT_ALG_HANDLE Algorithm = NULL;
    BCRYPT_KEY_HANDLE Key = NULL;
    BCryptBuffer Buffer;
    BCryptBufferDesc Description;
    UCHAR Ikm[22];
    UCHAR Output[sizeof(HkdfOkm)];
    ULONG ResultSize = 0;
    NTSTATUS Status;

    RtlFillMemory(Ikm, sizeof(Ikm), 0x0b);
    Status = BCryptOpenAlgorithmProvider(&Algorithm, BCRYPT_HKDF_ALGORITHM, NULL,
                                         BCRYPT_PROV_DISPATCH);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    Status = BCryptGenerateSymmetricKey(Algorithm, &Key, NULL, 0,
                                        FromPrk ? (PUCHAR)HkdfPrk : Ikm,
                                        FromPrk ? sizeof(HkdfPrk) : sizeof(Ikm),
                                        0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto Cleanup;

    Status = BCryptSetProperty(Key, BCRYPT_HKDF_HASH_ALGORITHM,
                               (PUCHAR)BCRYPT_SHA256_ALGORITHM,
                               sizeof(BCRYPT_SHA256_ALGORITHM), 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (FromPrk)
        Status = BCryptSetProperty(Key, BCRYPT_HKDF_PRK_AND_FINALIZE, NULL, 0, 0);
    else
        Status = BCryptSetProperty(Key, BCRYPT_HKDF_SALT_AND_FINALIZE,
                                   (PUCHAR)HkdfSalt, sizeof(HkdfSalt), 0);
    ok_eq_hex(Status, STATUS_SUCCESS);

    Buffer.BufferType = KDF_HKDF_INFO;
    Buffer.pvBuffer = (PVOID)HkdfInfo;
    Buffer.cbBuffer = sizeof(HkdfInfo);
    Description.ulVersion = BCRYPTBUFFER_VERSION;
    Description.cBuffers = 1;
    Description.pBuffers = &Buffer;

    Status = BCryptKeyDerivation(Key, &Description, Output, sizeof(Output),
                                 &ResultSize, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_ulong(ResultSize, sizeof(Output));
    if (NT_SUCCESS(Status))
        CheckBytes(FromPrk ? "HKDF-SHA-256 expand" : "HKDF-SHA-256",
                   Output, HkdfOkm, sizeof(Output));
    Status = BCryptDestroyKey(Key);
    ok_eq_hex(Status, STATUS_SUCCESS);

Cleanup:
    Status = BCryptCloseAlgorithmProvider(Algorithm, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
}

static VOID
TestRandom(VOID)
{
    UCHAR First[32] = {0}, Second[32] = {0};
    UCHAR Zero[32] = {0};
    NTSTATUS Status;

    Status = BCryptGenRandom(NULL, First, sizeof(First), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = BCryptGenRandom(NULL, Second, sizeof(Second), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok(RtlCompareMemory(First, Zero, sizeof(First)) != sizeof(First),
       "RNG returned all zeroes\n");
    ok(RtlCompareMemory(First, Second, sizeof(First)) != sizeof(First),
       "two RNG calls returned identical output\n");
}

START_TEST(KsecBcrypt)
{
    LONG SuccessesBefore = ResultBuffer->Successes;
    LONG FailuresBefore = ResultBuffer->Failures;

    TestSha256();
    TestHmacSha256();
    TestAesCmac();
    TestAesCbcDecrypt();
    TestKdf(BCRYPT_PBKDF2_ALGORITHM, FALSE);
    TestKdf(Sp800108Algorithm, TRUE);
    TestAead("AES-GCM", BCRYPT_AES_ALGORITHM, TRUE,
             GcmKey, sizeof(GcmKey), GcmNonce, GcmAad, sizeof(GcmAad),
             GcmPlainText, GcmCipherText, sizeof(GcmPlainText), GcmTag);
    TestAead("ChaCha20-Poly1305", BCRYPT_CHACHA20_POLY1305_ALGORITHM, FALSE,
             ChaChaKey, sizeof(ChaChaKey), ChaChaNonce, ChaChaAad, sizeof(ChaChaAad),
             ChaChaPlainText, ChaChaCipherText, sizeof(ChaChaPlainText), ChaChaTag);
    TestHkdf(FALSE);
    TestHkdf(TRUE);
    TestRandom();

    if (ResultBuffer->Failures == FailuresBefore)
    {
        DbgPrint("KSEC_BCRYPT_KMTEST_PASS checks=%ld\n",
                 ResultBuffer->Successes - SuccessesBefore);
    }
}
