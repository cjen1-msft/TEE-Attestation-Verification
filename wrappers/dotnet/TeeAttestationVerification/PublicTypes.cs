// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace TeeAttestationVerification;

public enum ErrorCode
{
    Ok = 0,
    InvalidArgument = 1,
    ErrorIsNull = 2,
    Panic = 3,
    UnsupportedProcessor = 101,
    InvalidRootCertificate = 102,
    CertificateChainError = 103,
    SignatureVerificationError = 104,
    TcbVerificationError = 105,
    CoseCbor = 201,
    CoseUnexpectedType = 202,
    CoseUnsupportedAlgorithm = 203,
    CoseKeyImport = 204,
    CoseVerification = 205,
    CaciCose = 301,
    CaciCertificate = 302,
    CaciDidX509 = 303,
    CaciSignature = 304,
    CaciMeasurement = 305,
    CaciPolicy = 306,
}

public enum CborKind
{
    Int = 1,
    Simple = 2,
    Bytes = 3,
    Text = 4,
    Array = 5,
    Map = 6,
    Tagged = 7,
}

public sealed class VerifyException : Exception
{
    internal VerifyException(ErrorCode code, string message)
        : base(message)
    {
        Code = code;
    }

    public ErrorCode Code { get; }
}
