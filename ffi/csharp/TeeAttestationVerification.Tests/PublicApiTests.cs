// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;
using System.Text;

namespace TeeAttestationVerification.Tests;

public sealed class PublicApiTests
{
    [Fact]
    public void PublicApiMatchesReviewedSnapshot()
    {
        Assembly assembly = typeof(AttestationVerifier).Assembly;
        string actual = string.Join(
            Environment.NewLine,
            assembly.GetExportedTypes()
                .OrderBy(type => type.FullName, StringComparer.Ordinal)
                .SelectMany(DescribeType)) + Environment.NewLine;
        string expected = File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "expected-api.txt"),
            Encoding.UTF8).ReplaceLineEndings();

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ErrorCodeValuesMatchNativeAbi()
    {
        Assert.Equal(0, (int)ErrorCode.Ok);
        Assert.Equal(1, (int)ErrorCode.InvalidArgument);
        Assert.Equal(2, (int)ErrorCode.ErrorIsNull);
        Assert.Equal(3, (int)ErrorCode.Panic);
        Assert.Equal(101, (int)ErrorCode.UnsupportedProcessor);
        Assert.Equal(102, (int)ErrorCode.InvalidRootCertificate);
        Assert.Equal(103, (int)ErrorCode.CertificateChainError);
        Assert.Equal(104, (int)ErrorCode.SignatureVerificationError);
        Assert.Equal(105, (int)ErrorCode.TcbVerificationError);
        Assert.Equal(201, (int)ErrorCode.CoseCbor);
        Assert.Equal(202, (int)ErrorCode.CoseUnexpectedType);
        Assert.Equal(203, (int)ErrorCode.CoseUnsupportedAlgorithm);
        Assert.Equal(204, (int)ErrorCode.CoseKeyImport);
        Assert.Equal(205, (int)ErrorCode.CoseVerification);
        Assert.Equal(301, (int)ErrorCode.CaciCose);
        Assert.Equal(302, (int)ErrorCode.CaciCertificate);
        Assert.Equal(303, (int)ErrorCode.CaciDidX509);
        Assert.Equal(304, (int)ErrorCode.CaciSignature);
        Assert.Equal(305, (int)ErrorCode.CaciMeasurement);
        Assert.Equal(306, (int)ErrorCode.CaciPolicy);
    }

    [Fact]
    public void CborKindValuesMatchNativeAbi()
    {
        Assert.Equal(1, (int)CborKind.Int);
        Assert.Equal(2, (int)CborKind.Simple);
        Assert.Equal(3, (int)CborKind.Bytes);
        Assert.Equal(4, (int)CborKind.Text);
        Assert.Equal(5, (int)CborKind.Array);
        Assert.Equal(6, (int)CborKind.Map);
        Assert.Equal(7, (int)CborKind.Tagged);
    }

    private static IEnumerable<string> DescribeType(Type type)
    {
        string modifiers = type.IsAbstract && type.IsSealed
            ? "public static class"
            : type.IsEnum
                ? "public enum"
                : type.IsSealed ? "public sealed class" : "public class";
        string inheritance = type.BaseType == typeof(Exception) ? " : Exception" : string.Empty;
        yield return $"{modifiers} {Display(type)}{inheritance}";

        if (type.IsEnum)
        {
            foreach (string name in Enum.GetNames(type))
            {
                yield return $"  {name} = {Convert.ToInt64(Enum.Parse(type, name))}";
            }

            yield break;
        }

        const BindingFlags flags =
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        foreach (PropertyInfo property in type.GetProperties(flags)
                     .OrderBy(property => property.Name, StringComparer.Ordinal))
        {
            yield return $"  property {Display(property.PropertyType)} {property.Name} {{ get; }}";
        }

        foreach (MethodInfo method in type.GetMethods(flags)
                     .Where(method => !method.IsSpecialName)
                     .OrderBy(method => method.Name, StringComparer.Ordinal)
                     .ThenBy(method => string.Join(",", method.GetParameters().Select(
                         parameter => Display(parameter.ParameterType))), StringComparer.Ordinal))
        {
            string obsolete = method.GetCustomAttribute<ObsoleteAttribute>() is null
                ? string.Empty
                : "[Obsolete] ";
            string parameters = string.Join(
                ", ",
                method.GetParameters().Select(parameter =>
                    $"{Display(parameter.ParameterType)} {parameter.Name}"));
            yield return $"  {obsolete}method {Display(method.ReturnType)} {method.Name}({parameters})";
        }
    }

    private static string Display(Type type)
    {
        if (type.IsArray)
        {
            return $"{Display(type.GetElementType()!)}[]";
        }

        if (type.IsGenericType)
        {
            string name = type.Name[..type.Name.IndexOf('`')];
            return $"{name}<{string.Join(", ", type.GetGenericArguments().Select(Display))}>";
        }

        return type switch
        {
            _ when type == typeof(void) => "void",
            _ when type == typeof(bool) => "bool",
            _ when type == typeof(byte) => "byte",
            _ when type == typeof(int) => "int",
            _ when type == typeof(long) => "long",
            _ when type == typeof(uint) => "uint",
            _ when type == typeof(ulong) => "ulong",
            _ when type == typeof(string) => "string",
            _ => type.Name,
        };
    }
}
