using System.Security.Cryptography;

namespace Acl.Fs.Core.Abstractions.Factory;

internal interface IAesGcmFactory
{
    AesGcm Create(byte[] key);
}