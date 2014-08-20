using System.Runtime.InteropServices.WindowsRuntime;

namespace JoseRT.Jws
{
    public interface IJwsSigner
    {
        byte[] Sign([ReadOnlyArray] byte[] securedInput, object key);
        bool Verify([ReadOnlyArray] byte[] signature, [ReadOnlyArray] byte[] securedInput, object key);
        string Name { get; }
    }
}