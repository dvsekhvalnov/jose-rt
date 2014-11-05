using JoseRT.util;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Win8Tests
{
    [TestClass]
    public class ArraysTest
    {
        [TestMethod]
        public void Concat()
        {
            //given
            byte[] zeros = null;
            byte[] first = { 0, 1 };
            byte[] second = { 2, 3, 4, 5 };
            byte[] third = { 6, 7, 8, 9 };
            byte[] forth = null;

            //then
            CollectionAssert.AreEqual(Arrays.Concat(zeros, first, second, third, forth), new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 });
        }

        [TestMethod]
        public void FirstHalf()
        {
            //given
            byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

            //then
            CollectionAssert.AreEqual(Arrays.FirstHalf(data), new byte[] { 0, 1, 2, 3, 4 });
        }

        [TestMethod]
        public void SecondHalf()
        {
            //given
            byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

            //then
            CollectionAssert.AreEqual(Arrays.SecondHalf(data), new byte[] { 5, 6, 7, 8, 9 });
        }

        [TestMethod]
        public void LongToBytes()
        {
            CollectionAssert.AreEqual(Arrays.LongToBytes(255), new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF });
            CollectionAssert.AreEqual(Arrays.LongToBytes(-2), new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE });
        }



    }
}