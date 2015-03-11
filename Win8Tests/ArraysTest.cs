using System.Diagnostics;
using JoseRT.Util;
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

        [TestMethod]
        public void XorArrays()
        {
            //given
            byte[] data = { 0xFF, 0x00, 0xF0, 0x0F, 0x55, 0xAA, 0xBB, 0xCC };

            //when
            byte[] test = Arrays.Xor(data, new byte[] { 0x00, 0xFF, 0x0F, 0xF0, 0xAA, 0x55, 0x44, 0x33 });
            byte[] test2 = Arrays.Xor(data, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });

            //then
            CollectionAssert.AreEqual(test, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
            CollectionAssert.AreEqual(test2, new byte[] { 0x00, 0xFF, 0x0F, 0xF0, 0xAA, 0x55, 0x44, 0x33 });
        }

        [TestMethod]
        public void Xor()
        {
            //given
            byte[] data = { 0xFF, 0x00, 0xF0, 0x0F, 0x55, 0xAA, 0xBB, 0xCC };

            //when
            byte[] test = Arrays.XorLong(data, 0x00FF0FF0AA554433);
            byte[] test2 = Arrays.XorLong(data, -1);

            //then
            CollectionAssert.AreEqual(test, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
            CollectionAssert.AreEqual(test2, new byte[] { 0x00, 0xFF, 0x0F, 0xF0, 0xAA, 0x55, 0x44, 0x33 });
        }


        [TestMethod]
        public void LeftmostBits()
        {
            //given
            byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

            //then
            CollectionAssert.AreEqual(Arrays.LeftmostBits(data, 16), new byte[] { 0, 1 });
            CollectionAssert.AreEqual(Arrays.LeftmostBits(data, 72), new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8 });
        }

        [TestMethod]
        public void IntToBytes()
        {
            CollectionAssert.AreEqual(Arrays.IntToBytes(255), new byte[] { 0x00, 0x00, 0x00, 0xFF });
            CollectionAssert.AreEqual(Arrays.IntToBytes(-2), new byte[] { 0xFF, 0xFF, 0xFF, 0xFE });
        }

        [TestMethod]
        public void BytesToLong()
        {
            Assert.AreEqual(Arrays.BytesToLong(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF }), 255);
            Assert.AreEqual(Arrays.BytesToLong(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE }), -2);
        }

        [TestMethod]
        public void Slice()
        {
            //given
            byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };

            //when
            byte[][] test = Arrays.Slice(data, 3);

            //then
            CollectionAssert.AreEqual(test[0], new byte[] { 0, 1, 2 });
            CollectionAssert.AreEqual(test[1], new byte[] { 3, 4, 5 });
            CollectionAssert.AreEqual(test[2], new byte[] { 6, 7, 8 });
        }


    }
}