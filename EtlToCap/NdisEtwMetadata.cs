using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;

namespace EtlToCap
{
    [System.Runtime.InteropServices.StructLayout(LayoutKind.Explicit, Pack = 4, Size = 48)]
    public struct NdisEtwMetadata
    {
        public NdisEtwMetadata(EventRecord record) : this((byte[])record.Properties[3].Value)
        {
            if (record.Properties.Count < 4)
                throw new ArgumentOutOfRangeException("record", record.Properties.Count, "Record Properties does not have 4 or more values");
        }

        public NdisEtwMetadata(byte[] rawBytes)
        {
            var ptr = Marshal.AllocHGlobal(48);
            try
            {
                Marshal.Copy(rawBytes, 0, ptr, 48);
                this = (NdisEtwMetadata)Marshal.PtrToStructure(ptr, typeof(NdisEtwMetadata));
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    Marshal.FreeHGlobal(ptr);
            }
        }

        public static bool isNdisEtwMetadata(EventRecord record)
        {
            if (record.Properties.Count > 3)
                return isNdisEtwMetadata((byte[])record.Properties[3].Value);

            return false;
        }

        public static bool isNdisEtwMetadata(byte[] rawBytes)
        {
            if (rawBytes.Length > 2 &&
                rawBytes[0] == 0x80 &&
                rawBytes[1] == 0x01 &&
                rawBytes[2] == 0x30)
                return true;

            return false;
        }
        public static byte[] NdisEtwMetadataBytes(EventRecord record)
        {
            if (isNdisEtwMetadata(record))
                return (byte[])record.Properties[3].Value;
            else
                return new byte[0];            
        }

        public override string ToString()
        {
            string returnString = null;

            returnString = "NdisEtwMetaData:\r\n";

            foreach (var field in typeof(NdisEtwMetadata).GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public))
            {
                if (field.Name.Contains("MediaSpecificInfo")) continue;
                returnString += string.Format(" {0} {1} |", field.Name + ":", field.GetValue(this));
            }

            return returnString;
        }

        [FieldOffset(0)]
        public byte Type;
        [FieldOffset(1)]
        public byte Revision;
        [FieldOffset(2)]
        public UInt16 Size;
        [FieldOffset(4)]
        public UInt32 ReceiveFlags;
        [FieldOffset(8)]
        public UInt32 PhyId;
        [FieldOffset(12)]
        public UInt32 CenterFreq;
        [FieldOffset(16)]
        public UInt32 NumMPDUsReceived;
        [FieldOffset(20)]
        public Int32 RSSI;
        [FieldOffset(24)]
        public UInt32 DataRate;
        [FieldOffset(28)]
        public UInt32 SizeMediaSpecificInfo;
        [FieldOffset(32)]
        public UInt64 MediaSpecificInfo;
        [FieldOffset(40)]
        public UInt64 Timestamp;
    }
}
