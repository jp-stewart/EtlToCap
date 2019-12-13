using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics.Eventing.Reader;
using System.Reflection;
using System.Security.Cryptography;

namespace EtlToCap
{
    public class pcapng
    {
        private BinaryWriter fileWriter;
        private SectionHeaderBlock headerBlock;
        private InterfaceDescriptionBlock interfaceBlock;
        private UInt64 packetsWithHeaders = 0;
        private UInt64 packetCount = 0;
        private Int64 totalSectionCount = -1;
        private UInt32 maxPacketSize = 65535;

        public pcapng(BinaryWriter fileWriter) : this(fileWriter, 65535)
        { }
        public pcapng(BinaryWriter fileWriter, UInt32 maxpacketSize) : this(fileWriter, maxpacketSize, 1)
        { }

        public pcapng(BinaryWriter fileWriter, UInt32 maxPacketSize, UInt16 linkType)
        {
            if (fileWriter == null)
                throw new ArgumentNullException("fileWriter");

            this.fileWriter = fileWriter;
            this.maxPacketSize = maxPacketSize;

            this.headerBlock = new SectionHeaderBlock();
            this.interfaceBlock = new InterfaceDescriptionBlock(maxPacketSize, linkType);

            totalSectionCount = this.interfaceBlock.totalByteLength;

            fileWriter.Write(headerBlock.totalBytes);
            fileWriter.Write(interfaceBlock.totalBytes);
        }

        public void UpdateHeaderBlock()
        {
            headerBlock.sectionLength = totalSectionCount;

            if (fileWriter.BaseStream != null &&
                fileWriter.BaseStream.CanSeek &&
                fileWriter.BaseStream.CanWrite)
            {
                fileWriter.Seek(0, SeekOrigin.Begin);
                fileWriter.Write(headerBlock.totalBytes);
            }
        }
        
        // PCAPNG
        // Physical File Layout
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // | SHB | IDB | EPB | EPB |    ...    | EPB |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        public void writePacket(EventRecord record, byte[] headerRecord = null)
        {
            EnhancedPacketBlock packet = null;

            if (headerRecord != null && NdisEtwMetadata.isNdisEtwMetadata(headerRecord))
            {
                NdisEtwMetadata header = new NdisEtwMetadata(headerRecord);

                packet = new EnhancedPacketBlock(record, header, maxPacketSize);
                packetsWithHeaders++;
            }
            else
            {
                packet = new EnhancedPacketBlock(record, maxPacketSize);
            }

            totalSectionCount += packet.totalByteLength;
            packetCount++;

            fileWriter.Write(packet.totalBytes);
        }

    }

    public static class Utilities
    {
        public static byte[] GetStructBytes(object outputObject, int totalSize)
        {
            if (totalSize < 1)
                throw new ArgumentOutOfRangeException("totalSize", totalSize, "totalSize is <= 0");

            string typeName = outputObject.GetType().ToString();
            byte[] returnArray = new byte[totalSize];
            IntPtr ptr = Marshal.AllocHGlobal(totalSize);

            try
            {
                Marshal.StructureToPtr(outputObject, ptr, false);
                Marshal.Copy(ptr, returnArray, 0, totalSize);
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    Marshal.FreeHGlobal(ptr);
            }

            return returnArray;
        }

        public static int padLength(UInt32 value, UInt32 pad)
        {
            if (value % pad == 0)
                return (int)value;
            else
                return (int)value + ((int)pad - ((int)value % (int)pad));
        }
    }


    public class CommentBlock
    {
        // Options

        //    [<-----1----->] [<-----2----->] [<-----3----->] [<-----4----->]
        //    0                   1                   2                   3
        //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // 0 |      Option Code              |         Option Length         |
        //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // 4 /                         Option Value                          /
        //   /              variable length, padded to 32 bits               /
        //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //   /                                                               /
        //   /                  . . . other options. . .                     /
        //   /                                                               /
        //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //   |  Option Code == opt_endofopt  |       Option Length == 0      |
        //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        // Option Codes:    Code:   Length:
        // COMMENT          1       [Actual]
        // END_OF_OPTIONS   0       0

        [System.Runtime.InteropServices.StructLayout(LayoutKind.Explicit, Pack = 4, Size = 4)]
        internal struct CommentBlockStart
        {
            //Optional Comment
            [MarshalAs(UnmanagedType.U2)]
            [FieldOffset(0)]
            public UInt16 typeComment;
            //Option Length (16 bits): an unsigned value that contains the actual length of the following 
            //  'Option Value' field without the padding octets
            [FieldOffset(2)]
            [MarshalAs(UnmanagedType.U2)]
            public UInt16 optLength;
        }

        [System.Runtime.InteropServices.StructLayout(LayoutKind.Explicit, Pack = 4, Size = 4)]
        internal struct CommentBlockEnd
        {
            //End Comment
            [MarshalAs(UnmanagedType.U2)]
            [FieldOffset(0)]
            public UInt16 typeEnd;
            [MarshalAs(UnmanagedType.U2)]
            [FieldOffset(2)]
            public UInt16 optLength;
        }

        private CommentBlockStart startBlock;
        private CommentBlockEnd endBlock;
        private byte[] commentBytes;

        public CommentBlock() : this(" ")
        { }

        public CommentBlock(string comment)
        {
            commentBytes = System.Text.Encoding.UTF8.GetBytes(comment);

            startBlock = new CommentBlockStart();
            startBlock.typeComment = 0x1;
            startBlock.optLength = commentByteLength;

            endBlock = new CommentBlockEnd();
            endBlock.typeEnd = 0x0;
            endBlock.optLength = 0x0;
        }

        public UInt16 commentByteLength
        {
            get { return (UInt16)commentBytes.Length; }
        }

        public int totalByteLength
        {
            get { return Utilities.padLength(commentByteLength, 4) + 8; }
        }

        public byte[] totalBytes
        {
            get
            {
                byte[] returnBytes = new byte[totalByteLength];
                Array.Clear(returnBytes, 0, totalByteLength);

                Array.Copy(Utilities.GetStructBytes(startBlock, 4), 0, returnBytes, 0, 4);
                Array.Copy(commentBytes, 0, returnBytes, 4, commentByteLength);
                Array.Copy(Utilities.GetStructBytes(endBlock, 4), 0, returnBytes, totalByteLength - 4, 4);

                return returnBytes;
            }
        }
    }


    public class SectionHeaderBlock
    {

        // Section Header Block

        //     [<-----1----->] [<-----2----->] [<-----3----->] [<-----4----->]
        //     0                   1                   2                   3
        //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        //    +---------------------------------------------------------------+
        //  0 |                   Block Type = 0x0A0D0D0A                     |
        //    +---------------------------------------------------------------+
        //  4 |                      Block Total Length                       |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //  8 |                Byte-Order Magic = 0x1A2B3C4D                  |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // 12 |        Major Version = 1      |       Minor Version = 0       |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // 16 |                                                               |
        //    |                        Section Length                         |
        //    |                                                               |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // 24 /                                                               /
        //    /                      Options(variable)                        /
        //    /                                                               /
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //    |                      Block Total Length                       |
        //    +---------------------------------------------------------------+

        [System.Runtime.InteropServices.StructLayout(LayoutKind.Explicit, Pack = 4, Size = 24)]
        internal struct HeaderBlockStart
        {
            [MarshalAs(UnmanagedType.U4)]
            [FieldOffset(0)]
            public UInt32 blockType;
            [MarshalAs(UnmanagedType.U4)]
            [FieldOffset(4)]
            public UInt32 blockLength;
            [MarshalAs(UnmanagedType.U4)]
            [FieldOffset(8)]
            public UInt32 magicNumber;
            [MarshalAs(UnmanagedType.U2)]
            [FieldOffset(12)]
            public UInt16 majorVersion;
            [MarshalAs(UnmanagedType.U2)]
            [FieldOffset(14)]
            public UInt16 minorVersion;
            [MarshalAs(UnmanagedType.I8)]
            [FieldOffset(16)]
            public Int64 sectionLength;
        }

        private HeaderBlockStart startBlock;
        private CommentBlock comment;

        public SectionHeaderBlock() : this(null, -1)
        { }

        public SectionHeaderBlock(string overrideComment, Int64 overrideSectionLen = -1)
        {
            comment = new CommentBlock(overrideComment ?? "Pcapng file converted using EtlToCap software.");

            startBlock = new HeaderBlockStart();
            startBlock.blockType = 0x0A0D0D0A;
            startBlock.blockLength = (uint)comment.totalByteLength + 28;
            startBlock.magicNumber = 0x1A2B3C4D;
            startBlock.majorVersion = 0x1;
            startBlock.minorVersion = 0x0;
            startBlock.sectionLength = overrideSectionLen; //Initial value
        }

        public Int64 sectionLength
        {
            set
            {
                this.startBlock.sectionLength = value;
            }
        }

        public int totalByteLength
        {
            get { return (int)startBlock.blockLength; }
        }

        public byte[] totalBytes
        {
            get
            {
                byte[] returnBytes = new byte[totalByteLength];
                Array.Clear(returnBytes, 0, totalByteLength);

                Array.Copy(Utilities.GetStructBytes(startBlock, 24), 0, returnBytes, 0, 24);
                Array.Copy(comment.totalBytes, 0, returnBytes, 24, comment.totalByteLength);

                //This is the Block Total Length field
                Array.Copy(BitConverter.GetBytes((UInt32)startBlock.blockLength), 0, returnBytes, totalByteLength - 4, 4);

                return returnBytes;
            }
        }
    }


    public class InterfaceDescriptionBlock
    {

        // Interface Description Block

        //     [<-----1----->] [<-----2----->] [<-----3----->] [<-----4----->]
        //     0                   1                   2                   3
        //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        //    +---------------------------------------------------------------+
        //  0 |                    Block Type = 0x00000001                    |
        //    +---------------------------------------------------------------+
        //  4 |                      Block Total Length                       |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //  8 |           LinkType            |         Reserved = 0          |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // 12 |                            SnapLen                            |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // 16 /                                                               /
        //    /                      Options(variable)                        /
        //    /                                                               /
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //    |                      Block Total Length                       |
        //    +---------------------------------------------------------------+

        [System.Runtime.InteropServices.StructLayout(LayoutKind.Explicit, Pack = 4, Size = 16)]
        internal struct InterfaceBlockStart
        {
            [MarshalAs(UnmanagedType.U4)]
            [FieldOffset(0)]
            public UInt32 blockType;
            [MarshalAs(UnmanagedType.U4)]
            [FieldOffset(4)]
            public UInt32 blockLength;
            [MarshalAs(UnmanagedType.U2)]
            [FieldOffset(8)]
            public UInt16 linkType;
            [MarshalAs(UnmanagedType.U2)]
            [FieldOffset(10)]
            public UInt16 reserved;
            [MarshalAs(UnmanagedType.U4)]
            [FieldOffset(12)]
            public UInt32 snapLen;
        }

        private InterfaceBlockStart startBlock;
        private CommentBlock comment;

        public InterfaceDescriptionBlock() : this(65535)
        { }

        public InterfaceDescriptionBlock(UInt32 maxPacketSize, UInt16 linkType = 1)
        {
            string linkStringName = "Ethernet";
            switch (linkType)
            {
                case 105:
                    linkStringName = "802.11";
                    break;
            }
            comment = new CommentBlock(String.Format("Etl packet capture converted assuming {0} frames.", linkStringName));

            startBlock = new InterfaceBlockStart();
            startBlock.blockType = 0x00000001;
            startBlock.blockLength = (uint)comment.totalByteLength + 20;
            startBlock.linkType = linkType;
            startBlock.reserved = 0x0;
            startBlock.snapLen = maxPacketSize;
        }

        public int totalByteLength
        {
            get { return (int)startBlock.blockLength; }
        }

        public byte[] totalBytes
        {
            get
            {
                byte[] returnBytes = new byte[totalByteLength];
                Array.Clear(returnBytes, 0, totalByteLength);

                Array.Copy(Utilities.GetStructBytes(startBlock, 16), 0, returnBytes, 0, 16);
                Array.Copy(comment.totalBytes, 0, returnBytes, 16, comment.totalByteLength);

                //This is the Block Total Length field
                Array.Copy(BitConverter.GetBytes((UInt32)startBlock.blockLength), 0, returnBytes, totalByteLength - 4, 4);

                return returnBytes;
            }
        }
    }


    public class EnhancedPacketBlock
    {

        // Enhanced Packet Block

        //     [<-----1----->] [<-----2----->] [<-----3----->] [<-----4----->]
        //     0                   1                   2                   3
        //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        //    +---------------------------------------------------------------+
        //  0 |                    Block Type = 0x00000006                    |
        //    +---------------------------------------------------------------+
        //  4 |                      Block Total Length                       |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //  8 |                         Interface ID                          |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // 12 |                        Timestamp(High)                        |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // 16 |                        Timestamp(Low)                         |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // 20 |                    Captured Packet Length                     |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // 24 |                    Original Packet Length                     |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // 28 /                                                               /
        //    /                          Packet Data                          /
        //    /              variable length, padded to 32 bits               /
        //    /                                                               /
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //    /                                                               /
        //    /                      Options(variable)                        /
        //    /                                                               /
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //    |                      Block Total Length                       |
        //    +---------------------------------------------------------------+

        [System.Runtime.InteropServices.StructLayout(LayoutKind.Explicit, Pack = 4, Size = 28)]
        internal struct EnhancedPacketBlockStart
        {
            [MarshalAs(UnmanagedType.U4)]
            [FieldOffset(0)]
            public UInt32 blockType;
            [MarshalAs(UnmanagedType.U4)]
            [FieldOffset(4)]
            public UInt32 blockLength;
            [MarshalAs(UnmanagedType.U4)]
            [FieldOffset(8)]
            public UInt32 interfaceId;
            [MarshalAs(UnmanagedType.U4)]
            [FieldOffset(12)]
            public UInt32 timestampHigh;
            [MarshalAs(UnmanagedType.U4)]
            [FieldOffset(16)]
            public UInt32 timestampLow;
            [MarshalAs(UnmanagedType.U4)]
            [FieldOffset(20)]
            public UInt32 capturedPacketLength;
            [MarshalAs(UnmanagedType.U4)]
            [FieldOffset(24)]
            public UInt32 originalPacketLength;
        }

        [System.Runtime.InteropServices.StructLayout(LayoutKind.Explicit, Pack = 4, Size = 8)]
        public struct TimeStamp
        {
            public TimeStamp(DateTime timeCreated)
            {
                TimeSpan since1970 = timeCreated.Subtract(DateTime.SpecifyKind(new DateTime(1970, 1, 1), DateTimeKind.Utc));
                timestampLow = 0;
                timestampHigh = 0;
                timestamp = (UInt64)since1970.Ticks / (TimeSpan.TicksPerMillisecond / 1000);
            }

            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.U8)]
            public UInt64 timestamp;
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.U4)]
            public UInt32 timestampHigh;
            [FieldOffset(4)]
            [MarshalAs(UnmanagedType.U4)]
            public UInt32 timestampLow;
        }

        private EnhancedPacketBlockStart startBlock;
        private CommentBlock comment = null;
        private byte[] packet;
        private TimeStamp timestamp;

        public EnhancedPacketBlock(EventRecord record, UInt32 maxPacketSize = 65535) : 
            this(record, maxPacketSize, null)
        { }

        public EnhancedPacketBlock(EventRecord record, NdisEtwMetadata header, UInt32 maxPacketSize) :
            this(record, maxPacketSize, header.ToString())
        { }

        public EnhancedPacketBlock(EventRecord record, UInt32 maxPacketSize, string headerString = null)
        {
            if (record.Properties.Count < 4)
                throw new ArgumentOutOfRangeException("record", record.Properties.Count, "record properties too small");
            
            startBlock = new EnhancedPacketBlockStart();

            if (!String.IsNullOrEmpty(headerString))
            {
                comment = new CommentBlock(headerString);
            }

            startBlock.blockType = 0x00000006;
            startBlock.interfaceId = 0x0;

            timestamp = new TimeStamp((DateTime)record.TimeCreated);

            startBlock.timestampHigh = timestamp.timestampHigh;
            startBlock.timestampLow = timestamp.timestampLow;

            startBlock.originalPacketLength = (UInt32)((byte[])record.Properties[3].Value).Length;
            startBlock.capturedPacketLength = maxPacketSize < startBlock.originalPacketLength ?
                maxPacketSize : startBlock.originalPacketLength;
            
            packet = (byte[])record.Properties[3].Value;


            startBlock.blockLength = packetPaddedLength + 
                (comment == null ? 0 :(UInt32)comment.totalByteLength) + 32;
        }

        public int totalByteLength
        {
            get { return (int)startBlock.blockLength; }
        }

        private UInt32 packetPaddedLength
        {
            get { return (UInt32)Utilities.padLength(startBlock.capturedPacketLength,4); }
        }

        public byte[] totalBytes
        {
            get
            {
                byte[] returnBytes = new byte[totalByteLength];
                Array.Clear(returnBytes, 0, totalByteLength);

                Array.Copy(Utilities.GetStructBytes(startBlock, 28), 0, returnBytes, 0, 28);
                Array.Copy(packet, 0, returnBytes, 28, packet.Length);
                
                if (comment != null)
                    Array.Copy(comment.totalBytes, 0, returnBytes, packetPaddedLength + 28, comment.totalByteLength);

                //This is the Block Total Length field
                Array.Copy(BitConverter.GetBytes((UInt32)startBlock.blockLength), 0, returnBytes, totalByteLength - 4, 4);

                return returnBytes;
            }
        }
    }




}
