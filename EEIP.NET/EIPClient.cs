using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Sres.Net.EEIP
{
    public class EEIPClient
    {
        TcpClient client;
        NetworkStream stream;
        UInt32 sessionHandle;
        UInt32 connectionID_O_T;
        UInt32 connectionID_T_O;
        UInt32 multicastAddress;
        UInt16 connectionSerialNumber;
        /// <summary>
        /// TCP-Port of the Server
        /// </summary>
        public ushort TCPPort { get; set; } = 0xAF12;
        /// <summary>
        /// UDP-Port of the IO-Adapter - Standard is 0xAF12
        /// </summary>
        public ushort TargetUDPPort { get; set; } = 0x08AE;
        /// <summary>
        /// UDP-Port of the Scanner - Standard is 0xAF12
        /// </summary>
        public ushort OriginatorUDPPort { get; set; } = 0x08AE;
        /// <summary>
        /// IPAddress of the Ethernet/IP Device
        /// </summary>
        /// 
        public string IPAddress { get; set; } = "172.0.0.1";
        /// <summary>
        /// Requested Packet Rate (RPI) in Microseconds Originator -> Target for Implicit-Messaging (Default 0x7A120 -> 500ms)
        /// </summary>
        public UInt32 RequestedPacketRate_O_T { get; set; } = 0x7A120;      //500ms
        /// <summary>
        /// Requested Packet Rate (RPI) in Microseconds Target -> Originator for Implicit-Messaging (Default 0x7A120 -> 500ms)
        /// </summary>
        public UInt32 RequestedPacketRate_T_O { get; set; } = 0x7A120;      //500ms
        /// <summary>
        /// "1" Indicates that multiple connections are allowed Originator -> Target for Implicit-Messaging (Default: TRUE) 
        /// </summary>
        public bool O_T_OwnerRedundant { get; set; } = true;                //For Forward Open
        /// <summary>
        /// "1" Indicates that multiple connections are allowed Target -> Originator for Implicit-Messaging (Default: TRUE) 
        /// </summary>
        public bool T_O_OwnerRedundant { get; set; } = true;                //For Forward Open
        /// <summary>
        /// With a fixed size connection, the amount of data shall be the size of specified in the "Connection Size" Parameter.
        /// With a variable size, the amount of data could be up to the size specified in the "Connection Size" Parameter
        /// Originator -> Target for Implicit Messaging (Default: True (Variable length))
        /// </summary>
        public bool O_T_VariableLength { get; set; } = true;                //For Forward Open
        /// <summary>
        /// With a fixed size connection, the amount of data shall be the size of specified in the "Connection Size" Parameter.
        /// With a variable size, the amount of data could be up to the size specified in the "Connection Size" Parameter
        /// Target -> Originator for Implicit Messaging (Default: True (Variable length))
        /// </summary>
        public bool T_O_VariableLength { get; set; } = true;                //For Forward Open
        /// <summary>
        /// The maximum size in bytes (only pure data without sequence count and 32-Bit Real Time Header (if present)) from Originator -> Target for Implicit Messaging (Default: 505)
        /// </summary>
        public UInt16 O_T_Length { get; set; } = 505;                //For Forward Open - Max 505
        /// <summary>
        /// The maximum size in bytes (only pure data woithout sequence count and 32-Bit Real Time Header (if present)) from Target -> Originator for Implicit Messaging (Default: 505)
        /// </summary>
        public UInt16 T_O_Length { get; set; } = 505;                //For Forward Open - Max 505
        /// <summary>
        /// Connection Type Originator -> Target for Implicit Messaging (Default: ConnectionType.Point_to_Point)
        /// </summary>
        public ConnectionType O_T_ConnectionType { get; set; } = ConnectionType.Point_to_Point;
        /// <summary>
        /// Connection Type Target -> Originator for Implicit Messaging (Default: ConnectionType.Multicast)
        /// </summary>
        public ConnectionType T_O_ConnectionType { get; set; } = ConnectionType.Multicast;
        /// <summary>
        /// Priority Originator -> Target for Implicit Messaging (Default: Priority.Scheduled)
        /// Could be: Priority.Scheduled; Priority.High; Priority.Low; Priority.Urgent
        /// </summary>
        public Priority O_T_Priority { get; set; } = Priority.Scheduled;
        /// <summary>
        /// Priority Target -> Originator for Implicit Messaging (Default: Priority.Scheduled)
        /// Could be: Priority.Scheduled; Priority.High; Priority.Low; Priority.Urgent
        /// </summary>
        public Priority T_O_Priority { get; set; } = Priority.Scheduled;
        /// <summary>
        /// Class Assembly (Consuming IO-Path - Outputs) Originator -> Target for Implicit Messaging (Default: 0x64)
        /// </summary>
        public byte O_T_InstanceID { get; set; } = 0x64;               //Ausgänge
        /// <summary>
        /// Class Assembly (Producing IO-Path - Inputs) Target -> Originator for Implicit Messaging (Default: 0x64)
        /// </summary>
        public byte T_O_InstanceID { get; set; } = 0x65;               //Eingänge
        /// <summary>
        /// Provides Access to the Class 1 Real-Time IO-Data Originator -> Target for Implicit Messaging    
        /// </summary>
        private byte[] _O_T_IOData = new byte[505];   //Class 1 Real-Time IO-Data O->T   

        private object _O_T_IOData_lock = new object();

        /// <summary>
        /// Provides Access to the Class 1 Real-Time IO-Data Target -> Originator for Implicit Messaging
        /// </summary>
        private byte[] _T_O_IOData = new byte[505];    //Class 1 Real-Time IO-Data T->O  

        private object _T_O_IOData_lock = new object();


        /// <summary>
        /// Used Real-Time Format Originator -> Target for Implicit Messaging (Default: RealTimeFormat.Header32Bit)
        /// Possible Values: RealTimeFormat.Header32Bit; RealTimeFormat.Heartbeat; RealTimeFormat.ZeroLength; RealTimeFormat.Modeless
        /// </summary>
        public RealTimeFormat O_T_RealTimeFormat { get; set; } = RealTimeFormat.Header32Bit;
        /// <summary>
        /// Used Real-Time Format Target -> Originator for Implicit Messaging (Default: RealTimeFormat.Modeless)
        /// Possible Values: RealTimeFormat.Header32Bit; RealTimeFormat.Heartbeat; RealTimeFormat.ZeroLength; RealTimeFormat.Modeless
        /// </summary>
        public RealTimeFormat T_O_RealTimeFormat { get; set; } = RealTimeFormat.Modeless;
        /// <summary>
        /// AssemblyObject for the Configuration Path in case of Implicit Messaging (Standard: 0x04)
        /// </summary>
        public byte AssemblyObjectClass { get; set; } = 0x04;
        /// <summary>
        /// ConfigurationAssemblyInstanceID is the InstanceID of the configuration Instance in the Assembly Object Class (Standard: 0x01)
        /// </summary>
        public byte ConfigurationAssemblyInstanceID { get; set; } = 0x01;
        /// <summary>
        /// Returns the Date and Time when the last Implicit Message has been received fŕom The Target Device
        /// Could be used to determine a Timeout
        /// </summary>        
        public DateTime LastReceivedImplicitMessage { get; set; }
    
        public EEIPClient()
        {
            Console.WriteLine("EEIP Library Version: " + Assembly.GetExecutingAssembly().GetName().Version.ToString());
            Console.WriteLine("Copyright (c) Stefan Rossmann Engineering Solutions");
            Console.WriteLine();
        }

        public class UdpState
        {
            public System.Net.IPEndPoint e;
            public UdpClient u;

        }

        /// <summary>
        /// List and identify potential targets. This command shall be sent as braodcast massage using UDP.
        /// The broadcast is sent on every interface address at once and the replies are collected for one second.
        /// </summary>
        /// <returns>List<Encapsulation.CIPIdentityItem> contains the received informations from all devices </returns>	
        public List<Encapsulation.CIPIdentityItem> ListIdentity()
        {
            //A new list for every call: the replies of this call, and nothing that arrives after it returned
            List<Encapsulation.CIPIdentityItem> returnList = new List<Encapsulation.CIPIdentityItem>();
            List<UdpClient> sockets = new List<UdpClient>();
            List<System.Threading.Tasks.Task> receivers = new List<System.Threading.Tasks.Task>();
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if ((ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 || ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet) && ni.OperationalStatus == OperationalStatus.Up)
                    {

                        foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                        {
                            if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            {
                                System.Net.IPAddress mask = ip.IPv4Mask;
                                System.Net.IPAddress address = ip.Address;

                                String multicastAddress = (address.GetAddressBytes()[0] | (~(mask.GetAddressBytes()[0])) & 0xFF).ToString() + "." + (address.GetAddressBytes()[1] | (~(mask.GetAddressBytes()[1])) & 0xFF).ToString() + "." + (address.GetAddressBytes()[2] | (~(mask.GetAddressBytes()[2])) & 0xFF).ToString() + "." + (address.GetAddressBytes()[3] | (~(mask.GetAddressBytes()[3])) & 0xFF).ToString();

                                byte[] sendData = new byte[24];
                                sendData[0] = 0x63;               //Command for "ListIdentity"
                                System.Net.Sockets.UdpClient udpClient = new System.Net.Sockets.UdpClient();
                                sockets.Add(udpClient);
                                udpClient.EnableBroadcast = true;       //The directed broadcast address is refused without it (Linux)
                                System.Net.IPEndPoint endPoint = new System.Net.IPEndPoint(System.Net.IPAddress.Parse(multicastAddress), 44818);
                                try
                                {
                                    udpClient.Send(sendData, sendData.Length, endPoint);
                                }
                                catch (SocketException)
                                {
                                    continue;       //This interface can't broadcast (e.g. network unreachable), the others still can
                                }

                                receivers.Add(ReceiveIdentityReplies(udpClient, returnList));
                            }
                        }
                    }
                }
                System.Threading.Thread.Sleep(1000);
            }
            finally
            {
                //Closing the sockets ends the receivers; once they are done nobody touches the list any more
                foreach (UdpClient udpClient in sockets)
                    udpClient.Close();
                System.Threading.Tasks.Task.WaitAll(receivers.ToArray());
            }
            return returnList;
        }

        private static async System.Threading.Tasks.Task ReceiveIdentityReplies(UdpClient socket, List<Encapsulation.CIPIdentityItem> returnList)
        {
            while (true)
            {
                byte[] receiveBytes;
                try
                {
                    receiveBytes = (await socket.ReceiveAsync().ConfigureAwait(false)).Buffer;
                }
                catch (ObjectDisposedException)
                {
                    return;                     //Closed at the end of ListIdentity
                }
                catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionReset)
                {
                    continue;                   //ICMP "port unreachable" (Windows), not the end of the socket
                }
                catch (SocketException)
                {
                    return;                     //Closed at the end of ListIdentity (operation aborted) or unusable
                }

                if (receiveBytes.Length < 2 || (receiveBytes[0] | (receiveBytes[1] << 8)) != 0x63)
                    continue;
                Encapsulation.CIPIdentityItem item;
                try
                {
                    item = Encapsulation.CIPIdentityItem.getCIPIdentityItem(24, receiveBytes);
                }
                catch (System.IO.InvalidDataException)
                {
                    continue;                   //Not a (complete) reply of an EtherNet/IP device, ignore it
                }
                lock (returnList)
                {
                    returnList.Add(item);
                }
            }
        }

        /// <summary>
        /// Sends a RegisterSession command to a target to initiate session
        /// </summary>
        /// <param name="address">IP-Address of the target device</param> 
        /// <param name="port">Port of the target device (default should be 0xAF12)</param> 
        /// <returns>Session Handle</returns>	
        public UInt32 RegisterSession(UInt32 address, UInt16 port)
        {
            if (sessionHandle != 0)
                return sessionHandle;
            Encapsulation encapsulation = new Encapsulation();
            encapsulation.Command = Encapsulation.CommandsEnum.RegisterSession;
            encapsulation.Length = 4;
            encapsulation.CommandSpecificData.Add(1);       //Protocol version (should be set to 1)
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);       //Session options shall be set to "0"
            encapsulation.CommandSpecificData.Add(0);


            string ipAddress = Encapsulation.CIPIdentityItem.getIPAddress(address);
            this.IPAddress = ipAddress;
            client = new TcpClient(ipAddress, port);
            stream = client.GetStream();

            try
            {
                stream.Write(encapsulation.toBytes(), 0, encapsulation.toBytes().Length);
                byte[] data = ReadEncapsulationFrame();
                this.sessionHandle = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(4));
            }
            catch
            {
                client.Close();
                throw;
            }
            return this.sessionHandle;
        }

        /// <summary>
        /// Sends a UnRegisterSession command to a target to terminate session
        /// </summary> 
        public void UnRegisterSession()
        {
            Encapsulation encapsulation = new Encapsulation();
            encapsulation.Command = Encapsulation.CommandsEnum.UnRegisterSession;
            encapsulation.Length = 0;
            encapsulation.SessionHandle =  sessionHandle;
 
            try
            {
                stream.Write(encapsulation.toBytes(), 0, encapsulation.toBytes().Length);
            }
            catch (Exception)
            {
                //Handle Exception to allow to Close the Stream if the connection was closed by Remote Device
            }
            byte[] data = new Byte[256];
            client.Close();
            stream.Close();
            sessionHandle = 0;
        }

        public void ForwardOpen()
        {
            this.ForwardOpen(false);
        }

        System.Net.Sockets.UdpClient udpClientReceive;
        System.Threading.CancellationTokenSource sendCancellation;
        public void ForwardOpen(bool largeForwardOpen)
        {
            ushort o_t_headerOffset = 2;                    //Zählt den Sequencecount und evtl 32bit header zu der Länge dazu
            if (O_T_RealTimeFormat == RealTimeFormat.Header32Bit)
                o_t_headerOffset = 6;
            if (O_T_RealTimeFormat == RealTimeFormat.Heartbeat)
                o_t_headerOffset = 0;

            ushort t_o_headerOffset = 2;                    //Zählt den Sequencecount und evtl 32bit header zu der Länge dazu
            if (T_O_RealTimeFormat == RealTimeFormat.Header32Bit)
                t_o_headerOffset = 6;
            if (T_O_RealTimeFormat == RealTimeFormat.Heartbeat)
                t_o_headerOffset = 0;

            int lengthOffset = (5 + (O_T_ConnectionType == ConnectionType.Null ? 0 : 2) + (T_O_ConnectionType == ConnectionType.Null ? 0 : 2));

            Encapsulation encapsulation = new Encapsulation();
            encapsulation.SessionHandle = sessionHandle;
            encapsulation.Command = Encapsulation.CommandsEnum.SendRRData;
            //!!!!!!-----Length Field at the end!!!!!!!!!!!!!
            
            //---------------Interface Handle CIP
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Interface Handle CIP

            //----------------Timeout
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Timeout

            //Common Packet Format (Table 2-6.1)
            Encapsulation.CommonPacketFormat commonPacketFormat = new Encapsulation.CommonPacketFormat();
            commonPacketFormat.ItemCount = 0x02;

            commonPacketFormat.AddressItem = 0x0000;        //NULL (used for UCMM Messages)
            commonPacketFormat.AddressLength = 0x0000;

            
            commonPacketFormat.DataItem = 0xB2;
            commonPacketFormat.DataLength = (ushort)(41 + (ushort)lengthOffset);
            if (largeForwardOpen)
                commonPacketFormat.DataLength = (ushort)(commonPacketFormat.DataLength + 4);



            //----------------CIP Command "Forward Open" (Service Code 0x54)
            if (!largeForwardOpen)
                commonPacketFormat.Data.Add(0x54);
            //----------------CIP Command "Forward Open"  (Service Code 0x54)

            //----------------CIP Command "large Forward Open" (Service Code 0x5B)
            else
                commonPacketFormat.Data.Add(0x5B);
            //----------------CIP Command "large Forward Open"  (Service Code 0x5B)

            //----------------Requested Path size
            commonPacketFormat.Data.Add(2);
            //----------------Requested Path size

            //----------------Path segment for Class ID
            commonPacketFormat.Data.Add(0x20);
            commonPacketFormat.Data.Add((byte)6);
            //----------------Path segment for Class ID

            //----------------Path segment for Instance ID
            commonPacketFormat.Data.Add(0x24);
            commonPacketFormat.Data.Add((byte)1);
            //----------------Path segment for Instace ID

            //----------------Priority and Time/Tick - Table 3-5.16 (Vol. 1)
            commonPacketFormat.Data.Add(0x03);
            //----------------Priority and Time/Tick

            //----------------Timeout Ticks - Table 3-5.16 (Vol. 1)
            commonPacketFormat.Data.Add(0xfa);
            //----------------Timeout Ticks

            this.connectionID_O_T = Convert.ToUInt32(new Random().Next(0xfffffff));
            this.connectionID_T_O = Convert.ToUInt32(new Random().Next(0xfffffff)+1);
            commonPacketFormat.Data.Add((byte)connectionID_O_T);
            commonPacketFormat.Data.Add((byte)(connectionID_O_T >> 8));
            commonPacketFormat.Data.Add((byte)(connectionID_O_T >> 16));
            commonPacketFormat.Data.Add((byte)(connectionID_O_T >> 24));


            commonPacketFormat.Data.Add((byte)connectionID_T_O);
            commonPacketFormat.Data.Add((byte)(connectionID_T_O >> 8));
            commonPacketFormat.Data.Add((byte)(connectionID_T_O >> 16));
            commonPacketFormat.Data.Add((byte)(connectionID_T_O >> 24));

            this.connectionSerialNumber = Convert.ToUInt16(new Random().Next(0xFFFF)+2);
            commonPacketFormat.Data.Add((byte)connectionSerialNumber);
            commonPacketFormat.Data.Add((byte)(connectionSerialNumber >> 8));

            //----------------Originator Vendor ID
            commonPacketFormat.Data.Add(0xFF);
            commonPacketFormat.Data.Add(0);
            //----------------Originaator Vendor ID

            //----------------Originator Serial Number
            commonPacketFormat.Data.Add(0xFF);
            commonPacketFormat.Data.Add(0xFF);
            commonPacketFormat.Data.Add(0xFF);
            commonPacketFormat.Data.Add(0xFF);
            //----------------Originator Serial Number

            //----------------Timeout Multiplier
            commonPacketFormat.Data.Add(3);
            //----------------Timeout Multiplier

            //----------------Reserved
            commonPacketFormat.Data.Add(0);
            commonPacketFormat.Data.Add(0);
            commonPacketFormat.Data.Add(0);
            //----------------Reserved

            //----------------Requested Packet Rate O->T in Microseconds
            commonPacketFormat.Data.Add((byte)RequestedPacketRate_O_T);
            commonPacketFormat.Data.Add((byte)(RequestedPacketRate_O_T >> 8));
            commonPacketFormat.Data.Add((byte)(RequestedPacketRate_O_T >> 16));
            commonPacketFormat.Data.Add((byte)(RequestedPacketRate_O_T >> 24));
            //----------------Requested Packet Rate O->T in Microseconds

            //----------------O->T Network Connection Parameters
            bool redundantOwner = (bool)O_T_OwnerRedundant;
            byte connectionType = (byte)O_T_ConnectionType; //1=Multicast, 2=P2P
            byte priority = (byte)O_T_Priority;         //00=low; 01=High; 10=Scheduled; 11=Urgent
            bool variableLength = O_T_VariableLength;       //0=fixed; 1=variable
            UInt16 connectionSize = (ushort)(O_T_Length + o_t_headerOffset);      //The maximum size in bytes og the data for each direction (were applicable) of the connection. For a variable -> maximum
            UInt32 NetworkConnectionParameters = (UInt16)((UInt16)(connectionSize & 0x1FF) | ((Convert.ToUInt16(variableLength)) << 9) | ((priority & 0x03) << 10) | ((connectionType & 0x03) << 13) | ((Convert.ToUInt16(redundantOwner)) << 15));
            if (largeForwardOpen)
                NetworkConnectionParameters = (UInt32)((uint)(connectionSize & 0xFFFF) | ((Convert.ToUInt32(variableLength)) << 25) | (uint)((priority & 0x03) << 26) | (uint)((connectionType & 0x03) << 29) | ((Convert.ToUInt32(redundantOwner)) << 31));
            commonPacketFormat.Data.Add((byte)NetworkConnectionParameters);
            commonPacketFormat.Data.Add((byte)(NetworkConnectionParameters >> 8));
            if (largeForwardOpen)
            {
                commonPacketFormat.Data.Add((byte)(NetworkConnectionParameters >> 16));
                commonPacketFormat.Data.Add((byte)(NetworkConnectionParameters >> 24));
            }
            //----------------O->T Network Connection Parameters

            //----------------Requested Packet Rate T->O in Microseconds
            commonPacketFormat.Data.Add((byte)RequestedPacketRate_T_O);
            commonPacketFormat.Data.Add((byte)(RequestedPacketRate_T_O >> 8));
            commonPacketFormat.Data.Add((byte)(RequestedPacketRate_T_O >> 16));
            commonPacketFormat.Data.Add((byte)(RequestedPacketRate_T_O >> 24));
            //----------------Requested Packet Rate T->O in Microseconds

            //----------------T->O Network Connection Parameters


            redundantOwner = (bool)T_O_OwnerRedundant;
            connectionType = (byte)T_O_ConnectionType; //1=Multicast, 2=P2P
            priority = (byte)T_O_Priority;
            variableLength = T_O_VariableLength;
            connectionSize = (ushort)(T_O_Length  + t_o_headerOffset);
            NetworkConnectionParameters = (UInt16)((UInt16)(connectionSize & 0x1FF) | ((Convert.ToUInt16(variableLength)) << 9) | ((priority & 0x03) << 10) | ((connectionType & 0x03) << 13) | ((Convert.ToUInt16(redundantOwner)) << 15));
            if (largeForwardOpen)
                NetworkConnectionParameters = (UInt32)((uint)(connectionSize & 0xFFFF) | ((Convert.ToUInt32(variableLength)) << 25) | (uint)((priority & 0x03) << 26) | (uint)((connectionType & 0x03) << 29) | ((Convert.ToUInt32(redundantOwner)) << 31));
            commonPacketFormat.Data.Add((byte)NetworkConnectionParameters);
            commonPacketFormat.Data.Add((byte)(NetworkConnectionParameters >> 8));
            if (largeForwardOpen)
            {
                commonPacketFormat.Data.Add((byte)(NetworkConnectionParameters >> 16));
                commonPacketFormat.Data.Add((byte)(NetworkConnectionParameters >> 24));
            }
            //----------------T->O Network Connection Parameters

            //----------------Transport Type/Trigger
            commonPacketFormat.Data.Add(0x01);
            //X------- = 0= Client; 1= Server
            //-XXX---- = Production Trigger, 0 = Cyclic, 1 = CoS, 2 = Application Object
            //----XXXX = Transport class, 0 = Class 0, 1 = Class 1, 2 = Class 2, 3 = Class 3
            //----------------Transport Type Trigger
            //Connection Path size 
            commonPacketFormat.Data.Add((byte)((0x2) + (O_T_ConnectionType == ConnectionType.Null ? 0 : 1) + (T_O_ConnectionType == ConnectionType.Null ? 0 : 1) ));
            //Verbindugspfad
            commonPacketFormat.Data.Add((byte)(0x20));
            commonPacketFormat.Data.Add((byte)(AssemblyObjectClass));
            commonPacketFormat.Data.Add((byte)(0x24));
            commonPacketFormat.Data.Add((byte)(ConfigurationAssemblyInstanceID));
            if (O_T_ConnectionType != ConnectionType.Null)
            {
                commonPacketFormat.Data.Add((byte)(0x2C));
                commonPacketFormat.Data.Add((byte)(O_T_InstanceID));
            }
            if (T_O_ConnectionType != ConnectionType.Null)
            {
                commonPacketFormat.Data.Add((byte)(0x2C));
                commonPacketFormat.Data.Add((byte)(T_O_InstanceID));
            }
            
            //AddSocket Addrress Item O->T
            
                commonPacketFormat.SocketaddrInfo_O_T = new Encapsulation.SocketAddress();
                commonPacketFormat.SocketaddrInfo_O_T.SIN_port = OriginatorUDPPort;
                commonPacketFormat.SocketaddrInfo_O_T.SIN_family = 2;
            if (O_T_ConnectionType == ConnectionType.Multicast)
            {
                UInt32 multicastResponseAddress = EEIPClient.GetMulticastAddress(BinaryPrimitives.ReadUInt32BigEndian(System.Net.IPAddress.Parse(IPAddress).GetAddressBytes()));

                commonPacketFormat.SocketaddrInfo_O_T.SIN_Address = (multicastResponseAddress);

                multicastAddress = commonPacketFormat.SocketaddrInfo_O_T.SIN_Address;
            }
            else
                commonPacketFormat.SocketaddrInfo_O_T.SIN_Address = 0;

            encapsulation.Length = (ushort)(commonPacketFormat.toBytes().Length+6);//(ushort)(57 + (ushort)lengthOffset);
            //20 04 24 01 2C 65 2C 6B

            byte[] dataToWrite = new byte[encapsulation.toBytes().Length + commonPacketFormat.toBytes().Length];
            System.Buffer.BlockCopy(encapsulation.toBytes(), 0, dataToWrite, 0, encapsulation.toBytes().Length);
            System.Buffer.BlockCopy(commonPacketFormat.toBytes(), 0, dataToWrite, encapsulation.toBytes().Length, commonPacketFormat.toBytes().Length);
            //encapsulation.toBytes();
            
            stream.Write(dataToWrite, 0, dataToWrite.Length);
            byte[] data = ReadSendRRDataReply();

            //--------------------------BEGIN Error?
            if (data[42] != 0)      //Exception codes see "Table B-1.1 CIP General Status Codes"
            {
                if (data[42] == 0x1)
                    if (data[43] == 0 || data.Length < 46)
                        throw new CIPException("Connection failure, General Status Code: " + data[42]);
                    else
                        throw new CIPException("Connection failure, General Status Code: " + data[42] + " Additional Status Code: " + ((data[45] << 8) | data[44]) + " " + ObjectLibrary.ConnectionManagerObject.GetExtendedStatus((uint)((data[45] << 8) | data[44])));
                else
                    throw new CIPException(GeneralStatusCodes.GetStatusCode(data[42]));
            }
            //--------------------------END Error?
            if (data.Length < 52)
                throw new CIPException("Truncated Forward_Open reply: " + data.Length + " bytes");
            //Read the Network ID from the Reply (see 3-3.7.1.1)
            int itemCount = data[30] + (data[31] << 8);
            int lengthUnconectedDataItem = data[38] + (data[39] << 8);
            this.connectionID_O_T = data[44] + (uint)(data[45] << 8) + (uint)(data[46] << 16) + (uint)(data[47] << 24);
            this.connectionID_T_O = data[48] + (uint)(data[49] << 8) + (uint)(data[50] << 16) + (uint)(data[51] << 24);

            //Is a SocketInfoItem present?
            int numberOfCurrentItem = 0;
            Encapsulation.SocketAddress socketInfoItem;
            while (itemCount > 2 && 40 + lengthUnconectedDataItem + 20 * (numberOfCurrentItem + 1) <= data.Length)
            {
                int typeID = data[40 + lengthUnconectedDataItem+ 20 * numberOfCurrentItem] + (data[40 + lengthUnconectedDataItem + 1+ 20 * numberOfCurrentItem] << 8);
                if (typeID == 0x8001)
                {
                    socketInfoItem = new Encapsulation.SocketAddress();
                    socketInfoItem.SIN_Address = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(40 + lengthUnconectedDataItem + 8 + 20 * numberOfCurrentItem));
                    socketInfoItem.SIN_port = (UInt16)((UInt16)(data[40 + lengthUnconectedDataItem + 7 + 20 * numberOfCurrentItem]) + (UInt16)(data[40 + lengthUnconectedDataItem + 6 + 20 * numberOfCurrentItem] << 8));
                    if (T_O_ConnectionType == ConnectionType.Multicast)
                        multicastAddress = socketInfoItem.SIN_Address;
                    TargetUDPPort = socketInfoItem.SIN_port;
                }
                numberOfCurrentItem++;
                itemCount--;
            }
            //Open UDP-Port



            System.Net.IPEndPoint endPointReceive = new System.Net.IPEndPoint(System.Net.IPAddress.Any, OriginatorUDPPort);
            udpClientReceive = new System.Net.Sockets.UdpClient(endPointReceive);
            if (multicastAddress != 0)
            {
                byte[] multicastBytes = new byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(multicastBytes, multicastAddress);
                System.Net.IPAddress multicast = new System.Net.IPAddress(multicastBytes);
                udpClientReceive.JoinMulticastGroup(multicast);
              
            }

            //Every connection gets its own token and receive loop: a late ForwardClose or a late completion of the previous connection's socket can't touch this one
            sendCancellation = new System.Threading.CancellationTokenSource();
            System.Threading.CancellationToken stopSending = sendCancellation.Token;
            System.Threading.Thread sendThread = new System.Threading.Thread(() => sendUDP(stopSending));
            sendThread.IsBackground = true;
            sendThread.Start();

            _ = ReceiveLoopClass1(udpClientReceive);
        }

        public void LargeForwardOpen()
        {
            this.ForwardOpen(true);
        }

        private ushort o_t_detectedLength;
        /// <summary>
        /// Detects the Length of the data Originator -> Target.
        /// The Method uses an Explicit Message to detect the length.
        /// The IP-Address, Port and the Instance ID has to be defined before
        /// </summary>
        public ushort Detect_O_T_Length ()
        {
            if (o_t_detectedLength == 0)
            {
                if (this.sessionHandle == 0)
                    this.RegisterSession();
                o_t_detectedLength = (ushort)(this.GetAttributeSingle(0x04, O_T_InstanceID, 3)).Length;
                return o_t_detectedLength;
            }
            else
                return o_t_detectedLength;
        }

        private ushort t_o_detectedLength;
        /// <summary>
        /// Detects the Length of the data Target -> Originator.
        /// The Method uses an Explicit Message to detect the length.
        /// The IP-Address, Port and the Instance ID has to be defined before
        /// </summary>
        public ushort Detect_T_O_Length()
        {
            if (t_o_detectedLength == 0)
            {
                if (this.sessionHandle == 0)
                    this.RegisterSession();
                t_o_detectedLength = (ushort)(this.GetAttributeSingle(0x04, T_O_InstanceID, 3)).Length;
                return t_o_detectedLength;
            }
            else
                return t_o_detectedLength;
        }

        internal static UInt32 GetMulticastAddress(UInt32 deviceIPAddress)
        {
            UInt32 cip_Mcast_Base_Addr = 0xEFC00100;
            UInt32 cip_Host_Mask = 0x3FF;
            UInt32 netmask = 0;

            //Class A Network?
            if (deviceIPAddress <= 0x7FFFFFFF)
                netmask = 0xFF000000;
            //Class B Network?
            if (deviceIPAddress >= 0x80000000 && deviceIPAddress <= 0xBFFFFFFF)
                netmask = 0xFFFF0000;
            //Class C Network?
            if (deviceIPAddress >= 0xC0000000 && deviceIPAddress <= 0xDFFFFFFF)
                netmask = 0xFFFFFF00;

            UInt32 hostID = deviceIPAddress & ~netmask;
            UInt32 mcastIndex = hostID - 1;
            mcastIndex = mcastIndex & cip_Host_Mask;

            return (UInt32) (cip_Mcast_Base_Addr + mcastIndex * (UInt32)32);

        }

        public void ForwardClose()
        {
            //First stop the Thread which send data

            sendCancellation?.Cancel();


            int lengthOffset = (5 + (O_T_ConnectionType == ConnectionType.Null ? 0 : 2) + (T_O_ConnectionType == ConnectionType.Null ? 0 : 2));

            Encapsulation encapsulation = new Encapsulation();
            encapsulation.SessionHandle = sessionHandle;
            encapsulation.Command = Encapsulation.CommandsEnum.SendRRData;
            encapsulation.Length = (ushort)(16 +17+ (ushort)lengthOffset);
            //---------------Interface Handle CIP
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Interface Handle CIP

            //----------------Timeout
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Timeout

            //Common Packet Format (Table 2-6.1)
            Encapsulation.CommonPacketFormat commonPacketFormat = new Encapsulation.CommonPacketFormat();
            commonPacketFormat.ItemCount = 0x02;

            commonPacketFormat.AddressItem = 0x0000;        //NULL (used for UCMM Messages)
            commonPacketFormat.AddressLength = 0x0000;


            commonPacketFormat.DataItem = 0xB2;
            commonPacketFormat.DataLength = (ushort)(17 + (ushort)lengthOffset);



            //----------------CIP Command "Forward Close"
            commonPacketFormat.Data.Add(0x4E);
            //----------------CIP Command "Forward Close"

            //----------------Requested Path size
            commonPacketFormat.Data.Add(2);
            //----------------Requested Path size

            //----------------Path segment for Class ID
            commonPacketFormat.Data.Add(0x20);
            commonPacketFormat.Data.Add((byte)6);
            //----------------Path segment for Class ID

            //----------------Path segment for Instance ID
            commonPacketFormat.Data.Add(0x24);
            commonPacketFormat.Data.Add((byte)1);
            //----------------Path segment for Instace ID

            //----------------Priority and Time/Tick - Table 3-5.16 (Vol. 1)
            commonPacketFormat.Data.Add(0x03);
            //----------------Priority and Time/Tick

            //----------------Timeout Ticks - Table 3-5.16 (Vol. 1)
            commonPacketFormat.Data.Add(0xfa);
            //----------------Timeout Ticks

            //Connection serial number
            commonPacketFormat.Data.Add((byte)connectionSerialNumber);
            commonPacketFormat.Data.Add((byte)(connectionSerialNumber >> 8));
            //connection seruial number

            //----------------Originator Vendor ID
            commonPacketFormat.Data.Add(0xFF);
            commonPacketFormat.Data.Add(0);
            //----------------Originaator Vendor ID

            //----------------Originator Serial Number
            commonPacketFormat.Data.Add(0xFF);
            commonPacketFormat.Data.Add(0xFF);
            commonPacketFormat.Data.Add(0xFF);
            commonPacketFormat.Data.Add(0xFF);
            //----------------Originator Serial Number

            //Connection Path size 
            commonPacketFormat.Data.Add((byte)((0x2) + (O_T_ConnectionType == ConnectionType.Null ? 0 : 1) + (T_O_ConnectionType == ConnectionType.Null ? 0 : 1)));
            //Reserved
            commonPacketFormat.Data.Add(0);
            //Reserved


            //Verbindugspfad
            commonPacketFormat.Data.Add((byte)(0x20));
            commonPacketFormat.Data.Add(AssemblyObjectClass);
            commonPacketFormat.Data.Add((byte)(0x24));
            commonPacketFormat.Data.Add((byte)(ConfigurationAssemblyInstanceID));
            if (O_T_ConnectionType != ConnectionType.Null)
            {
                commonPacketFormat.Data.Add((byte)(0x2C));
                commonPacketFormat.Data.Add((byte)(O_T_InstanceID));
            }
            if (T_O_ConnectionType != ConnectionType.Null)
            {
                commonPacketFormat.Data.Add((byte)(0x2C));
                commonPacketFormat.Data.Add((byte)(T_O_InstanceID));
            }

            byte[] dataToWrite = new byte[encapsulation.toBytes().Length + commonPacketFormat.toBytes().Length];
            System.Buffer.BlockCopy(encapsulation.toBytes(), 0, dataToWrite, 0, encapsulation.toBytes().Length);
            System.Buffer.BlockCopy(commonPacketFormat.toBytes(), 0, dataToWrite, encapsulation.toBytes().Length, commonPacketFormat.toBytes().Length);
            encapsulation.toBytes();
            try
            {
                stream.Write(dataToWrite, 0, dataToWrite.Length);
            }
            catch (Exception e)
            {
                //Handle Exception  to allow Forward close if the connection was closed by the Remote Device before
            }
            byte[] data = null;

            try
            {
                data = ReadSendRRDataReply();
            }
            catch (Exception e) when (e is not CIPException)
            {
                //Handle Exception  to allow Forward close if the connection was closed by the Remote Device before
            }


            //--------------------------BEGIN Error?
            if (data != null && data[42] != 0)      //Exception codes see "Table B-1.1 CIP General Status Codes"
            {
                throw new CIPException(GeneralStatusCodes.GetStatusCode(data[42]));
            }


            //Close the Socket for Receive
            udpClientReceive.Close();
  
           


        }

        private void sendUDP(System.Threading.CancellationToken stop)
        {
            System.Net.IPEndPoint endPointsend = new System.Net.IPEndPoint(System.Net.IPAddress.Parse(IPAddress), TargetUDPPort);
            System.Net.SocketAddress targetAddress = endPointsend.Serialize();     //Serialized once, so that sending does not allocate
            using System.Net.Sockets.Socket udpSend = new System.Net.Sockets.Socket(endPointsend.AddressFamily, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp);

            ushort headerOffset = 0;
            if (O_T_RealTimeFormat == RealTimeFormat.Header32Bit)
                headerOffset = 4;
            int dataLength = O_T_Length;
            ushort o_t_Length = (ushort)(dataLength + headerOffset + 2);   //Modeless and zero Length
            byte[] o_t_IOData = new byte[20 + headerOffset + dataLength];

            //The packet is built once, only the sequence counts and the data change from packet to packet
            //---------------Item count
            o_t_IOData[0] = 2;
            o_t_IOData[1] = 0;
            //---------------Type ID
            o_t_IOData[2] = 0x02;
            o_t_IOData[3] = 0x80;
            //---------------Length
            o_t_IOData[4] = 0x08;
            o_t_IOData[5] = 0x00;
            //---------------connection ID
            o_t_IOData[6] = (byte)(connectionID_O_T);
            o_t_IOData[7] = (byte)(connectionID_O_T >> 8);
            o_t_IOData[8] = (byte)(connectionID_O_T >> 16);
            o_t_IOData[9] = (byte)(connectionID_O_T >> 24);
            //---------------Type ID
            o_t_IOData[14] = 0xB1;
            o_t_IOData[15] = 0x00;
            //---------------Length
            o_t_IOData[16] = (byte)o_t_Length;
            o_t_IOData[17] = (byte)(o_t_Length >> 8);
            //---------------32 bit Real Time Header (run)
            if (O_T_RealTimeFormat == RealTimeFormat.Header32Bit)
                o_t_IOData[20] = 1;

            //The requested packet rate is in microseconds
            long interval = (long)(RequestedPacketRate_O_T * (double)Stopwatch.Frequency / 1_000_000);
            long nextSend = Stopwatch.GetTimestamp();
            uint sequenceCount = 0;

            while (!stop.IsCancellationRequested)
            {
                sequenceCount++;
                //---------------sequence count
                o_t_IOData[10] = (byte)(sequenceCount);
                o_t_IOData[11] = (byte)(sequenceCount >> 8);
                o_t_IOData[12] = (byte)(sequenceCount >> 16);
                o_t_IOData[13] = (byte)(sequenceCount >> 24);
                //---------------Sequence count
                if (O_T_RealTimeFormat != RealTimeFormat.Heartbeat)
                {
                    o_t_IOData[18] = (byte)sequenceCount;
                    o_t_IOData[19] = (byte)(sequenceCount >> 8);
                }

                //---------------Write data
                lock (_O_T_IOData_lock)
                {
                    Array.Copy(_O_T_IOData, 0, o_t_IOData, 20 + headerOffset, dataLength);
                }
                //---------------Write data

                udpSend.SendTo(o_t_IOData, System.Net.Sockets.SocketFlags.None, targetAddress);

                //Absolute deadlines, so that the time spent building and sending a packet (and sleeping too long) does not add up to the interval
                nextSend += interval;
                long now = Stopwatch.GetTimestamp();
                if (nextSend < now - interval)      //More than one packet behind: carry on from now instead of sending a burst
                    nextSend = now;
                if (!WaitUntil(nextSend, stop))
                    break;
            }
        }

        /// <summary>
        /// Waits until <paramref name="deadline"/> (a <see cref="Stopwatch"/> timestamp) or until <paramref name="stop"/> is cancelled.
        /// Sleeping is only accurate to about a millisecond, so the last bit is spun out, which is the only way to
        /// keep an interval below a few milliseconds. Long intervals just sleep: a little jitter is better than a busy core.
        /// </summary>
        /// <returns>false if cancelled</returns>
        private static bool WaitUntil(long deadline, System.Threading.CancellationToken stop)
        {
            long remainingMilliseconds = (deadline - Stopwatch.GetTimestamp()) * 1000 / Stopwatch.Frequency;
            long sleepMilliseconds = remainingMilliseconds >= 5 ? remainingMilliseconds : remainingMilliseconds - 1;
            if (sleepMilliseconds > 0 && stop.WaitHandle.WaitOne((int)sleepMilliseconds))
                return false;

            System.Threading.SpinWait spinner = new System.Threading.SpinWait();
            while (Stopwatch.GetTimestamp() < deadline)
            {
                if (stop.IsCancellationRequested)
                    return false;
                spinner.SpinOnce(-1);       //Never sleeps, only spins and yields
            }
            return !stop.IsCancellationRequested;
        }

        /// <summary>
        /// Receives the class 1 T->O packets of one connection until its socket is closed (ForwardClose).
        /// Packets are handled one at a time and in order; nothing a packet contains can end the loop.
        /// </summary>
        private async System.Threading.Tasks.Task ReceiveLoopClass1(UdpClient socket)
        {
            bool sequenceKnown = false;
            ushort lastSequence = 0;
            while (true)
            {
                byte[] receiveBytes;
                try
                {
                    receiveBytes = (await socket.ReceiveAsync().ConfigureAwait(false)).Buffer;
                }
                catch (ObjectDisposedException)
                {
                    return;                     //Closed by ForwardClose
                }
                catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionReset)
                {
                    continue;                   //ICMP "port unreachable" for an earlier send (Windows), not the end of the socket
                }
                catch (SocketException)
                {
                    return;                     //Closed by ForwardClose (operation aborted) or unusable
                }
                HandleClass1Packet(receiveBytes, ref sequenceKnown, ref lastSequence);
                LastReceivedImplicitMessage = DateTime.Now;
            }
        }

        private void HandleClass1Packet(byte[] receiveBytes, ref bool sequenceKnown, ref ushort lastSequence)
        {
            ushort headerOffset = 0;
            if (T_O_RealTimeFormat == RealTimeFormat.Header32Bit)
                headerOffset = 4;

            //20 bytes: item count, sequenced address item (with connection ID and sequence number), connected data item header and its sequence count
            if (receiveBytes.Length < 20 + headerOffset)
                return;

            //Get the connection ID
            uint connectionID = (uint)(receiveBytes[6] | receiveBytes[7] << 8 | receiveBytes[8] << 16 | receiveBytes[9] << 24);
            if (connectionID != connectionID_T_O)
                return;

            //The data must be in a connected data item (0x00B1)
            if ((receiveBytes[14] | receiveBytes[15] << 8) != 0xB1)
                return;

            int dataLength = receiveBytes.Length - 20 - headerOffset;
            if (dataLength > _T_O_IOData.Length)
                return;

            //Ignore duplicates and old packets: only a count that is "ahead" of the last one (modulo 2^16) is new
            ushort sequence = (ushort)(receiveBytes[18] | receiveBytes[19] << 8);
            if (sequenceKnown && (short)(sequence - lastSequence) <= 0)
                return;
            sequenceKnown = true;
            lastSequence = sequence;

            lock (_T_O_IOData_lock)
            {
                Array.Copy(receiveBytes, 20 + headerOffset, _T_O_IOData, 0, dataLength);
            }
        }



        /// <summary>
        /// Sends a RegisterSession command to a target to initiate session
        /// </summary>
        /// <param name="address">IP-Address of the target device</param> 
        /// <param name="port">Port of the target device (default should be 0xAF12)</param> 
        /// <returns>Session Handle</returns>	
        public UInt32 RegisterSession(string address, UInt16 port)
        {
            string[] addressSubstring = address.Split('.');
            UInt32 ipAddress = UInt32.Parse(addressSubstring[3]) + (UInt32.Parse(addressSubstring[2]) << 8) + (UInt32.Parse(addressSubstring[1]) << 16) + (UInt32.Parse(addressSubstring[0]) << 24);
            return RegisterSession(ipAddress, port);
        }

        /// <summary>
        /// Sends a RegisterSession command to a target to initiate session with the Standard or predefined Port (Standard: 0xAF12)
        /// </summary>
        /// <param name="address">IP-Address of the target device</param> 
        /// <returns>Session Handle</returns>	
        public UInt32 RegisterSession(string address)
        {
            string[] addressSubstring = address.Split('.');
            UInt32 ipAddress = UInt32.Parse(addressSubstring[3]) + (UInt32.Parse(addressSubstring[2]) << 8) + (UInt32.Parse(addressSubstring[1]) << 16) + (UInt32.Parse(addressSubstring[0]) << 24);
            return RegisterSession(ipAddress, this.TCPPort);
        }

        /// <summary>
        /// Sends a RegisterSession command to a target to initiate session with the Standard or predefined Port and Predefined IPAddress (Standard-Port: 0xAF12)
        /// </summary>
        /// <returns>Session Handle</returns>	
        public UInt32 RegisterSession()
        {
            
            return RegisterSession(this.IPAddress, this.TCPPort);
        }

        public byte[] GetAttributeSingle(int classID, int instanceID, int attributeID)
        {
            byte[] requestedPath = GetEPath(classID, instanceID, attributeID);
            if (sessionHandle == 0)             //If a Session is not Registers, Try to Registers a Session with the predefined IP-Address and Port
                this.RegisterSession();
            byte[] dataToSend = new byte[42+ requestedPath.Length];
            Encapsulation encapsulation = new Encapsulation();
            encapsulation.SessionHandle = sessionHandle;
            encapsulation.Command = Encapsulation.CommandsEnum.SendRRData;
            encapsulation.Length = (UInt16)(18 + requestedPath.Length);
            //---------------Interface Handle CIP
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Interface Handle CIP

            //----------------Timeout
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Timeout

            //Common Packet Format (Table 2-6.1)
            Encapsulation.CommonPacketFormat commonPacketFormat = new Encapsulation.CommonPacketFormat();
            commonPacketFormat.ItemCount = 0x02;

            commonPacketFormat.AddressItem = 0x0000;        //NULL (used for UCMM Messages)
            commonPacketFormat.AddressLength = 0x0000;

            commonPacketFormat.DataItem = 0xB2;
            commonPacketFormat.DataLength = (UInt16)(2 + requestedPath.Length);



            //----------------CIP Command "Get Attribute Single"
            commonPacketFormat.Data.Add((byte)Sres.Net.EEIP.CIPCommonServices.Get_Attribute_Single);
            //----------------CIP Command "Get Attribute Single"

            //----------------Requested Path size (number of 16 bit words)
            commonPacketFormat.Data.Add((byte)(requestedPath.Length / 2));
            //----------------Requested Path size (number of 16 bit words)

            //----------------Path segment for Class ID
            //----------------Path segment for Class ID

            //----------------Path segment for Instance ID
            //----------------Path segment for Instace ID

            //----------------Path segment for Attribute ID
            //----------------Path segment for Attribute ID

            for (int i = 0; i < requestedPath.Length; i++)
            {
                commonPacketFormat.Data.Add(requestedPath[i]);
            }

            byte[] dataToWrite = new byte[encapsulation.toBytes().Length + commonPacketFormat.toBytes().Length];
            System.Buffer.BlockCopy(encapsulation.toBytes(), 0, dataToWrite, 0, encapsulation.toBytes().Length);
            System.Buffer.BlockCopy(commonPacketFormat.toBytes(), 0, dataToWrite, encapsulation.toBytes().Length, commonPacketFormat.toBytes().Length);
            encapsulation.toBytes();

            stream.Write(dataToWrite, 0, dataToWrite.Length);
            byte[] data = ReadSendRRDataReply();

            //--------------------------BEGIN Error?
            if (data[42] != 0)      //Exception codes see "Table B-1.1 CIP General Status Codes"
            {
                throw new CIPException(GeneralStatusCodes.GetStatusCode(data[42]));
            }
            //--------------------------END Error?

            byte[] returnData = data.AsSpan(44, 40 + (data[38] | data[39] << 8) - 44).ToArray();

            return returnData;
        }

        /// <summary>
        /// Implementation of Common Service "Get_Attribute_All" - Service Code: 0x01
        /// </summary>
        /// <param name="classID">Class id of requested Attributes</param> 
        /// <param name="instanceID">Instance of Requested Attributes (0 for class Attributes)</param> 
        /// <returns>Session Handle</returns>	
        public byte[] GetAttributeAll(int classID, int instanceID)
        {
            byte[] requestedPath = GetEPath(classID, instanceID, 0);
            if (sessionHandle == 0)             //If a Session is not Registered, Try to Registers a Session with the predefined IP-Address and Port
                this.RegisterSession();
            byte[] dataToSend = new byte[42 + requestedPath.Length];
            Encapsulation encapsulation = new Encapsulation();
            encapsulation.SessionHandle = sessionHandle;
            encapsulation.Command = Encapsulation.CommandsEnum.SendRRData;
            encapsulation.Length = (UInt16)(18 + requestedPath.Length);
            //---------------Interface Handle CIP
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Interface Handle CIP

            //----------------Timeout
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Timeout

            //Common Packet Format (Table 2-6.1)
            Encapsulation.CommonPacketFormat commonPacketFormat = new Encapsulation.CommonPacketFormat();
            commonPacketFormat.ItemCount = 0x02;

            commonPacketFormat.AddressItem = 0x0000;        //NULL (used for UCMM Messages)
            commonPacketFormat.AddressLength = 0x0000;

            commonPacketFormat.DataItem = 0xB2;
            commonPacketFormat.DataLength = (UInt16)(2 + requestedPath.Length); //WAS 6



            //----------------CIP Command "Get Attribute All"
            commonPacketFormat.Data.Add((byte)Sres.Net.EEIP.CIPCommonServices.Get_Attributes_All);
            //----------------CIP Command "Get Attribute All"

            //----------------Requested Path size
            commonPacketFormat.Data.Add((byte)(requestedPath.Length / 2));
            //----------------Requested Path size

            //----------------Path segment for Class ID
            //----------------Path segment for Class ID

            //----------------Path segment for Instance ID
            //----------------Path segment for Instace ID
            for (int i = 0; i < requestedPath.Length; i++)
            {
                commonPacketFormat.Data.Add(requestedPath[i]);
            }

            byte[] dataToWrite = new byte[encapsulation.toBytes().Length + commonPacketFormat.toBytes().Length];
            System.Buffer.BlockCopy(encapsulation.toBytes(), 0, dataToWrite, 0, encapsulation.toBytes().Length);
            System.Buffer.BlockCopy(commonPacketFormat.toBytes(), 0, dataToWrite, encapsulation.toBytes().Length, commonPacketFormat.toBytes().Length);
           

            stream.Write(dataToWrite, 0, dataToWrite.Length);
            byte[] data = ReadSendRRDataReply();
            //--------------------------BEGIN Error?
            if (data[42] != 0)      //Exception codes see "Table B-1.1 CIP General Status Codes"
            {
                throw new CIPException(GeneralStatusCodes.GetStatusCode(data[42]));
            }
            //--------------------------END Error?

            byte[] returnData = data.AsSpan(44, 40 + (data[38] | data[39] << 8) - 44).ToArray();

            return returnData;
        }

        public byte[] SetAttributeSingle(int classID, int instanceID, int attributeID, byte[] value)
        {
            byte[] requestedPath = GetEPath(classID, instanceID, attributeID);
            if (sessionHandle == 0)             //If a Session is not Registers, Try to Registers a Session with the predefined IP-Address and Port
                this.RegisterSession();
            byte[] dataToSend = new byte[42 + value.Length + requestedPath.Length];
            Encapsulation encapsulation = new Encapsulation();
            encapsulation.SessionHandle = sessionHandle;
            encapsulation.Command = Encapsulation.CommandsEnum.SendRRData;
            encapsulation.Length = (UInt16)(18+value.Length + requestedPath.Length);
            //---------------Interface Handle CIP
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Interface Handle CIP

            //----------------Timeout
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Timeout

            //Common Packet Format (Table 2-6.1)
            Encapsulation.CommonPacketFormat commonPacketFormat = new Encapsulation.CommonPacketFormat();
            commonPacketFormat.ItemCount = 0x02;

            commonPacketFormat.AddressItem = 0x0000;        //NULL (used for UCMM Messages)
            commonPacketFormat.AddressLength = 0x0000;

            commonPacketFormat.DataItem = 0xB2;
            commonPacketFormat.DataLength = (UInt16)(2 + value.Length+requestedPath.Length);



            //----------------CIP Command "Set Attribute Single"
            commonPacketFormat.Data.Add((byte)Sres.Net.EEIP.CIPCommonServices.Set_Attribute_Single);
            //----------------CIP Command "Set Attribute Single"

            //----------------Requested Path size (number of 16 bit words)
            commonPacketFormat.Data.Add((byte)(requestedPath.Length/2));
            //----------------Requested Path size (number of 16 bit words)

            //----------------Path segment for Class ID
            //----------------Path segment for Class ID

            //----------------Path segment for Instance ID
            //----------------Path segment for Instace ID

            //----------------Path segment for Attribute ID
            //----------------Path segment for Attribute ID
            for (int i = 0; i < requestedPath.Length; i++)
            {
                commonPacketFormat.Data.Add(requestedPath[i]);
            }

                //----------------Data
            for (int i = 0; i < value.Length; i++)
            {
                commonPacketFormat.Data.Add(value[i]);
            }
            //----------------Data

            byte[] dataToWrite = new byte[encapsulation.toBytes().Length + commonPacketFormat.toBytes().Length];
            System.Buffer.BlockCopy(encapsulation.toBytes(), 0, dataToWrite, 0, encapsulation.toBytes().Length);
            System.Buffer.BlockCopy(commonPacketFormat.toBytes(), 0, dataToWrite, encapsulation.toBytes().Length, commonPacketFormat.toBytes().Length);
            encapsulation.toBytes();

            stream.Write(dataToWrite, 0, dataToWrite.Length);
            byte[] data = ReadSendRRDataReply();

            //--------------------------BEGIN Error?
            if (data[42] != 0)      //Exception codes see "Table B-1.1 CIP General Status Codes"
            {
                throw new CIPException(GeneralStatusCodes.GetStatusCode(data[42]));
            }
            //--------------------------END Error?

            byte[] returnData = data.AsSpan(44, 40 + (data[38] | data[39] << 8) - 44).ToArray();

            return returnData;
        }

        /// <summary>
        /// Reads one complete encapsulation message: the 24 byte header and, as announced by its length field, the
        /// body. TCP is a byte stream, so a message may arrive in several pieces and be of any size up to 65559 bytes.
        /// </summary>
        /// <returns>Header and body</returns>
        /// <exception cref="CIPException">The encapsulation status of the reply is not "success"</exception>
        /// <exception cref="System.IO.IOException">The connection ended before the whole message arrived</exception>
        private byte[] ReadEncapsulationFrame()
        {
            byte[] frame = new byte[24];
            stream.ReadExactly(frame, 0, 24);
            int length = BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(2));
            if (length > 0)
            {
                Array.Resize(ref frame, 24 + length);
                stream.ReadExactly(frame, 24, length);      //Also consumed on an error status, to keep the stream in sync
            }
            uint status = BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(8));
            if (status != 0)
                throw new CIPException("Encapsulation error, Status Code: 0x" + status.ToString("X2") + " (" + GetEncapsulationStatusText(status) + ")");
            return frame;
        }

        /// <summary>
        /// Reads the reply to a SendRRData command and makes sure that the CIP reply header (general status at byte
        /// 42, additional status size at byte 43) is there and that the data item fits in the message.
        /// </summary>
        private byte[] ReadSendRRDataReply()
        {
            byte[] frame = ReadEncapsulationFrame();
            if (frame.Length < 44)
                throw new CIPException("Truncated SendRRData reply: " + frame.Length + " bytes");
            int dataItemEnd = 40 + (frame[38] | frame[39] << 8);
            if (dataItemEnd < 44 || dataItemEnd > frame.Length)
                throw new CIPException("Invalid data item length in SendRRData reply");
            return frame;
        }

        private static string GetEncapsulationStatusText(uint status)
        {
            switch (status)
            {
                case 0x01: return "invalid or unsupported command";
                case 0x02: return "insufficient memory";
                case 0x03: return "incorrect data";
                case 0x64: return "invalid session handle";
                case 0x65: return "invalid length";
                case 0x69: return "unsupported encapsulation protocol revision";
                default: return "unknown";
            }
        }

        /// <summary>
        /// Get the Encrypted Request Path - See Volume 1 Appendix C (C9)
        /// e.g. for 8 Bit: 20 05 24 02 30 01
        /// for 16 Bit: 21 00 05 00 24 02 30 01
        /// </summary>
        /// <param name="classID">Requested Class ID</param>
        /// <param name="instanceID">Requested Instance ID</param>
        /// <param name="attributeID">Requested Attribute ID - if "0" the attribute will be ignored</param>
        /// <returns>Encrypted Request Path</returns>
        internal static byte[] GetEPath(int classID, int instanceID, int attributeID)
        {
            int byteCount = 0;
            if (classID < 0xff)
                byteCount = byteCount + 2;
            else
                byteCount = byteCount + 4;
           
            if (instanceID < 0xff)
                byteCount = byteCount + 2;
            else
                byteCount = byteCount + 4;
            if (attributeID != 0)
                if (attributeID < 0xff)
                    byteCount = byteCount + 2;
                else
                    byteCount = byteCount + 4;

            byte[] returnValue = new byte[byteCount];
            byteCount = 0;
            if (classID < 0xff)
            {
                returnValue[byteCount] = 0x20;
                returnValue[byteCount+1] = (byte)classID;
                byteCount = byteCount + 2;
            }
            else
            {
                returnValue[byteCount] = 0x21;
                returnValue[byteCount + 1] = 0;                             //Padded Byte
                returnValue[byteCount + 2] = (byte)classID;                 //LSB
                returnValue[byteCount + 3] = (byte)(classID>>8);            //MSB
                byteCount = byteCount + 4;
            }


            if (instanceID < 0xff)
            {
                returnValue[byteCount] = 0x24;
                returnValue[byteCount + 1] = (byte)instanceID;
                byteCount = byteCount + 2;
            }
            else
            {
                returnValue[byteCount] = 0x25;
                returnValue[byteCount + 1] = 0;                                //Padded Byte
                returnValue[byteCount + 2] = ((byte)instanceID);                 //LSB
                returnValue[byteCount + 3] = (byte)(instanceID >> 8);          //MSB
                byteCount = byteCount + 4;
            }
            if (attributeID != 0)
                if (attributeID < 0xff)
                {
                    returnValue[byteCount] = 0x30;
                    returnValue[byteCount + 1] = (byte)attributeID;
                    byteCount = byteCount + 2;
                }
                else
                {
                    returnValue[byteCount] = 0x31;
                    returnValue[byteCount + 1] = 0;                                 //Padded Byte
                    returnValue[byteCount + 2] = (byte)attributeID;                 //LSB
                    returnValue[byteCount + 3] = (byte)(attributeID >> 8);          //MSB
                    byteCount = byteCount + 4;
                }

            return returnValue;

        }

        /// <summary>
        /// Implementation of Common Service "Get_Attribute_All" - Service Code: 0x01
        /// </summary>
        /// <param name="classID">Class id of requested Attributes</param> 
        public byte[] GetAttributeAll(int classID)
        {
            return this.GetAttributeAll(classID, 0);
        }

        ObjectLibrary.IdentityObject identityObject;
        /// <summary>
        /// Implementation of the identity Object (Class Code: 0x01) - Required Object according to CIP-Specification
        /// </summary>
        public ObjectLibrary.IdentityObject IdentityObject
        {
            get
            {
                if (identityObject == null)
                    identityObject = new ObjectLibrary.IdentityObject(this);
                return identityObject;

            }
        }

        ObjectLibrary.MessageRouterObject messageRouterObject;
        /// <summary>
        /// Implementation of the Message Router Object (Class Code: 0x02) - Required Object according to CIP-Specification
        /// </summary>
        public ObjectLibrary.MessageRouterObject MessageRouterObject
        {
            get
            {
                if (messageRouterObject == null)
                    messageRouterObject = new ObjectLibrary.MessageRouterObject(this);
                return messageRouterObject;

            }
        }

        ObjectLibrary.AssemblyObject assemblyObject;
        /// <summary>
        /// Implementation of the Assembly Object (Class Code: 0x04)
        /// </summary>
        public ObjectLibrary.AssemblyObject AssemblyObject
        {
            get
            {
                if (assemblyObject == null)
                    assemblyObject = new ObjectLibrary.AssemblyObject(this);
                return assemblyObject;
            }
        }

        ObjectLibrary.TcpIpInterfaceObject tcpIpInterfaceObject;
        /// <summary>
        /// Implementation of the TCP/IP Object (Class Code: 0xF5) - Required Object according to CIP-Specification
        /// </summary>
        public ObjectLibrary.TcpIpInterfaceObject TcpIpInterfaceObject
        {
            get
            {
                if (tcpIpInterfaceObject == null)
                    tcpIpInterfaceObject = new ObjectLibrary.TcpIpInterfaceObject(this);
                return tcpIpInterfaceObject;

            }
        }

        /// <summary>
        /// Provides Access to the Class 1 Real-Time IO-Data Originator -> Target for Implicit Messaging    
        /// </summary>
        public byte[] O_T_IOData
        {
            get
            {
                lock (_O_T_IOData_lock)
                {
                    return (byte[]) _O_T_IOData.Clone();
                }
            }
            set
            {
                lock (_O_T_IOData_lock)
                {
                    var length = value == null ? 0 : Math.Min(value.Length, _O_T_IOData.Length);
                    if (value != null)
                    {
                        Array.Copy(value, _O_T_IOData, length);
                    }

                    Array.Clear(_O_T_IOData, length, _O_T_IOData.Length - length);
                }
            }
        }

        /// <summary>
        /// Provides Access to the Class 1 Real-Time IO-Data Target -> Originator for Implicit Messaging
        /// </summary>
        public byte[] T_O_IOData
        {
            get
            {
                lock (_T_O_IOData_lock)
                {
                    return (byte[]) _T_O_IOData.Clone();
                }
            }
        }

        /// <summary>
        /// Converts a bytearray (received e.g. via getAttributeSingle) to ushort
        /// </summary>
        /// <param name="byteArray">bytearray to convert</param> 
        public static ushort ToUshort(byte[] byteArray)
        {
            UInt16 returnValue;
            returnValue = (UInt16)(byteArray[1] << 8 | byteArray[0]);
            return returnValue;
        }

        /// <summary>
        /// Converts a bytearray (received e.g. via getAttributeSingle) to uint
        /// </summary>
        /// <param name="byteArray">bytearray to convert</param> 
        public static uint ToUint(byte[] byteArray)
        {
            UInt32 returnValue = ((UInt32)byteArray[3] << 24 | (UInt32)byteArray[2] << 16 | (UInt32)byteArray[1] << 8 | (UInt32)byteArray[0]);
            return returnValue;
        }

        /// <summary>
        /// Returns the "Bool" State of a byte Received via getAttributeSingle
        /// </summary>
        /// <param name="inputByte">byte to convert</param> 
        /// <param name="bitposition">bitposition to convert (First bit = bitposition 0)</param> 
        /// <returns>Converted bool value</returns>
        public static bool ToBool(byte inputByte, int bitposition)
        {
           
            return (((inputByte>>bitposition)&0x01) != 0) ? true : false;
        }
    }

    public enum ConnectionType : byte
    {
        Null = 0,
        Multicast = 1,
        Point_to_Point = 2
    }

    public enum Priority : byte
    {
        Low = 0,
        High = 1,
        Scheduled = 2,
        Urgent = 3
    }

    public enum RealTimeFormat : byte
    {
        Modeless = 0,
        ZeroLength = 1,
        Heartbeat = 2,
        Header32Bit = 3

        
    }
}
