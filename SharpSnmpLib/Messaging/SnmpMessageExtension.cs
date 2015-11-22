// SNMP message extension class.
// Copyright (C) 2008-2010 Malcolm Crowe, Lex Li, and other contributors.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy of this
// software and associated documentation files (the "Software"), to deal in the Software
// without restriction, including without limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
// to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or
// substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
// FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Lextm.SharpSnmpLib.Security;

namespace Lextm.SharpSnmpLib.Messaging
{
    /// <summary>
    /// Extension methods for <see cref="ISnmpMessage"/>.
    /// </summary>
    public static class SnmpMessageExtension
    {
        /// <summary>
        /// Gets the <see cref="SnmpType"/>.
        /// </summary>
        /// <param name="message">The <see cref="ISnmpMessage"/>.</param>
        /// <returns></returns>
        public static SnmpType TypeCode(this ISnmpMessage message)
        {
            if (message == null)
            {
                throw new ArgumentNullException("message");
            }
            
            return message.Pdu().TypeCode;
        }
        
        /// <summary>
        /// Variables.
        /// </summary>
        /// <param name="message">The <see cref="ISnmpMessage"/>.</param>
        public static IList<Variable> Variables(this ISnmpMessage message)
        {
            if (message == null)
            {
                throw new ArgumentNullException("message");
            }

            var code = message.TypeCode();
            return code == SnmpType.Unknown ? new List<Variable>(0) : message.Scope.Pdu.Variables;
        }

        /// <summary>
        /// Request ID.
        /// </summary>
        /// <param name="message">The <see cref="ISnmpMessage"/>.</param>
        public static int RequestId(this ISnmpMessage message)
        {
            if (message == null)
            {
                throw new ArgumentNullException("message");
            }

            return message.Scope.Pdu.RequestId.ToInt32();
        }

        /// <summary>
        /// Gets the message ID.
        /// </summary>
        /// <value>The message ID.</value>
        /// <param name="message">The <see cref="ISnmpMessage"/>.</param>
        /// <remarks>For v3, message ID is different from request ID. For v1 and v2c, they are the same.</remarks>
        public static int MessageId(this ISnmpMessage message)
        {
            if (message == null)
            {
                throw new ArgumentNullException("message");
            }

            return message.Header == Header.Empty ? message.RequestId() : message.Header.MessageId;
        }

        /// <summary>
        /// PDU.
        /// </summary>
        /// <param name="message">The <see cref="ISnmpMessage"/>.</param>
        [SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Pdu")]
        public static ISnmpPdu Pdu(this ISnmpMessage message)
        {
            if (message == null)
            {
                throw new ArgumentNullException("message");
            }

            return message.Scope.Pdu;
        }

        /// <summary>
        /// Community name.
        /// </summary>
        /// <param name="message">The <see cref="ISnmpMessage"/>.</param>
        public static OctetString Community(this ISnmpMessage message)
        {
            if (message == null)
            {
                throw new ArgumentNullException("message");
            }

            return message.Parameters.UserName;
        }

        /// <summary>
        /// Sends an <see cref="ISnmpMessage"/>.
        /// </summary>
        /// <param name="message">The <see cref="ISnmpMessage"/>.</param>
        /// <param name="manager">Manager</param>
        public static async Task SendAsync(this ISnmpMessage message, EndPoint manager)
        {
            if (message == null)
            {
                throw new ArgumentNullException("message");
            }

            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }

            var code = message.TypeCode();
            if ((code != SnmpType.TrapV1Pdu && code != SnmpType.TrapV2Pdu) && code != SnmpType.ReportPdu)
            {
                throw new InvalidOperationException(string.Format(
                    CultureInfo.InvariantCulture,
                    "not a trap message: {0}",
                    code));
            }

            using (var socket = manager.GetSocket())
            {
                await message.SendAsync(manager, socket);
            }
        }
        
        /// <summary>
        /// Sends an <see cref="ISnmpMessage"/>.
        /// </summary>
        /// <param name="message">The <see cref="ISnmpMessage"/>.</param>
        /// <param name="manager">Manager</param>
        /// <param name="socket">The socket.</param>
        public static async Task SendAsync(this ISnmpMessage message, EndPoint manager, Socket socket)
        {
            if (message == null)
            {
                throw new ArgumentNullException("message");
            }

            if (socket == null)
            {
                throw new ArgumentNullException("socket");
            }

            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }

            var code = message.TypeCode();
            if ((code != SnmpType.TrapV1Pdu && code != SnmpType.TrapV2Pdu) && code != SnmpType.ReportPdu)
            {
                throw new InvalidOperationException(string.Format(
                    CultureInfo.InvariantCulture,
                    "not a trap message: {0}",
                    code));
            }

            var bytes = message.ToBytes();
            using (var info = new SocketAsyncEventArgs())
            {
                info.RemoteEndPoint = manager;
                info.SetBuffer(bytes, 0, bytes.Length);
                var awaitable1 = new SocketAwaitable(info);
                await socket.SendToAsync(awaitable1);
            }
        }
        
        /// <summary>
        /// Sends this <see cref="ISnmpMessage"/> and handles the response from agent.
        /// </summary>
        /// <param name="request">The <see cref="ISnmpMessage"/>.</param>
        /// <param name="receiver">Port number.</param>
        /// <param name="registry">User registry.</param>
        /// <returns></returns>
        public static async Task<ISnmpMessage> GetResponse(this ISnmpMessage request, IPEndPoint receiver, UserRegistry registry)
        {
            // TODO: make more usage of UserRegistry.
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }

            if (receiver == null)
            {
                throw new ArgumentNullException("receiver");
            }

            var code = request.TypeCode();
            if (code == SnmpType.TrapV1Pdu || code == SnmpType.TrapV2Pdu || code == SnmpType.ReportPdu)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "not a request message: {0}", code));
            }
            
            using (var socket = receiver.GetSocket())
            {
                return await request.GetResponseAsync(receiver, registry, socket);
            }
        }

        /// <summary>
        /// Sends this <see cref="ISnmpMessage"/> and handles the response from agent.
        /// </summary>
        /// <param name="request">The <see cref="ISnmpMessage"/>.</param>
        /// <param name="receiver">Port number.</param>
        /// <returns></returns>
        public static async Task<ISnmpMessage> GetResponseAsync(this ISnmpMessage request, IPEndPoint receiver)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }

            if (receiver == null)
            {
                throw new ArgumentNullException("receiver");
            }

            var code = request.TypeCode();
            if (code == SnmpType.TrapV1Pdu || code == SnmpType.TrapV2Pdu || code == SnmpType.ReportPdu)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "not a request message: {0}", code));
            }
            
            using (var socket = receiver.GetSocket())
            {
                return await request.GetResponseAsync(receiver, socket);
            }
        }

        /// <summary>
        /// Sends this <see cref="ISnmpMessage"/> and handles the response from agent.
        /// </summary>
        /// <param name="request">The <see cref="ISnmpMessage"/>.</param>
        /// <param name="receiver">Agent.</param>
        /// <param name="udpSocket">The UDP <see cref="Socket"/> to use to send/receive.</param>
        /// <returns></returns>
        public static async Task<ISnmpMessage> GetResponseAsync(this ISnmpMessage request, IPEndPoint receiver, Socket udpSocket)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }
            
            if (receiver == null)
            {
                throw new ArgumentNullException("receiver");
            }
            
            if (udpSocket == null)
            {
                throw new ArgumentNullException("udpSocket");
            }
            
            var registry = new UserRegistry();
            if (request.Version == VersionCode.V3)
            {
                registry.Add(request.Parameters.UserName, request.Privacy);
            }

            return await request.GetResponseAsync(receiver, registry, udpSocket);
        }

        /// <summary>
        /// Sends an <see cref="ISnmpMessage"/> and handles the response from agent.
        /// </summary>
        /// <param name="request">The <see cref="ISnmpMessage"/>.</param>
        /// <param name="receiver">Agent.</param>
        /// <param name="udpSocket">The UDP <see cref="Socket"/> to use to send/receive.</param>
        /// <param name="registry">The user registry.</param>
        /// <returns></returns>
        public static async Task<ISnmpMessage> GetResponseAsync(this ISnmpMessage request, IPEndPoint receiver, UserRegistry registry, Socket udpSocket)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }

            if (udpSocket == null)
            {
                throw new ArgumentNullException("udpSocket");
            }

            if (receiver == null)
            {
                throw new ArgumentNullException("receiver");
            }

            if (registry == null)
            {
                throw new ArgumentNullException("registry");
            }

            var requestCode = request.TypeCode();
            if (requestCode == SnmpType.TrapV1Pdu || requestCode == SnmpType.TrapV2Pdu || requestCode == SnmpType.ReportPdu)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "not a request message: {0}", requestCode));
            }

            var bytes = request.ToBytes();
#if CF
            int bufSize = 8192;
#else
            var bufSize = udpSocket.ReceiveBufferSize;
#endif

            // Whatever you change, try to keep the Send and the Receive close to each other.
            using (var info = new SocketAsyncEventArgs())
            {
                info.RemoteEndPoint = receiver;
                info.SetBuffer(bytes, 0, bytes.Length);
                var awaitable1 = new SocketAwaitable(info);
                await udpSocket.SendToAsync(awaitable1);
            }

            int count;
            var reply = new byte[bufSize];

            // IMPORTANT: follow http://blogs.msdn.com/b/pfxteam/archive/2011/12/15/10248293.aspx
            var args = new SocketAsyncEventArgs();
            EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
            try
            {
                args.RemoteEndPoint = remote;
                args.SetBuffer(reply, 0, bufSize);
                var awaitable = new SocketAwaitable(args);
                count = await udpSocket.ReceiveAsync(awaitable);
            }
            catch (SocketException ex)
            {
                // FIXME: If you use a Mono build without the fix for this issue (https://bugzilla.novell.com/show_bug.cgi?id=599488), please uncomment this code.
                /*
                if (SnmpMessageExtension.IsRunningOnMono && ex.ErrorCode == 10035)
                {
                    throw TimeoutException.Create(receiver.Address, timeout);
                }
                // */

                if (ex.SocketErrorCode == SocketError.TimedOut)
                {
                    throw TimeoutException.Create(receiver.Address, 0);
                }

                throw;
            }
            finally
            {
                args.Dispose();
            }

            // Passing 'count' is not necessary because ParseMessages should ignore it, but it offer extra safety (and would avoid an issue if parsing >1 response).
            var response = MessageFactory.ParseMessages(reply, 0, count, registry)[0];
            var responseCode = response.TypeCode();
            if (responseCode == SnmpType.ResponsePdu || responseCode == SnmpType.ReportPdu)
            {
                var requestId = request.MessageId();
                var responseId = response.MessageId();
                if (responseId != requestId)
                {
                    throw OperationException.Create(string.Format(CultureInfo.InvariantCulture, "wrong response sequence: expected {0}, received {1}", requestId, responseId), receiver.Address);
                }

                return response;
            }

            throw OperationException.Create(string.Format(CultureInfo.InvariantCulture, "wrong response type: {0}", responseCode), receiver.Address);
        }

        /// <summary>
        /// Tests if running on Mono.
        /// </summary>
        /// <returns></returns>
        public static bool IsRunningOnMono
        {
            get { return Type.GetType("Mono.Runtime") != null; }
        }

        /// <summary>
        /// Packs up the <see cref="ISnmpMessage"/>.
        /// </summary>
        /// <param name="message">The <see cref="ISnmpMessage"/>.</param>
        /// <param name="length">The length bytes.</param>
        /// <returns></returns>
        internal static Sequence PackMessage(this ISnmpMessage message, byte[] length)
        {
            if (message == null)
            {
                throw new ArgumentNullException("message");
            }

            return ByteTool.PackMessage(
                length,
                message.Version,
                message.Header,
                message.Parameters,
                message.Privacy.GetScopeData(message.Header, message.Parameters, message.Scope.GetData(message.Version)));
        }
    }
}
