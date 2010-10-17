﻿using System;
using System.Collections.Generic;

namespace Lextm.SharpSnmpLib.Pipeline
{
    /// <summary>
    /// GET message handler.
    /// </summary>
    public class GetV1MessageHandler : IMessageHandler
    {
        /// <summary>
        /// Handles the specified message.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="store">The object store.</param>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1031:DoNotCatchGeneralExceptionTypes")]
        public ResponseData Handle(SnmpContext context, ObjectStore store)
        {
            ErrorCode status = ErrorCode.NoError;
            int index = 0;
            IList<Variable> result = new List<Variable>();
            foreach (Variable v in context.Request.Pdu.Variables)
            {
                index++;
                ScalarObject obj = store.GetObject(v.Id);
                if (obj != null)
                {
                    try
                    {
                        Variable item = obj.Variable;
                        result.Add(item);
                    }
                    catch (AccessFailureException)
                    {
                        status = ErrorCode.NoSuchName;
                    }
                    catch (Exception)
                    {
                        status = ErrorCode.GenError;
                    }
                }
                else
                {
                    status = ErrorCode.NoSuchName;
                }

                if (status != ErrorCode.NoError)
                {
                    return new ResponseData(null, status, index);
                }
            }

            return new ResponseData(result, status, index);
        }
    }
}