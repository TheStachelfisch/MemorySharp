using System;

namespace MemorySharp
{
    internal class Helper
    {
       
    }

    [Serializable]
    public class ProcessNotFoundException : Exception
    {
        public ProcessNotFoundException() : base() { }
        public ProcessNotFoundException(string message) : base(message) { }
        public ProcessNotFoundException(string message, SystemException inner) : base(message, inner) { }
    }
}