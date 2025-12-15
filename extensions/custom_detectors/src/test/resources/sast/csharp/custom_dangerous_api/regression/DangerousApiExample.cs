using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace Example
{
    public class DangerousApiExample
    {
        public void SerializeData(object data, Stream stream)
        {
            var formatter = new BinaryFormatter();
            formatter.Serialize(stream, data); // FLAW
        }

        public object DeserializeData(Stream stream)
        {
            var formatter = new BinaryFormatter();
            return formatter.Deserialize(stream); // FLAW
        }
    }
}
