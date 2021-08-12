// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Xml;
using System.Collections;

namespace System.Security.Cryptography.Xml
{
    internal sealed class CanonicalXmlNodeList : XmlNodeList, IList
    {
        private readonly ArrayList _nodeArray = new();

        public override XmlNode Item(int index)
        {
            return (XmlNode)_nodeArray[index]!;
        }

        public override IEnumerator GetEnumerator()
        {
            return _nodeArray.GetEnumerator();
        }

        public override int Count => _nodeArray.Count;

        // IList methods
        public int Add(object? value)
        {
            if (value is not XmlNode)
                throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, "node");
            return _nodeArray.Add(value);
        }

        public void Clear()
        {
            _nodeArray.Clear();
        }

        public bool Contains(object? value)
        {
            return _nodeArray.Contains(value);
        }

        public int IndexOf(object? value)
        {
            return _nodeArray.IndexOf(value);
        }

        public void Insert(int index, object? value)
        {
            if (value is not XmlNode)
                throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, nameof(value));
            _nodeArray.Insert(index, value);
        }

        public void Remove(object? value)
        {
            _nodeArray.Remove(value);
        }

        public void RemoveAt(int index)
        {
            _nodeArray.RemoveAt(index);
        }

        public bool IsFixedSize => _nodeArray.IsFixedSize;

        public bool IsReadOnly => _nodeArray.IsReadOnly;

        object? IList.this[int index]
        {
            get { return _nodeArray[index]; }
            set
            {
                if (value is not XmlNode)
                    throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, nameof(value));
                _nodeArray[index] = value;
            }
        }

        public void CopyTo(Array array, int index)
        {
            _nodeArray.CopyTo(array, index);
        }

        public object SyncRoot => _nodeArray.SyncRoot;

        public bool IsSynchronized => _nodeArray.IsSynchronized;
    }
}
