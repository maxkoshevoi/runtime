// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics.CodeAnalysis;
using System.Xml;

namespace System.Security.Cryptography.Xml
{
    public sealed class EncryptionProperty
    {
        private XmlElement? _elemProp;
        private XmlElement? _cachedXml;

        // We are being lax here as per the spec
        public EncryptionProperty() { }

        public EncryptionProperty(XmlElement elementProperty)
        {
            if (elementProperty == null)
                throw new ArgumentNullException(nameof(elementProperty));
            if (elementProperty.LocalName != "EncryptionProperty" || elementProperty.NamespaceURI != EncryptedXml.XmlEncNamespaceUrl)
                throw new CryptographicException(SR.Cryptography_Xml_InvalidEncryptionProperty);

            _elemProp = elementProperty;
            _cachedXml = null;
        }

        public string? Id { get; private set; }

        public string? Target { get; private set; }

        public XmlElement? PropertyElement
        {
            get { return _elemProp; }
            set
            {
                if (value == null)
                    throw new ArgumentNullException(nameof(value));
                if (value.LocalName != "EncryptionProperty" || value.NamespaceURI != EncryptedXml.XmlEncNamespaceUrl)
                    throw new CryptographicException(SR.Cryptography_Xml_InvalidEncryptionProperty);

                _elemProp = value;
                _cachedXml = null;
            }
        }

        [MemberNotNullWhen(true, nameof(_cachedXml))]
        private bool CacheValid => _cachedXml != null;

        public XmlElement GetXml()
        {
            if (CacheValid) return _cachedXml;

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            return GetXml(document);
        }

        internal XmlElement GetXml(XmlDocument document)
        {
            return (XmlElement)document.ImportNode(_elemProp, true);
        }

        [MemberNotNull(nameof(_elemProp))]
        [MemberNotNull(nameof(_cachedXml))]
        public void LoadXml(XmlElement value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));
            if (value.LocalName != "EncryptionProperty" || value.NamespaceURI != EncryptedXml.XmlEncNamespaceUrl)
                throw new CryptographicException(SR.Cryptography_Xml_InvalidEncryptionProperty);

            // cache the Xml
            _cachedXml = value;
            Id = Utils.GetAttribute(value, "Id", EncryptedXml.XmlEncNamespaceUrl);
            Target = Utils.GetAttribute(value, "Target", EncryptedXml.XmlEncNamespaceUrl);
            _elemProp = value;
        }
    }
}
