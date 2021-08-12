// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO;
using System.Xml;

namespace System.Security.Cryptography.Xml
{
    public class XmlDsigExcC14NTransform : Transform
    {
        private readonly Type[] _inputTypes = { typeof(Stream), typeof(XmlDocument), typeof(XmlNodeList) };
        private readonly Type[] _outputTypes = { typeof(Stream) };
        private readonly bool _includeComments;
        private ExcCanonicalXml? _excCanonicalXml;

        public XmlDsigExcC14NTransform() : this(false, null) { }

        public XmlDsigExcC14NTransform(bool includeComments) : this(includeComments, null) { }

        public XmlDsigExcC14NTransform(string inclusiveNamespacesPrefixList) : this(false, inclusiveNamespacesPrefixList) { }

        public XmlDsigExcC14NTransform(bool includeComments, string? inclusiveNamespacesPrefixList)
        {
            _includeComments = includeComments;
            InclusiveNamespacesPrefixList = inclusiveNamespacesPrefixList;
            Algorithm = (includeComments ? SignedXml.XmlDsigExcC14NWithCommentsTransformUrl : SignedXml.XmlDsigExcC14NTransformUrl);
        }

        public string? InclusiveNamespacesPrefixList { get; set; }

        public override Type[] InputTypes => _inputTypes;

        public override Type[] OutputTypes => _outputTypes;

        public override void LoadInnerXml(XmlNodeList nodeList)
        {
            if (nodeList == null)
            {
                return;
            }

            foreach (XmlNode n in nodeList)
            {
                if (n is XmlElement e)
                {
                    if (e.LocalName.Equals("InclusiveNamespaces")
                    && e.NamespaceURI.Equals(SignedXml.XmlDsigExcC14NTransformUrl) &&
                    Utils.HasAttribute(e, "PrefixList", SignedXml.XmlDsigNamespaceUrl))
                    {
                        if (!Utils.VerifyAttributes(e, "PrefixList"))
                        {
                            throw new CryptographicException(SR.Cryptography_Xml_UnknownTransform);
                        }
                        this.InclusiveNamespacesPrefixList = Utils.GetAttribute(e, "PrefixList", SignedXml.XmlDsigNamespaceUrl);
                        return;
                    }
                    else
                    {
                        throw new CryptographicException(SR.Cryptography_Xml_UnknownTransform);
                    }
                }
            }
        }

        public override void LoadInput(object obj)
        {
            XmlResolver? resolver = (ResolverSet ? _xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), BaseURI));
            if (obj is Stream stream)
            {
                _excCanonicalXml = new ExcCanonicalXml(stream, _includeComments, InclusiveNamespacesPrefixList, resolver, BaseURI);
            }
            else if (obj is XmlDocument document)
            {
                _excCanonicalXml = new ExcCanonicalXml(document, _includeComments, InclusiveNamespacesPrefixList, resolver);
            }
            else if (obj is XmlNodeList list)
            {
                _excCanonicalXml = new ExcCanonicalXml(list, _includeComments, InclusiveNamespacesPrefixList, resolver);
            }
            else
                throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, nameof(obj));
        }

        protected override XmlNodeList? GetInnerXml()
        {
            if (InclusiveNamespacesPrefixList == null)
                return null;
            XmlDocument document = new XmlDocument();
            XmlElement element = document.CreateElement("Transform", SignedXml.XmlDsigNamespaceUrl);
            if (!string.IsNullOrEmpty(Algorithm))
                element.SetAttribute("Algorithm", Algorithm);
            XmlElement prefixListElement = document.CreateElement("InclusiveNamespaces", SignedXml.XmlDsigExcC14NTransformUrl);
            prefixListElement.SetAttribute("PrefixList", InclusiveNamespacesPrefixList);
            element.AppendChild(prefixListElement);
            return element.ChildNodes;
        }

        public override object GetOutput()
        {
            return new MemoryStream(_excCanonicalXml.GetBytes());
        }

        public override object GetOutput(Type type)
        {
            if (type != typeof(Stream) && !type.IsSubclassOf(typeof(Stream)))
                throw new ArgumentException(SR.Cryptography_Xml_TransformIncorrectInputType, nameof(type));
            return new MemoryStream(_excCanonicalXml.GetBytes());
        }

        public override byte[] GetDigestedOutput(HashAlgorithm hash)
        {
            return _excCanonicalXml.GetDigestedBytes(hash);
        }
    }
}
