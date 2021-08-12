// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections;
using System.Xml;

namespace System.Security.Cryptography.Xml
{
    public class Signature
    {
        private SignedInfo? _signedInfo;
        private string? _signatureValueId;
        private KeyInfo? _keyInfo;

        internal SignedXml? SignedXml { get; set; }

        //
        // public constructors
        //

        public Signature()
        {
            ObjectList = new ArrayList();
            ReferencedItems = new CanonicalXmlNodeList();
        }

        //
        // public properties
        //

        public string? Id { get; set; }

        public SignedInfo? SignedInfo
        {
            get => _signedInfo;
            set
            {
                _signedInfo = value;
                if (SignedXml != null && _signedInfo != null)
                    _signedInfo.SignedXml = SignedXml;
            }
        }

        public byte[]? SignatureValue { get; set; }

        public KeyInfo KeyInfo
        {
            get
            {
                _keyInfo ??= new KeyInfo();
                return _keyInfo;
            }
            set { _keyInfo = value; }
        }

        public IList ObjectList { get; set; }

        internal CanonicalXmlNodeList ReferencedItems { get; private set; }

        //
        // public methods
        //

        public XmlElement GetXml()
        {
            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            return GetXml(document);
        }

        internal XmlElement GetXml(XmlDocument document)
        {
            // Create the Signature
            XmlElement signatureElement = (XmlElement)document.CreateElement("Signature", SignedXml.XmlDsigNamespaceUrl);
            if (!string.IsNullOrEmpty(Id))
                signatureElement.SetAttribute("Id", Id);

            // Add the SignedInfo
            if (_signedInfo == null)
                throw new CryptographicException(SR.Cryptography_Xml_SignedInfoRequired);

            signatureElement.AppendChild(_signedInfo.GetXml(document));

            // Add the SignatureValue
            if (SignatureValue == null)
                throw new CryptographicException(SR.Cryptography_Xml_SignatureValueRequired);

            XmlElement signatureValueElement = document.CreateElement("SignatureValue", SignedXml.XmlDsigNamespaceUrl);
            signatureValueElement.AppendChild(document.CreateTextNode(Convert.ToBase64String(SignatureValue)));
            if (!string.IsNullOrEmpty(_signatureValueId))
                signatureValueElement.SetAttribute("Id", _signatureValueId);
            signatureElement.AppendChild(signatureValueElement);

            // Add the KeyInfo
            if (KeyInfo.Count > 0)
                signatureElement.AppendChild(KeyInfo.GetXml(document));

            // Add the Objects
            foreach (object obj in ObjectList)
            {
                if (obj is DataObject dataObj)
                {
                    signatureElement.AppendChild(dataObj.GetXml(document));
                }
            }

            return signatureElement;
        }

        public void LoadXml(XmlElement value)
        {
            // Make sure we don't get passed null
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            // Signature
            XmlElement signatureElement = value;
            if (!signatureElement.LocalName.Equals("Signature"))
                throw new CryptographicException(SR.Cryptography_Xml_InvalidElement, "Signature");

            // Id attribute -- optional
            Id = Utils.GetAttribute(signatureElement, "Id", SignedXml.XmlDsigNamespaceUrl);
            if (!Utils.VerifyAttributes(signatureElement, "Id"))
                throw new CryptographicException(SR.Cryptography_Xml_InvalidElement, "Signature");

            XmlNamespaceManager nsm = new XmlNamespaceManager(value.OwnerDocument.NameTable);
            nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            int expectedChildNodes = 0;

            // SignedInfo
            XmlNodeList? signedInfoNodes = signatureElement.SelectNodes("ds:SignedInfo", nsm);
            if (signedInfoNodes == null || signedInfoNodes.Count == 0 || signedInfoNodes.Count > 1)
                throw new CryptographicException(SR.Cryptography_Xml_InvalidElement, "SignedInfo");
            XmlElement? signedInfoElement = signedInfoNodes[0] as XmlElement;
            expectedChildNodes += signedInfoNodes.Count;

            SignedInfo = new SignedInfo();
            SignedInfo.LoadXml(signedInfoElement);

            // SignatureValue
            XmlNodeList? signatureValueNodes = signatureElement.SelectNodes("ds:SignatureValue", nsm);
            if (signatureValueNodes == null || signatureValueNodes.Count == 0 || signatureValueNodes.Count > 1)
                throw new CryptographicException(SR.Cryptography_Xml_InvalidElement, "SignatureValue");
            XmlElement signatureValueElement = (XmlElement)signatureValueNodes[0]!;
            expectedChildNodes += signatureValueNodes.Count;
            SignatureValue = Convert.FromBase64String(Utils.DiscardWhiteSpaces(signatureValueElement.InnerText));
            _signatureValueId = Utils.GetAttribute(signatureValueElement, "Id", SignedXml.XmlDsigNamespaceUrl);
            if (!Utils.VerifyAttributes(signatureValueElement, "Id"))
                throw new CryptographicException(SR.Cryptography_Xml_InvalidElement, "SignatureValue");

            // KeyInfo - optional single element
            XmlNodeList? keyInfoNodes = signatureElement.SelectNodes("ds:KeyInfo", nsm);
            _keyInfo = new KeyInfo();
            if (keyInfoNodes != null)
            {
                if (keyInfoNodes.Count > 1)
                {
                    throw new CryptographicException(SR.Cryptography_Xml_InvalidElement, "KeyInfo");
                }
                foreach (XmlNode node in keyInfoNodes)
                {
                    if (node is XmlElement keyInfoElement)
                        _keyInfo.LoadXml(keyInfoElement);
                }
                expectedChildNodes += keyInfoNodes.Count;
            }

            // Object - zero or more elements allowed
            XmlNodeList? objectNodes = signatureElement.SelectNodes("ds:Object", nsm);
            ObjectList.Clear();
            if (objectNodes != null)
            {
                foreach (XmlNode node in objectNodes)
                {
                    if (node is XmlElement objectElement)
                    {
                        DataObject dataObj = new DataObject();
                        dataObj.LoadXml(objectElement);
                        ObjectList.Add(dataObj);
                    }
                }
                expectedChildNodes += objectNodes.Count;
            }

            // Select all elements that have Id attributes
            XmlNodeList? nodeList = signatureElement.SelectNodes("//*[@Id]", nsm);
            if (nodeList != null)
            {
                foreach (XmlNode node in nodeList)
                {
                    ReferencedItems.Add(node);
                }
            }
            // Verify that there aren't any extra nodes that aren't allowed
            if (signatureElement.SelectNodes("*")?.Count != expectedChildNodes)
            {
                throw new CryptographicException(SR.Cryptography_Xml_InvalidElement, "Signature");
            }
        }

        public void AddObject(DataObject dataObject)
        {
            ObjectList.Add(dataObject);
        }
    }
}
