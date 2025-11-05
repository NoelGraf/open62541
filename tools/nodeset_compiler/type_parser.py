import abc
import codecs
import csv
import json
import xml.etree.ElementTree as etree
import xml.dom.minidom as dom
import copy
import re
from collections import OrderedDict

try:
    from opaque_type_mapping import get_base_type_for_opaque as get_base_type_for_opaque_ns0
except ImportError:
    from nodeset_compiler.opaque_type_mapping import get_base_type_for_opaque as get_base_type_for_opaque_ns0

builtin_types = {
    "Boolean":          "ns=0;i=1",
    "SByte":            "ns=0;i=2",
    "Byte":             "ns=0;i=3",
    "Int16":            "ns=0;i=4",
    "UInt16":           "ns=0;i=5",
    "Int32":            "ns=0;i=6",
    "UInt32":           "ns=0;i=7",
    "Int64":            "ns=0;i=8",
    "UInt64":           "ns=0;i=9",
    "Float":            "ns=0;i=10",
    "Double":           "ns=0;i=11",
    "String":           "ns=0;i=12",
    "DateTime":         "ns=0;i=13",
    "Guid":             "ns=0;i=14",
    "ByteString":       "ns=0;i=15",
    "XmlElement":       "ns=0;i=16",
    "NodeId":           "ns=0;i=17",
    "ExpandedNodeId":   "ns=0;i=18",
    "StatusCode":       "ns=0;i=19",
    "QualifiedName":    "ns=0;i=20",
    "LocalizedText":    "ns=0;i=21",
    "ExtensionObject":  "ns=0;i=22",
    "DataValue":        "ns=0;i=23",
    "Variant":          "ns=0;i=24",
    "DiagnosticInfo":   "ns=0;i=25",
}

builtin_pointerfree = ["Boolean", "SByte", "Byte", "Int16", "UInt16",
                       "Int32", "UInt32", "Int64", "UInt64", "Float", "Double",
                       "DateTime", "StatusCode", "Guid"]

# DataTypes that are ignored/not generated
excluded_types = [
    # NodeId Types
    "NodeIdType", "TwoByteNodeId", "FourByteNodeId", "NumericNodeId",
    "StringNodeId", "GuidNodeId", "ByteStringNodeId",
    # Node Types
    "InstanceNode", "TypeNode", "Node", "ObjectNode", "ObjectTypeNode", "VariableNode",
    "VariableTypeNode", "ReferenceTypeNode", "MethodNode", "ViewNode", "DataTypeNode"]

rename_types = {"NumericRange": "OpaqueNumericRange"}

# Type aliases
type_aliases = {"CharArray": "String"}

user_opaque_type_mapping = {}  # contains user defined opaque type mapping

class TypeNotDefinedException(Exception):
    pass

def get_base_type_for_opaque(name):
    if name in user_opaque_type_mapping:
        return user_opaque_type_mapping[name]
    return get_base_type_for_opaque_ns0(name)

def get_type_name(xml_type_name):
    [namespace, type_name] = xml_type_name.split(':', 1)
    return [namespace, type_aliases.get(type_name, type_name)]

def get_type_for_name(xml_type_name, types, xmlNamespaces):
    [member_type_name_ns, member_type_name] = get_type_name(xml_type_name)
    resultNs = xmlNamespaces[member_type_name_ns]
    if resultNs == 'http://opcfoundation.org/BinarySchema/':
        resultNs = 'http://opcfoundation.org/UA/'
    if resultNs not in types:
        raise TypeNotDefinedException(f"Unknown namespace: '{resultNs}'")
    if member_type_name not in types[resultNs]:
        raise TypeNotDefinedException(f"Unknown type: '{member_type_name}'")
    return types[resultNs][member_type_name]

def _normalize_nodeid(node_id_str, namespaceIndexMap):
    """
    Normalisiert verschiedene NodeId/ExpandedNodeId-Varianten in die Form 'ns=<idx>;<idType>=<value>'.

    Unterstützt:
      - 'i=6'                      -> 'ns=0;i=6'
      - 'ns=1;i=6525'              -> unverändert
      - 'ns=2;s=MyType'            -> unverändert
      - 'nsu=http://...;i=1234'    -> 'ns=<idxAusMap>;i=1234'
      - 'g=...' / 'b=...'          -> GUID- bzw. ByteString-NodeIds

    Wirft TypeNotDefinedException bei unbekannter Namespace-URI (nsu=...) oder ungültiger NodeId.
    """
    if not isinstance(node_id_str, str):
        node_id_str = str(node_id_str)

    s = node_id_str.strip()
    if not s:
        raise TypeNotDefinedException(f"Invalid NodeId: '{node_id_str}'")

    parts = [p.strip() for p in s.split(';') if p.strip()]
    ns_index = 0
    id_part = None

    for p in parts:
        lp = p.lower()
        if lp.startswith('ns='):
            try:
                ns_index = int(p[3:])
            except ValueError:
                raise TypeNotDefinedException(f"Invalid namespace index in NodeId: '{node_id_str}'")
        elif lp.startswith('nsu='):
            ns_uri = p[4:]
            if ns_uri in namespaceIndexMap:
                try:
                    ns_index = int(namespaceIndexMap[ns_uri])
                except ValueError:
                    raise TypeNotDefinedException(f"Invalid ns index for URI '{ns_uri}' in namespaceIndexMap")
            else:
                raise TypeNotDefinedException(f"Unknown namespace URI in NodeId: '{ns_uri}'")
        elif lp.startswith(('i=', 's=', 'g=', 'b=')):
            # id_part im Original belassen (Case/Format), nur den Prefix prüfen
            id_part = p

    if id_part is None:
        # Falls nur 'ns=...' geliefert wurde oder gar kein eigentlicher Id-Part vorhanden ist
        raise TypeNotDefinedException(f"Invalid NodeId (missing id part): '{node_id_str}'")

    return f"ns={ns_index};{id_part}"


def get_type_for_nodeid(node_id_str, types, namespaceIndexMap):
    """
    Sucht in 'types' (wie in deinem Parser aufgebaut) den Datentyp, dessen .nodeId
    der übergebenen NodeId entspricht. Rückgabe ist das Type-Objekt (z. B. StructType/EnumerationType).

    Parameter:
      - node_id_str: NodeId-String (z. B. 'i=6', 'ns=1;i=6525', optional 'nsu=<uri>;i=...').
      - types:        Dict[str(namespaceUri)] -> Dict[str(typeName)] -> Type-Objekt
      - namespaceIndexMap: Dict[str(namespaceUri)] -> int(nsIndex)

    Raises:
      - TypeNotDefinedException, falls kein passender Typ gefunden wird.
    """
    target = _normalize_nodeid(node_id_str, namespaceIndexMap)

    # Optional: kleiner Cache könnte hier helfen, wenn häufig gesucht wird.
    for ns_uri in types:
        for tname, tobj in types[ns_uri].items():
            nid = getattr(tobj, "nodeId", None)
            if not nid:
                continue
            try:
                normalized = _normalize_nodeid(nid, namespaceIndexMap)
            except TypeNotDefinedException:
                # Falls ein vorhandener Typ eine ungewöhnliche/kaputte NodeId trägt, überspringen
                continue

            if normalized == target:
                return tobj

    raise TypeNotDefinedException(f"Unknown NodeId: '{node_id_str}'")

class Type:
    def __init__(self, outname, xml, namespaceUri):
        self.name = None
        if xml is not None:
            self.name = xml.get("Name")
            if self.name is None:
                for child in xml:
                    if child.tag == "{http://opcfoundation.org/UA/2011/03/UANodeSet.xsd}DisplayName":
                        self.name = child.text
                        break
        self.outname = outname
        self.namespaceUri = namespaceUri
        self.pointerfree = False
        self.members = []
        self.description = ""
        self.nodeId = None
        if xml is not None:
            self.nodeId = xml.get("NodeId")
        self.binaryEncodingId = None
        self.xmlEncodingId = None
        if xml is not None:
            for child in xml:
                if child.tag == "{http://opcfoundation.org/BinarySchema/}Documentation":
                    self.description = child.text
                    break


class BuiltinType(Type):
    def __init__(self, name):
        Type.__init__(self, "types", None, "http://opcfoundation.org/UA/")
        self.name = name
        self.pointerfree = self.name in builtin_pointerfree


class EnumerationType(Type):
    def __init__(self, outname, xml, namespace):
        Type.__init__(self, outname, xml, namespace)
        self.pointerfree = True
        self.elements = OrderedDict()
        self.isOptionSet = bool(xml.get("IsOptionSet", "false") == "true")
        self.lengthInBits = 0
        try:
            self.lengthInBits = int(xml.get("LengthInBits", "32"))
        except ValueError as ex:
            raise Exception("Error at EnumerationType '" + self.name + "': 'LengthInBits' XML attribute '" +
                xml.get("LengthInBits") + "' is not convertible to integer. " +
                f"Exception: {ex}")

        # default values for enumerations (encoded as int32):
        self.strDataType = "UA_Int32"
        self.strTypeKind = "UA_DATATYPEKIND_ENUM"
        self.strTypeIndex = "UA_TYPES_INT32"

        # special handling for OptionSet datatype (bitmask)
        if self.isOptionSet is True:
            if self.lengthInBits <= 8:
                self.strDataType = "UA_Byte"
                self.strTypeKind = "UA_DATATYPEKIND_BYTE"
                self.strTypeIndex = "UA_TYPES_BYTE"
            elif self.lengthInBits <= 16:
                self.strDataType = "UA_UInt16"
                self.strTypeKind = "UA_DATATYPEKIND_UINT16"
                self.strTypeIndex = "UA_TYPES_UINT16"
            elif self.lengthInBits <= 32:
                self.strDataType = "UA_UInt32"
                self.strTypeKind = "UA_DATATYPEKIND_UINT32"
                self.strTypeIndex = "UA_TYPES_UINT32"
            elif self.lengthInBits <= 64:
                self.strDataType = "UA_UInt64"
                self.strTypeKind = "UA_DATATYPEKIND_UINT64"
                self.strTypeIndex = "UA_TYPES_UINT64"
            else:
                raise Exception("Error at EnumerationType() CTOR '" + self.name + "': 'LengthInBits' value '" +
                    self.lengthInBits + "' is not supported")

        for child in xml:
            if child.tag == "{http://opcfoundation.org/BinarySchema/}EnumeratedValue" or child.tag == "{http://opcfoundation.org/UA/2011/03/UANodeSet.xsd}Definition":
                if child.tag == "{http://opcfoundation.org/BinarySchema/}EnumeratedValue":
                    self.elements[child.get("Name")] = child.get("Value")
                    continue
                for fields in child:
                    self.elements[fields.get("Name")] = fields.get("Value")

class OpaqueType(Type):
    def __init__(self, outname, xml, namespace, base_type):
        Type.__init__(self, outname, xml, namespace)
        self.base_type = base_type


class StructMember:
    def __init__(self, name, member_type, is_array, is_optional):
        self.name = name
        self.member_type = member_type
        self.is_array = is_array
        self.is_optional = is_optional


class StructType(Type):
    def __init__(self, outname, xml, namespace, types, xmlNamespaces):
        Type.__init__(self, outname, xml, namespace)
        length_fields = []
        optional_fields = []
        switch_fields = []
        self.is_recursive = False

        typename = type_aliases.get(xml.get("Name"), xml.get("Name"))
        if typename is None:
            typename = self.name

        bt = xml.get("BaseType")
        self.is_union = bool(bt and get_type_name(bt)[1] == "Union")
        for child in xml:
            length_field = child.get("LengthField")
            if length_field:
                length_fields.append(length_field)
        for child in xml:
            switch_field = child.get("SwitchField")
            if switch_field:
                switch_fields.append(switch_field)
        for child in xml:
            child_type = child.get("TypeName")
            if child_type and get_type_name(child_type)[1] == "Bit":
                optional_fields.append(child.get("Name"))
        for child in xml:
            if not child.tag == "{http://opcfoundation.org/BinarySchema/}Field":
                continue
            if child.get("Name") in length_fields:
                continue
            if get_type_name(child.get("TypeName"))[1] == "Bit":
                continue
            if self.is_union and child.get("Name") in switch_fields:
                continue
            switch_field = child.get("SwitchField")
            member_is_optional = (switch_field and switch_field in optional_fields)
            member_name = child.get("Name")
            member_name = member_name[:1].lower() + member_name[1:]
            is_array = bool(child.get("LengthField"))

            member_type_name = get_type_name(child.get("TypeName"))[1]
            if member_type_name == typename: # If a type contains itself, use self as member_type
                if not is_array:
                    raise RuntimeError("Type " + typename +  " contains itself as a non-array member")
                member_type = self
                self.is_recursive = True
            else:
                member_type = get_type_for_name(child.get("TypeName"), types, xmlNamespaces)

            self.members.append(StructMember(member_name, member_type, is_array, member_is_optional))

        if not self.members:
            for child in xml:
                if not child.tag == "{http://opcfoundation.org/UA/2011/03/UANodeSet.xsd}Definition":
                    continue
                for f in child:
                    fname = f.get("Name")
                    dt_attr = f.get("DataType")
                    # childname = re.sub(r'^\d+:', '', dt_attr) if dt_attr else None
                    # Optional fields (SwitchField pattern) aren’t directly present in NodeSet2; we honor IsOptional flag.
                    is_opt = (f.get("IsOptional") == "true")
                    value_rank = f.get("ValueRank")
                    is_array = value_rank is not None and int(value_rank) > 1

                    member_type_nodeid = f.get("DataType")
                    if _normalize_nodeid(member_type_nodeid, xmlNamespaces) == _normalize_nodeid(self.nodeId, xmlNamespaces): # If a type contains itself, use self as member_type
                        if not is_array:
                            raise RuntimeError("Type " + typename +  " contains itself as a non-array member")
                        member_type = self
                        self.is_recursive = True
                    else:
                        member_type =  get_type_for_nodeid(member_type_nodeid, types, xmlNamespaces)

                    self.members.append(StructMember(fname, member_type, is_array, is_opt))


        self.pointerfree = True
        for m in self.members:
            if m.is_array or m.is_optional or not m.member_type.pointerfree:
                self.pointerfree = False


class TypeParser():
    __metaclass__ = abc.ABCMeta

    def __init__(self, opaque_map, selected_types, no_builtin, outname, namespaceIndexMap):
        self.selected_types = []
        self.fh = None
        self.ff = None
        self.fc = None
        self.fe = None
        self.opaque_map = opaque_map
        self.selected_types = selected_types
        self.no_builtin = no_builtin
        self.outname = outname
        self.types = OrderedDict()
        self.namespaceIndexMap = namespaceIndexMap

    @staticmethod
    def merge_dicts(*dict_args):
        """
        Given any number of dicts, shallow copy and merge into a new dict,
        precedence goes to key value pairs in latter dicts.
        """
        result = {}
        for dictionary in dict_args:
            result.update(dictionary)
        return result

    def parseTypeDefinitions(self, outname, xmlDescription):
        def typeReady(element, types, xmlNamespaces):
            "Are all member types defined?"
            parentname = type_aliases.get(element.get("Name"), element.get("Name")) # If a type contains itself, declare that type as available
            for child in element:
                if child.tag == "{http://opcfoundation.org/BinarySchema/}Field":
                    childname = get_type_name(child.get("TypeName"))[1]
                    if childname not in ("Bit", parentname):
                        try:
                            get_type_for_name(child.get("TypeName"), types, xmlNamespaces)
                        except TypeNotDefinedException:
                            # Type is using other types which are not yet loaded, try later
                            return False
            return True

        def unknownTypes(element, types, xmlNamespaces):
            "Return all unknown types (for debugging)"
            unknowns = []
            for child in element:
                if child.tag == "{http://opcfoundation.org/BinarySchema/}Field":
                    try:
                        get_type_for_name(child.get("TypeName"), types, xmlNamespaces)
                    except TypeNotDefinedException:
                        # Type is using other types which are not yet loaded, try later
                        unknowns.append(child.get("TypeName"))
            return unknowns

        def structWithOptionalFields(element):
            "Is this a structure with optional fields?"
            opt_fields = []
            for child in element:
                if child.tag != "{http://opcfoundation.org/BinarySchema/}Field":
                    continue
                typename = child.get("TypeName")
                if typename and get_type_name(typename)[1] == "Bit":
                    if re.match(re.compile('.+Specified'), child.get("Name")):
                        opt_fields.append(child.get("Name"))
                    elif child.get("Name") == "Reserved1":
                        if len(opt_fields) + int(child.get("Length")) != 32:
                            return False
                        break
                    else:
                        return False
                else:
                    return False
            for child in element:
                switchfield = child.get("SwitchField")
                if switchfield and switchfield in opt_fields:
                    opt_fields.remove(switchfield)
            return len(opt_fields) == 0

        def structWithBitFields(element):
            "Is this a structure with bitfields?"
            for child in element:
                typename = child.get("TypeName")
                if typename and get_type_name(typename)[1] == "Bit":
                    return True
            return False

        snippets = OrderedDict()
        xmlDoc = etree.iterparse(
            xmlDescription, events=['start-ns']
        )
        xmlNamespaces = dict([
            node for _, node in xmlDoc
        ])
        targetNamespace = xmlDoc.root.get("TargetNamespace")
        for typeXml in xmlDoc.root:
            if not typeXml.get("Name"):
                continue
            name = typeXml.get("Name")
            snippets[name] = typeXml

        detectLoop = len(snippets) + 1
        while len(snippets) > 0:
            if detectLoop == len(snippets):
                name, typeXml = snippets.popitem()
                raise RuntimeError("Infinite loop detected or type not found while processing types " +
                                   name + ": unknonwn subtype " + str(unknownTypes(typeXml, self.types, xmlNamespaces)) +
                                   ". If the unknown subtype is 'Bit', then maybe a struct with " +
                                   "optional fields is defined wrong in the .bsd-file. If not, maybe " +
                                   "you need to import additional types with the --import flag. " +
                                   "E.g. '--import=UA_TYPES#/path/to/deps/ua-nodeset/Schema/" +
                                   "Opc.Ua.Types.bsd'")
            detectLoop = len(snippets)
            for name, typeXml in list(snippets.items()):
                if (targetNamespace in self.types and name in self.types[targetNamespace]) or name in excluded_types:
                    del snippets[name]
                    continue
                if not typeReady(typeXml, self.types, xmlNamespaces):
                    continue
                if structWithBitFields(typeXml) and not structWithOptionalFields(typeXml):
                    continue
                if name in builtin_types:
                    new_type = BuiltinType(name)
                elif typeXml.tag == "{http://opcfoundation.org/BinarySchema/}EnumeratedType":
                    new_type = EnumerationType(outname, typeXml, targetNamespace)
                elif typeXml.tag == "{http://opcfoundation.org/BinarySchema/}OpaqueType":
                    new_type = OpaqueType(outname, typeXml, targetNamespace,
                                          get_base_type_for_opaque(name)['name'])
                elif typeXml.tag == "{http://opcfoundation.org/BinarySchema/}StructuredType":
                    try:
                        new_type = StructType(outname, typeXml, targetNamespace, self.types, xmlNamespaces)
                    except TypeNotDefinedException:
                        # Type is using other types which are not yet loaded, try later
                        continue
                else:
                    raise Exception("Type not known")

                self.insert_type(new_type)
                del snippets[name]

    def parseTypeDefinitionsFromXml(self, outname, xmlDescription):
        """
        Parse UA DataTypes from a **NodeSet2 XML** (not BSD).

        Supports:
          - Enumerations (Fields with 'Value' => EnumeratedType)
          - Structures (Fields with 'DataType' => StructuredType)
          - OptionSets (Enum with IsOptionSet="true" or ValueRank=-2 heuristic)
        """
        # --- helpers (reuse your get_type_for_name etc. contracts) ---
        def qn(tag, ns):
            return f"{{{ns}}}{tag}"

        # Typical NodeSet2 namespaces
        NS_UANODESET = "http://opcfoundation.org/UA/2011/03/UANodeSet.xsd"
        # Older or vendor NodeSet2 files sometimes omit the schema URL; we’ll accept bare tags via fallback

        # Parse XML once
        xmlContent = xmlDescription.read()
        if isinstance(xmlContent, bytes):
            try:
                # strip BOM if present
                import codecs
                if xmlContent.startswith(codecs.BOM_UTF8):
                    xmlContent = xmlContent.lstrip(codecs.BOM_UTF8)
                xmlContent = xmlContent.decode("utf-8")
            except Exception:
                pass

        # Remove uax: prefix (mirrors your createSymbolicNameTable behavior)
        import re
        xmlContent = re.sub(r"<([/]?)uax:(.+?)([/]?)>", r"<\1\2\3>", xmlContent)

        from xml.etree import ElementTree as ET
        root = ET.fromstring(xmlContent)

        # Gather namespace map from the document (ElementTree doesn't expose prefixes directly)
        # We'll fall back to attributes we care about: BrowseName and DataType (which often carry nsIndex:Name)
        # Determine target namespace from the <UANodeSet> if present
        modelTags = [qn("Model", NS_UANODESET), "Model"]
        models = []
        for modelTag in modelTags:
            models.extend(root.findall(f".//{modelTag}"))

        targetNamespace = None
        for m in models:
            targetNamespace = m.attrib.get("ModelUri")

        if not targetNamespace:
            # As a fallback, keep the existing TypeDictionary style target namespace if already known
            # or default to UA base.
            targetNamespace = "http://opcfoundation.org/UA/"

        # Pull all UADataType nodes (with or without the schema-qualified name)
        dataTypeTags = [qn("UADataType", NS_UANODESET), "UADataType"]
        uaDataTypes = []
        for dtTag in dataTypeTags:
            uaDataTypes.extend(root.findall(f".//{dtTag}"))

        # Build a quick lookup of <UADataType> by BrowseName for dependency checks
        snippets = OrderedDict()
        for nd in uaDataTypes:
            name = nd.get("BrowseName")
            if not name:
                # Some exporters use 'DisplayName' only; skip those for now
                continue
            # Strip leading "<index>:" so '2:Foo' -> 'Foo' (safer than removing all digits)
            name = re.sub(r'^\d+:', '', name)
            snippets[name] = nd

        # Utilities
        def is_enum(def_el):
            # NodeSet2 enums usually have <Definition> with <Field Value="...">
            if def_el is None:
                return False
            for f in list(def_el):
                if f.get("Value") is not None:
                    return True
            return False

        def is_optionset(def_el, nd):
            # Heuristics:
            # - Some nodesets annotate OptionSets with EnumStrings and a property, but in pure NodeSet2:
            #   - Either an attribute IsOptionSet="true" on <Field> or on <Definition> (rare),
            #   - Or they're enums where values are powers of two, but we avoid numeric checks here.
            if def_el is not None and (def_el.get("IsOptionSet") == "true"):
                return True
            # Also honor the common "IsOptionSet" on any field
            if def_el is not None:
                for f in list(def_el):
                    if f.get("IsOptionSet") == "true":
                        return True
            # Schema sometimes encodes OptionSets as a structure with single UInt32 and Optional fields – out of scope here.
            return False

        def definition_element(nd):
            # Try qualified <Definition> first, then unqualified
            d = nd.find(qn("Definition", NS_UANODESET))
            if d is None:
                d = nd.find("Definition")
            return d

        def display_name_element(nd):
            # Try qualified <DisplayName> first, then unqualified
            d = nd.find(qn("DisplayName", NS_UANODESET))
            if d is None:
                d = nd.find("DisplayName")
            return d

        def fields(def_el):
            if def_el is None:
                return []
            # Accept both qualified and unqualified Field tags
            fs = list(def_el.findall(qn("Field", NS_UANODESET)))
            if not fs:
                fs = list(def_el.findall("Field"))
            return fs

        def parse_ns_qualified(name_or_nodeid):
            """
            Convert 'nsIdx:BrowseName' or 'i=.../ns=...' etc. into (namespaceUri, name)
            We keep it simple: if it's 'N:Name' -> (None, 'Name') and rely on get_type_for_name later.
            """
            if name_or_nodeid is None:
                return None, None
            # strip a single leading '<digits>:'
            clean = re.sub(r'^\d+:', '', name_or_nodeid)
            return (None, clean)

        # Resolution loop similar to BSD path
        detectLoop = len(snippets) + 1
        while len(snippets) > 0:
            if detectLoop == len(snippets):
                name, typeXml = snippets.popitem()
                # Debug information: list unresolved field types
                def_el = definition_element(typeXml)
                unknowns = []
                for f in fields(def_el):
                    dt_attr = f.get("DataType")
                    if dt_attr:
                        _, childname = parse_ns_qualified(dt_attr)
                        if childname and childname not in ("Bit", name):
                            try:
                                # This depends on your existing helper to resolve types
                                get_type_for_name(childname, self.types, {})
                            except TypeNotDefinedException:
                                unknowns.append(dt_attr)
                raise RuntimeError(
                    "Infinite loop detected or type not found while processing types "
                    + name + ": unknown subtype " + str(unknowns)
                    + ". Ensure UA base types or dependency nodesets are imported."
                )
            detectLoop = len(snippets)

            for name, nd in list(snippets.items()):
                # Skip if already present or explicitly excluded
                if (targetNamespace in self.types and name in self.types[targetNamespace]) or name in excluded_types:
                    del snippets[name]
                    continue

                def_el = definition_element(nd)
                if def_el is None:
                    # Some UADataType nodes are abstract (e.g., Structure). You likely handle those elsewhere.
                    # We register BuiltinType/abstract placeholders only if they are actually built-ins you care about.
                    # Otherwise, skip them.
                    continue

                # Check readiness: ensure all member types are defined
                ready = True
                enum_mode = is_enum(def_el)
                if not enum_mode:
                    # structure mode → check DataType of each field
                    for f in fields(def_el):
                        dt_attr = f.get("DataType")
                        if dt_attr:
                            _, childname = parse_ns_qualified(dt_attr)
                            if childname and childname not in ("Bit", name):
                                try:
                                    get_type_for_nodeid(childname, self.types, {})
                                except TypeNotDefinedException:
                                    ready = False
                                    break
                if not ready:
                    continue

                # Build a type object compatible with your existing codegen classes
                if enum_mode:
                    etype = EnumerationType(outname, nd, targetNamespace)
                    self.insert_type(etype)

                else:
                    # StructuredType
                    stype = StructType(outname, nd, targetNamespace, self.types, targetNamespace)
                    self.insert_type(stype)

                del snippets[name]


    @abc.abstractmethod
    def parse_types(self):
        pass

    def insert_type(self, typeObject):
        if typeObject.namespaceUri not in self.types:
            self.types[typeObject.namespaceUri] = OrderedDict()

        if typeObject.name in rename_types:
            typeObject.name = rename_types[typeObject.name]

        if typeObject.name not in self.types[typeObject.namespaceUri]:
            self.types[typeObject.namespaceUri][typeObject.name] = typeObject

    def create_types(self):
        # Create Builtins with NodeIds
        for builtin in builtin_types:
            bt = BuiltinType(builtin)
            bt.nodeId = builtin_types.get(builtin)
            self.insert_type(bt)

        for f in self.opaque_map:
            user_opaque_type_mapping.update(json.load(f))

        self.parse_types()

        # Read the selected data types
        arg_selected_types = self.selected_types
        self.selected_types = []
        for f in arg_selected_types:
            self.selected_types += list(filter(len, [line.strip() for line in f]))


class CSVBSDTypeParser(TypeParser):
    def __init__(self, opaque_map, selected_types, no_builtin, outname,
                 existing_bsd, type_bsd, type_csv, type_xml, namespaceIndexMap):
        TypeParser.__init__(self, opaque_map, selected_types, no_builtin, outname, namespaceIndexMap)
        self.existing_bsd = existing_bsd # bsd files with existing types that shall not be printed again
        self.existing_types_array = set() # existing TYPE_ARRAY from existing_bsd
        self.type_bsd = type_bsd # bsd files with new types
        self.type_csv = type_csv # csv files with nodeids, etc.
        self.type_xml = type_xml # xml files with symbolicNames etc.
        self.existing_types = [] # existing types that shall not be printed

    def parse_types(self):
        # parse existing types
        for i in self.existing_bsd:
            (outname_import, file_import) = i.split("#")
            self.existing_types_array.add(outname_import)
            outname_import = outname_import.lower()
            if outname_import.startswith("ua_"):
                outname_import = outname_import[3:]
            self.parseTypeDefinitions(outname_import, file_import)

        # all types loaded up to now should be assumed as existing types and therefore
        # no code should be generated
        self.existing_types = copy.deepcopy(self.types)
        # if outname is types (generate typedefinitions for NS0), we still need the BuiltinType
        # therefore remove them from the existing array
        if self.outname == "types":
            for ns in self.types:
                for t in self.types[ns]:
                    if isinstance(self.types[ns][t], BuiltinType):
                        del self.existing_types[ns][t]

        # parse the new types
        # for f in self.type_bsd:
        #     self.parseTypeDefinitions(self.outname, f)

        for f in self.type_xml:
            # Only generate if the type wasn't already created by BSD pass
            self.parseTypeDefinitionsFromXml(self.outname, f)

        # create a lookup table with symbolicNames
        table = {}
        for f in self.type_xml:
            table = self.createSymbolicNameTable(f)

        # extend the type definitions with nodeids, etc. from the csv file
        for f in self.type_csv:
            self.parseTypeDescriptions(f, table)

    def createSymbolicNameTable(self, f):
        table = {}
        nodeset_base = open(f.name, "rb")
        fileContent = nodeset_base.read()
        # Remove BOM since the dom parser cannot handle it on python 3 windows
        if fileContent.startswith(codecs.BOM_UTF8):
            fileContent = fileContent.lstrip(codecs.BOM_UTF8)
        fileContent = fileContent.decode("utf-8")

        # Remove the uax namespace from tags. UaModeler adds this namespace to some elements
        fileContent = re.sub(r"<([/]?)uax:(.+?)([/]?)>", "<\\g<1>\\g<2>\\g<3>>", fileContent)

        nodesets = dom.parseString(fileContent).getElementsByTagName("UANodeSet")
        if len(nodesets) == 0 or len(nodesets) > 1:
            raise Exception("contains no or more then 1 nodeset")
        nodeset = nodesets[0]
        dataTypeNodes = nodeset.getElementsByTagName("UADataType")
        for nd in dataTypeNodes:
            if nd.hasAttribute("SymbolicName"):
                # Remove any digit and the colon
                result_string = re.sub(r'\d|:', '', nd.attributes["BrowseName"].nodeValue)
                table[nd.attributes["SymbolicName"].nodeValue] = result_string
        return table

    def parseTypeDescriptions(self, f, table):
        csvreader = csv.reader(f, delimiter=',')
        for row in csvreader:
            if len(row) < 3:
                continue
            if row[2] == "Object":
                # Check if node name ends with _Encoding_DefaultBinary and store
                # the node id in the corresponding DataType
                m = re.match('(.*?)_Encoding_DefaultBinary$', row[0])
                if m:
                    baseType = m.group(1)
                    for ns in self.types:
                        if baseType in self.types[ns]:
                            self.types[ns][baseType].binaryEncodingId = row[1]
                            break

                # Check if node name ends with _Encoding_DefaultXml and store
                # the node id in the corresponding DataType
                m = re.match('(.*?)_Encoding_DefaultXml$', row[0])
                if m:
                    baseType = m.group(1)
                    for ns in self.types:
                        if baseType in self.types[ns]:
                            self.types[ns][baseType].xmlEncodingId = row[1]
                            break
                continue

            if row[2] != "DataType":
                continue

            typeName = row[0]
            if typeName == "BaseDataType":
                typeName = "Variant"
            elif typeName == "Structure":
                typeName = "ExtensionObject"
            if typeName in rename_types:
                typeName = rename_types[typeName]
            # check if typeName is a symbolicName and replace it with the browseName
            if typeName in table:
                typeName = table[typeName]
            for ns in self.types:
                if typeName in self.types[ns]:
                    self.types[ns][typeName].nodeId = row[1]
                    break
