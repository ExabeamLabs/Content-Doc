#### Parser Content
```Java
{
Name = rdp-vectra-meta-data
  DataType = "remote-logon"
  Conditions = [ """vectra_metadata_rdp""", """METADATA_RDP""" ]
  Fields = ${VectraParserTemplates.vectra-meta-data.Fields} [
    """result="+({outcome}[^"]+)"+"""
  ]
}
```