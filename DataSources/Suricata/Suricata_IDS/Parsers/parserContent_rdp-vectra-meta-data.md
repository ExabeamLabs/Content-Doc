#### Parser Content
```Java
{
Name = rdp-vectra-meta-data
  DataType = "remote-logon"
  Conditions = [ """vectra_metadata_rdp""", """METADATA_RDP""" ]
  Fields = ${VectraParserTemplates.vectra-meta-data.Fields} [
    """result="{1,20}({outcome}[^"]{1,2000})"{1,20}"""
  ]
}
vectra-meta-data = {
  Vendor = Vectra
  Product = Vectra Cognito Stream
  Lms = Direct
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """ts="{1,20}({time}\d{1,100})""",
    """id.orig_h="{1,20}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"{1,20}"""
    """id.orig_p="{1,20}({src_port}\d{1,100})"{1,20}""",
    """id.resp_h="{1,20}({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"{1,20}""",
    """id.resp_p="{1,20}({dest_port}\d{1,100})"{1,20}""",
    """orig_hostname="{1,20}({src_host}[^"]{1,2000})"{1,20}"""
    """resp_hostname="{1,20}(null|((IP-)*({dest_host}[^"]{1,2000})))"""
  ]

```