#### Parser Content
```Java
{
Name = ssh-vectra-meta-data
  DataType = "remote-logon"
  Conditions = [ """vectra_metadata_ssh""", """METADATA_SSH""" ]
  Fields = ${VectraParserTemplates.vectra-meta-data.Fields} [
    """server="{1,20}({server_version}[^"]{1,2000})"{1,20}""",
    """client="{1,20}({client_version}[^"]{1,2000})"{1,20}""",
    """cipher_alg="{1,20}({cipher_algorithm}[^"]{1,2000})"{1,20}""",
    """compression_alg="{1,20}(none|({compression_algotithm}[^"]{1,2000}))"{1,20}"""
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