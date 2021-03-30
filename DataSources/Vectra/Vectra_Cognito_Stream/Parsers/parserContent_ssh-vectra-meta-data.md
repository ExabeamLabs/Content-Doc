#### Parser Content
```Java
{
Name = ssh-vectra-meta-data
  DataType = "remote-logon"
  Conditions = [ """vectra_metadata_ssh""", """METADATA_SSH""" ]
  Fields = ${VectraParserTemplates.vectra-meta-data.Fields} [
    """server="+({server_version}[^"]+)"+""",
    """client="+({client_version}[^"]+)"+""",
    """cipher_alg="+({cipher_algorithm}[^"]+)"+""",
    """compression_alg="+(none|({compression_algotithm}[^"]+))"+"""
  ]
}
vectra-meta-data = {
  Vendor = Vectra
  Product = Vectra Cognito Stream
  Lms = Direct
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """ts="+({time}\d+)""",
    """id.orig_h="+({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"+"""
    """id.orig_p="+({src_port}\d+)"+""",
    """id.resp_h="+({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"+""",
    """id.resp_p="+({dest_port}\d+)"+""",
    """orig_hostname="+({src_host}[^"]+)"+"""
    """resp_hostname="+(null|((IP-)*({dest_host}[^"]+)))"""
  ]

```