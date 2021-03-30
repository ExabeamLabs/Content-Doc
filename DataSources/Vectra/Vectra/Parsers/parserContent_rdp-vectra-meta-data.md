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
vectra-meta-data = {
  Vendor = Vectra
  Product = Vectra
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