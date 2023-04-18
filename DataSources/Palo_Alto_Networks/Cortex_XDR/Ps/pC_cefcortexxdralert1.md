#### Parser Content
```Java
{
Name = cef-cortex-xdr-alert-1
  Vendor = Palo Alto Networks
  Product = Cortex XDR
  Lms = Syslog
  DataType = "security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """CEF:""", """|Palo Alto Networks|Cortex XDR|""", """tenantname=""", """deviceFacility=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """CEF:[^|]{1,2000}?\|([^\|]{1,2000}\|){4}({alert_name}[^\|]{1,2000})""",
    """CEF:([^\|]{1,2000}\|){6}({alert_severity}\d{1,100})\|""",
    """\WexternalId=({alert_id}\d{1,100})""",
    """\Wcat=({alert_type}[^\=]{1,2000}?)\s{1,100}\w{1,100}=""",
    """\Wcs2="?({command_line}[^\n]{1,2000}?)\s{0,100}"?\s{1,100}cs2Label=""",
    """initiatorPath=(System|({process}[^=]{1,2000}))\s{1,100}(\w{1,100}=|$)""",
    """\Wcs1=({process_name}[^\=]{1,2000})\s{1,100}""",
    """\Wsuser=\['(((NT AUTHORITY|TEST|({domain}[^\\\=]{1,2000}))\\+)?(N\/A|LOCAL SERVICE|SYSTEM|Administrator|NETWORK SERVICE|({user}[^\=]{1,2000}?)))(',\s|'\]\s{1,100}\w{1,100}=)""",
    """\Wshost=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\=]{1,2000}?))\s{1,100}\w{1,100}=""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})\s""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})\s""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wact=({action}[^$]{1,2000}?)\s{0,100}($|")""",
    """\WfileHash=({sha256_sum}[A-Za-z0-9]{1,2000})\s""",
    """\WfilePath=(System|({file_path}({file_parent}[^=]{1,2000}\\)?({file_name}[^\s]{1,2000}?((\.({file_ext}[^\s\.]{1,100}))|))))\s{1,100}\w{1,100}=""",
    """\Wrequest=({malware_url}[^\=]{1,2000})\s{1,100}\w{1,100}=""",
    """\Wincident=({additional_info}[^\s]{1,2000})\s{1,100}\w{1,100}="""
  ]


}
```