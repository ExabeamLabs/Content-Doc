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
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """CEF:[^|]+?\|([^\|]+\|){4}({alert_name}[^\|]+)""",
    """CEF:([^\|]+\|){6}({alert_severity}\d{1,100})\|""",
    """\WexternalId=({alert_id}\d{1,100})""",
    """\Wcat=({alert_type}[^\=]+?)\s{1,100}\w+=""",
    """\Wcs2="?({process}.+?)"?\s{1,100}cs2Label=""",
    """\Wcs1=({process_name}[^\=]+)\s{1,100}""",
    """\Wsuser=\['(((NT AUTHORITY|TEST|({domain}[^\\\=]+))\\+)?(N\/A|LOCAL SERVICE|SYSTEM|Administrator|NETWORK SERVICE|({user}[^\=]+?)))(',\s|'\]\s{1,100}\w+=)""",
    """\Wshost=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\=]+?))\s{1,100}\w+=""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)\s""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)\s""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wact=({action}[\w\s\(\)]+)""",
    """\WfileHash=({sha256_sum}[A-Za-z0-9]+)\s""",
    """\WfilePath=(System|({file_path}({file_parent}[^\=]*?)[\\\/]*({file_name}[^\\]+?(?:\.({file_ext}[^\.\s]+))?)))\s\w+=""",
    """\Wrequest=({malware_url}[^\=]+)\s{1,100}\w+="""
  ]
}
```