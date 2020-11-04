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
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """CEF:.+?\|([^\|]+\|){4}({alert_name}[^\|]+)""",
    """CEF:([^\|]+\|){6}({alert_severity}\d+)\|""",
    """\WexternalId=({alert_id}\d+)""",
    """\Wcat=({alert_type}[^\=]+?)\s+\w+=""",
    """\Wcs2="?({process}.+?)"?\s+cs2Label=""",
    """\Wcs1=({process_name}[^\=]+)\s+""",
    """\Wsuser=\['(((NT AUTHORITY|TEST|({domain}[^\\\=]+))\\+)?(N\/A|LOCAL SERVICE|SYSTEM|Administrator|NETWORK SERVICE|({user}[^\=]+?)))(',\s|'\]\s+\w+=)""",
    """\Wshost=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\=]+?))\s+\w+=""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)\s""",
    """\Wspt=({src_port}\d+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)\s""",
    """\Wdpt=({dest_port}\d+)""",
    """\Wact=({action}[\w\s\(\)]+)""",
    """\WfileHash=({sha256_sum}[A-Za-z0-9]+)\s""",
    """\WfilePath=(System|({file_path}({file_parent}[^\=]*?)[\\\/]*({file_name}[^\\]+?(?:\.({file_ext}[^\.\s]+))?)))\s\w+=""",
    """\Wrequest=({malware_url}[^\=]+)\s+\w+="""
  ]
}
```