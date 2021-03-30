#### Parser Content
```Java
{
Name = cef-unix-crypto-1
  DataType = "remore-logon"
  Conditions = [ """CEF""", """Unix|auditd""", """CRYPTO_SESSION""" ]
  Fields = ${UnixParserTemplates.cef-unix-template-1.Fields}[
    """CEF:([^\|]*\|){4}({event_name}[^|]+)\\\|({outcome}[^\|]+)""",
    """src=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """spt=({src_port}\d+)""",
    """dpt=({dest_port}\d+)"""
    ]
}
cef-unix-template-1 = {
    Vendor = Unix
    Product = Unix Auditd
    Lms = Direct
    TimeFormat = epoch
    Fields = [
      """\srt=({time}\d+)""",
      """\Wagt=({host}[A-Fa-f:\d.]+)""",
      """\sdvc(host)?=({host}[^\s]+)"""
      """\sduid=({user_id}\d+)""",
      """\ssuid=({user_id}\d+)""",
      """auid=({account_id}\d+)""",
      """cat=({activity}[^\|\s]+)""",
      """destinationServiceName=({service_name}[^\s]+)""",
      """\WeventId=({log_id}\d+)"""
      """\Wcs4=({pid}\d+)""",
      """\sdproc=({process}({directory}[^\s]*?[\\\/]+)?({process_name}[^\s\\\/]+))\s+\w+=""",
      """categoryOutcome=\/({outcome}[^\s]+)""",
      """src=({src_ip}[^\s]+)"""
      """dst=({dest_ip}[^\s]+)"""
      """spt=({src_port}\d+)""",
      """dpt=({dest_port}\d+)""",
      """\sduser=(\(unknown\)|({user}.+?))\s+\w+=""",
      """dhost=({dest_host}[^\s]+)""",
      """shost=({src_host}[^\s]+)"""
      ]

```