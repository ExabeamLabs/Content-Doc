#### Parser Content
```Java
{
Name = cef-unix-user-login-1
  DataType = "remote-logon"
  Conditions = [ """CEF""", """Unix|auditd""", """LOGIN""" ]
  Fields = ${UnixParserTemplates.cef-unix-template-1.Fields}[
    """CEF:([^\|]*\|){4}({event_name}[^|]+)\\"""
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