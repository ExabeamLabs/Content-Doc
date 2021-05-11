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
      """\srt=({time}\d{1,100})""",
      """\Wagt=({host}[A-Fa-f:\d.]+)""",
      """\sdvc(host)?=({host}[^\s]+)"""
      """\sduid=({user_id}\d{1,100})""",
      """\ssuid=({user_id}\d{1,100})""",
      """auid=({account_id}\d{1,100})""",
      """cat=({activity}[^\|\s]+)""",
      """destinationServiceName=({service_name}[^\s]+)""",
      """\WeventId=({log_id}\d{1,100})"""
      """\Wcs4=({pid}\d{1,100})""",
      """\sdproc=({process}({directory}[^\s]*?[\\\/]+)?({process_name}[^\s\\\/]+))\s{1,100}\w+=""",
      """categoryOutcome=\/({outcome}[^\s]+)""",
      """src=({src_ip}[^\s]+)"""
      """dst=({dest_ip}[^\s]+)"""
      """spt=({src_port}\d{1,100})""",
      """dpt=({dest_port}\d{1,100})""",
      """\sduser=(\(unknown\)|({user}.+?))\s{1,100}\w+=""",
      """dhost=({dest_host}[^\s]+)""",
      """shost=({src_host}[^\s]+)"""
      ]

```