#### Parser Content
```Java
{
Name = cef-unix-user-cmd-1
  DataType = "process-created"
  Conditions = [ """CEF""", """Unix|auditd""", """USER_CMD""" ]
  Fields = ${UnixParserTemplates.cef-unix-template-1.Fields}[
    """cmd\\=({command}[^\s]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){4}({event_name}[^|]{1,2000})\\"""
    ]
}
cef-unix-template-1 = {
    Vendor = Unix
    Product = Unix Auditd
    Lms = Direct
    TimeFormat = epoch
    Fields = [
      """\srt=({time}\d{1,100})""",
      """\Wagt=({host}[A-Fa-f:\d.]{1,2000})""",
      """\sdvc(host)?=({host}[^\s]{1,2000})"""
      """\sduid=({user_id}\d{1,100})""",
      """\ssuid=({user_id}\d{1,100})""",
      """auid=({account_id}\d{1,100})""",
      """cat=({activity}[^\|\s]{1,2000})""",
      """destinationServiceName=({service_name}[^\s]{1,2000})""",
      """\WeventId=({log_id}\d{1,100})"""
      """\Wcs4=({pid}\d{1,100})""",
      """\sdproc=({process}({directory}[^\s]{0,2000}?[\\\/]{1,2000})?({process_name}[^\s\\\/]{1,2000}))\s{1,100}\w+=""",
      """categoryOutcome=\/({outcome}[^\s]{1,2000})""",
      """src=({src_ip}[^\s]{1,2000})"""
      """dst=({dest_ip}[^\s]{1,2000})"""
      """spt=({src_port}\d{1,100})""",
      """dpt=({dest_port}\d{1,100})""",
      """\sduser=(\(unknown\)|({user}.+?))\s{1,100}\w+=""",
      """dhost=({dest_host}[^\s]{1,2000})""",
      """shost=({src_host}[^\s]{1,2000})"""
      ]

```