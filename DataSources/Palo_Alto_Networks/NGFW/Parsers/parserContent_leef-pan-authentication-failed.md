#### Parser Content
```Java
{
Name = leef-pan-authentication-failed
  DataType = "authentication-failed"
  Conditions = [ """LEEF:""","""|Palo Alto Networks|PAN-OS Syslog Integration|""","""type=auth""","""|auth-fail|""", ]
  Fields = ${PaloAltoParserTemplates.leef-pan-auth-event.Fields}[
    """Reason:\s{0,100}({failure_reason}[^\.]+)\.\s"""
  ]
}
leef-pan-auth-event = {
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Syslog
  TimeFormat = "MMM dd yyyy HH:mm:ss z"
  Fields = [
    """devTime=({time}\w+\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d\s\w+)""",
    """\s({host}[\w\.-]+)\s{1,100}LEEF:""",
    """LEEF:([^|]*\|){4}({event_name}[^|]+)""",
    """msg="({additional_info}[^"]+)"""",
    """user\s{0,100}'((({user}[^@']+)@({domain}[^']+))|(pre-logon|((({=domain}[^\\']+)\\)?({=user}[^']+))))'""",
    """From:\s{0,100}(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))"""
  ]

```