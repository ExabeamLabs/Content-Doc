#### Parser Content
```Java
{
Name = leef-pan-authentication-successful-1
  DataType = "authentication-successful"
  Conditions = [ """LEEF:""","""|Palo Alto Networks|PAN-OS Syslog Integration|""","""type=auth""","""|saml-signature-validated|""", ]

leef-pan-auth-event = {
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Syslog
  TimeFormat = "MMM dd yyyy HH:mm:ss z"
  Fields = [
    """devTime=({time}\w+\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d\s\w+)""",
    """\s({host}[\w\.-]{1,2000})\s{1,100}LEEF:""",
    """LEEF:([^|]{0,2000}\|){4}({event_name}[^|]{1,2000})""",
    """msg="({additional_info}[^"]{1,2000})"""",
    """user\s{0,100}'((({user}[^@']{1,2000})@({domain}[^']{1,2000}))|(pre-logon|((({=domain}[^\\']{1,2000})\\)?({=user}[^']{1,2000}))))'""",
    """From:\s{0,100}(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))"""
  
}
```