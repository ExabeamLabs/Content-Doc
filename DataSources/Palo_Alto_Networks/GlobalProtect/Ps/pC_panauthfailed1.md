#### Parser Content
```Java
{
Name = pan-auth-failed-1
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,SYSTEM,auth,""", """,auth-fail,""" ]
  Fields = [
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\d{1,100},({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}),""",    
    """"failed authentication for user '(localhost|none|system|\.{3}|({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%\.]{0,2000}:[A-Fa-f0-9%\.:]{1,2000}))|({user}[^@',]{1,2000})@({domain}[^@.,']{1,2000}\.lan)|({user_email}[^@',]{1,2000}@[^.]{1,2000}\.[^']{1,2000})|({=user}[^']{1,2000}))'""",
    """"When authenticating user '(localhost|none|system|\.{3}|({user}[^@',]{1,2000})@({domain}[^@.,']{1,2000}\.lan)|({user_email}[^@',]{1,2000}@[^.]{1,2000}\.[^']{1,2000})|({=user}[^']{1,2000}))' from '(({src_ip}[A-Fa-f\d:.]{1,2000})|({src_host}[\w\-.]{1,2000}))', ({failure_reason}[^.,]{1,2000})\.""",
    """Reason:\s{0,100}({failure_reason}[^\.]{1,2000})\.\s""",
    """From:\s{0,100}(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^"]{1,2000}?))\.?"""",
    """auth profile '({service}[^\']{1,2000})'""",
    """,SYSTEM,("[^"]{1,2000}",|[^,]{0,2000},){18}({dest_host}[\w\-.]{1,2000})"""
  ]
}
```