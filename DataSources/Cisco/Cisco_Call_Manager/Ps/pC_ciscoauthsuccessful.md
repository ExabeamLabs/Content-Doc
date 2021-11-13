#### Parser Content
```Java
{
Name = cisco-auth-successful
  Product = Cisco Call Manager
  DataType = "authentication-successful"
  Conditions = [ """EventType =UserLogging""", """=Login Authentication Successful]""" ]

cisco-events = {
  Vendor = Cisco
  Product = Cisco
  Lms = Direct
  TimeFormat = "MMM dd yyyy HH:mm:ss a"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\s({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm))""",
    """UserID\s{0,100}=({user}[^\s\]]{1,2000})""",
    """ClientAddress\s{0,100}=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """EventType\s{0,100}=({activity}[^\]]{1,2000})""",
    """ResourceAccessed\s{0,100}=({object}[^\]]{1,2000})""",
    """EventStatus\s{0,100}=({outcome}[^\]]{1,2000})""",
    """ComponentID\s{0,100}=({target}[^\]]{1,2000})""",
    """AuditDetails\s{0,100}=({additional_info}[^\]]{1,2000})""",
    """App ID\s{0,100}=({app}[^\]]{1,2000})""",
    """userPrincipalName"{1,20}:\s{0,100}"{1,20}({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}))""",
  
}
```