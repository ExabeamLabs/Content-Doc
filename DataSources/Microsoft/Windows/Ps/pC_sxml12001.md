#### Parser Content
```Java
{
Name = s-xml-1200-1
  DataType = "authentication-successful"
  Conditions = [ """(EventID 1200)""", """MSWinEventLog""", """AD FS Auditing""" ]

windows-xml-events-1 = {
  Vendor = Microsoft
  Product = Windows
  Lms = Splunk
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Fields = [
    """MSWinEventLog\s.{1,2000}?\s({time}\w{3}\s\d{2}\s(\d{2}:){2}\d{2}\s\d{4})""",
    """({host}[\w.-]{1,2000})\sMSWinEventLog\s""",
    """\(EventID\s({event_code}\d{1,200})\)""",
    """(<|&lt;)IpAddress(&gt;|>)({src_ip}[A-Fa-f\d:.]{1,2000})""",
    """(<|&lt;)UserId(&gt;|>)(N\/A|({user_email}[^@&]{1,2000}@[^&\.]{1,2000}\.[^&]{1,2000})|(({domain}[^\\&]{1,2000})\\{1,20})?({user}[^\\&]{1,2000}))(<|&lt;)\/UserId(&gt;|>)"""
  
}
```