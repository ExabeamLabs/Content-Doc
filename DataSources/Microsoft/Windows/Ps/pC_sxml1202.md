#### Parser Content
```Java
{
Name = s-xml-1202
  DataType = "authentication-successful"
  Conditions = [ """>1202</EventID>""", """<TimeCreated SystemTime=""" ]

windows-xml-events = {
  Vendor = Microsoft
  Product = Windows
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """<TimeCreated SystemTime(\\)?='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """<Computer>({host}[^<>]{1,2000})<""",
    """<Message>({event_name}[^:<\.]{1,2000})""",
    """<Message>({event_name}[^<]{1,2000}?)\.(\s|<)""",
    """<Message>({additional_info}[^<]{1,2000}?)\s{0,100}<""",
    """<Security UserID(\\)?='({user_sid}[^']{1,2000})""",
    """<EventID[^<]{0,2000}?>({event_code}\d{1,100})""",
    """<Keyword>({outcome}[^<]{1,2000})<""",
    """(<|&lt;)IpAddress(&gt;|>)({src_ip}[A-Fa-f\d:.]{1,2000})""",
    """(<|&lt;)UserId(&gt;|>)(N\/A|({user_email}[^@&]{1,2000}@[^&\.]{1,2000}\.[^&]{1,2000})|(({domain}[^\\&]{1,2000})\\{1,20})?({user}[^\\&]{1,2000}))(<|&lt;)\/UserId(&gt;|>)"""
  
}
```