#### Parser Content
```Java
{
Name = xml-1149
    Lms = Splunk
    Vendor = Microsoft
    Product = Windows
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
    DataType = "remote-logon"
    Conditions = [ """<EventID>1149<""", """<Security UserID=""", """<Param1>""", """<Computer>""" ]
    Fields = [
      """<TimeCreated SystemTime='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,10}Z)'""",
      """<Computer>({host}[\w\-.]{1,2000})<""",
      """({event_code}1149)""",
      """<Param1>({user}[^<@]{1,2000})(@({domain}[^<]{1,2000}))?<""",
      """<Param2>({domain}[^<]{1,2000})<""",
      """<Param3>({src_ip}[A-Fa-f\d:.]{1,2000})<""",
      """<Security UserID='({user_sid}[^']{1,2000})'"""
    ]
    DupFields = [ "host->dest_host" ]


}
```