#### Parser Content
```Java
{
Name = logrhythm-o365-file-write-7
  DataType = "file-write"
  Conditions = [ """SESSID=""", """RESULTCODE=""", """WORKLOAD=""", """COMMAND=FileCopied""", """ITEMTYPE=File""", """OBJECT=""" ]

logrhythm-o365-file-operation = {
    Vendor = Microsoft
    Product = Microsoft Office 365
    Lms = Syslog
    DataType = "file-operations"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """\sTS=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """USER=(Unknown|({user_email}[^@\s]{1,2000}@[^\s\.]{1,2000}?\.[^\s]{1,2000}?)|({user}[^\s@]{1,2000})(@({domain}[^\s]{1,2000}))?)\s{1,100}\w+=""",
      """DOMAIN=(|({domain}[^\s]{1,2000}?))\s{1,100}\w+=""",
      """USER=({domain}[^\\\s]{1,2000})\\({user}[^\s]{1,2000})""",
      """WORKLOAD=({app}[^=]{1,2000}?)\s{1,100}\w+=""",
      """COMMAND=({event_name}[^=]{1,20000}?)\s{1,100}\w+=""",
      """OBJECT=({object}[^=]{1,2000}?)\s{1,100}\w+=""",
      """\sFILENAME=({file_name}[^=]{1,2000}?(\.({file_ext}[^\s\=\.]{1,2000}))?)\s{1,100}\w+=""",
      """SIP=({src_ip}[a-fA-F\d:.]{1,2000})""",
      """USERAGENT=\s{0,100}(|({user_agent}[^\n]{1,2000}?))\s{0,100}(\w+=|$)""",
      """ITEMTYPE=({file_type}[^=]{1,2000}?)\s{1,100}\w+="""
    ]
    DupFields = [ "event_name->activity", "object->file_path" 
}
```