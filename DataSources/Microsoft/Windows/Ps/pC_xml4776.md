#### Parser Content
```Java
{
Name = xml-4776
    Vendor = Microsoft
    Product = Windows
    Lms = ElasticSearch
    DataType = "windows-4776"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""<EventID>4776</EventID>""", """'Status'>"""]
    Fields = [
      """SystemTime(\\)?=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
      """<Data Name(\\)?='Workstation'>(\\+)?(({dest_ip}(((\d{1,3}\.){1,3}\d{1,3})|([A-Fa-f0-9]{0,2000}:[A-Fa-f0-9:.]{1,2000})))|(?:(?!NULL)({dest_host}[^\s.]{1,2000})(\.[^\s]{1,2000})?))</Data>""",
      """<Computer>({host}[^<]{1,2000})</Computer>""",
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
      """<EventID>({event_code}\d{1,100})</EventID>""",
      """<Computer>(?!(?:[A-Fa-f:\d.]{1,2000}))[^<.]{1,2000}(\.({domain}[^<.]{1,2000})[^<]{0,2000})?</Computer>""",
      """<Data Name(\\)?='TargetUserName'>({user}[^@<]{1,2000}?)(?:@({domain}[^<.]{1,2000})[^<]{0,2000})?</Data>""",
      """<Data Name(\\)?='Status'>({result_code}[^<]{1,2000})</Data>""",
      """<Keywords><Keyword>({outcome}[^<]{1,2000})<"""
    ]
  

}
```