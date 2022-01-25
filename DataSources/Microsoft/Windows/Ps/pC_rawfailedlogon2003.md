#### Parser Content
```Java
{
Name = raw-failed-logon-2003
    Vendor = Microsoft
    Product = Windows
    Lms = Splunk
    DataType = "windows-failed-logon"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["Logon Failure", "Reason:", "Caller User Name:"]
    Fields = [
      """({event_name}Logon Failure)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """(?i)(((audit|failure)( |_)(audit|failure))|information)\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]{1,2000}>)\s{0,100}({host}[^=]{1,2000}?)\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]{1,2000}>)\s{0,100}""",
      """\d\d:\d\d:\d\d \d\d\d\d\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]{1,2000}>)\s{0,100}({event_code}\d{1,100})\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]{1,2000}>)\s{0,100}Security""",
      """({host}[^\s\/]{1,2000})\/Security \(({event_code}\d{1,100})\)""",
      """<Computer>({host}[^<]{1,2000})</Computer>""",
      """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?({host}.+?)("|\s)""",
      """Event(ID)?Code=({event_code}\d{1,100})""",
      """Caller User Name:\s{0,100}(-|({user}.+?))\s{0,100}Caller Domain:""",
      """Caller Domain:\s{0,100}(-|({domain}.+?))\s{0,100}Caller Logon ID:""",
      """User Name:\s{0,100}(?=\w)(-|({user}.+?))\s{0,100}Domain.+?Logon Type""",
      """Domain:\s{0,100}(?=\w)({domain}.+?)\s{0,100}Logon Type""",
      """Logon Type:\s{0,100}({logon_type}\d{1,100})\s{1,100}Logon Process:\s{1,100}({auth_process}.*?)\s{1,100}Authentication Package:\s{1,100}({auth_package}.*?)\s{1,100}Workstation Name:""",
      """Workstation Name:\s{0,100}(-|({src_host_windows}[^\s]{1,2000}))\s{0,100}Caller User Name:""",
      """Workstation Name:\s{0,100}({src_host}[^\s]{1,2000})\s{0,100}Caller User Name:.*?Source Network Address:\s{0,100}-\s{1,100}""",
      """Caller User Name:\s{0,100}(?:-|({caller_user}.+?))\s{0,100}Caller Domain:""",
      """Caller Domain:\s{0,100}({caller_domain}.+?)\s{0,100}Caller Logon ID:\s{0,100}\([^,]{1,2000

}
```