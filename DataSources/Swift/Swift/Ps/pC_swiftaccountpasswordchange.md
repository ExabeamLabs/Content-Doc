#### Parser Content
```Java
{
Name = swift-account-password-change
    DataType = "password-change"
    Conditions = [ """|SWIFT|Alliance Web Platform|""", """|password.changed|"""]

Swift-Alliance-Web-Platform = {
    Vendor = Swift
    Product = Swift
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
    Fields = [
      """({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}[+-]\d\d:\d\d)\s\S+\s\S+\sCEF:""",
      """CEF:([^|]{1,2000}\|){5}({event_name}[^|]{1,2000})\|({alert_severity}[^|]{1,2000})\|""",
      """\Wdvc=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
      """\Wdvchost=({host}[\w\-.]{1,2000})""",
      """suid=([^:\s]{1,2000}:)?({user}[^\s]{1,2000})""",
      """({app}Alliance Web Platform)""",
      """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
      """msg=({additional_info}[^=]{1,2000}?)\.?(\s{0,100}\w+=|\s{0,100}$)"""
    
}
```