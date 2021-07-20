#### Parser Content
```Java
{
Name = s-675
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-675"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = ["EventCode=675", "Pre-authentication failed:"]
    Fields = [
      """({event_name}Pre-authentication failed)""",
      """exabeam_raw=({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
      """ComputerName=({host}[\w.\-]{1,2000})""",
      """EventCode=({event_code}\d{1,100})""",
      """User Name:\s{1,100}({user}.+?)\s{1,100}User ID:\s{1,100}({user_sid}.+?)\s{1,100}Service Name""",
      """Service Name:\s{1,100}\w+\/(?=\w)({domain}.+?)\s{1,100}Pre-Authentication""",
      """Failure Code:\s{1,100}({result_code}[\w]{1,2000})""",
      """Client Address:\s{1,100}(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})"""
    ]
  }
```