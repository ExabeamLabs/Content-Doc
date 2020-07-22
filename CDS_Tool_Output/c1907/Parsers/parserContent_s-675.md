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
      """ComputerName=({host}[\w.\-]+)""",
      """EventCode=({event_code}\d+)""",
      """User Name:\s+({user}.+?)\s+User ID:\s+({user_sid}.+?)\s+Service Name""",
      """Service Name:\s+\w+\/(?=\w)({domain}.+?)\s+Pre-Authentication""",
      """Failure Code:\s+({result_code}[\w]+)""",
      """Client Address:\s+(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)"""
    ]
  }
```