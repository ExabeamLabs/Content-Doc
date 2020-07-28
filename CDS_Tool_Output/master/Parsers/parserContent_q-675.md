#### Parser Content
```Java
{
Name = q-675
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = QRadar
    DataType = "windows-675"
    TimeFormat = "epoch_sec"
    Conditions = [ "EventIDCode=675" ]
    Fields = [
      """({event_name}Pre-authentication failed)""",
      """TimeGenerated=({time}\d+)""",
      """Computer=({host}[^\s]+)""",
      """EventID=({event_code}\d+)""",
      """User Name:\s+({user}.+?)\s+User ID:\s+({user_sid}.+?)\s+Service Name""",
      """Service Name:\s+\w+\/(?=\w)({domain}.+?)\s+Pre-Authentication""",
      """Failure Code:\s+({result_code}[\w]+)""",
      """Client Address:\s+(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)"""
    ]
  }
```