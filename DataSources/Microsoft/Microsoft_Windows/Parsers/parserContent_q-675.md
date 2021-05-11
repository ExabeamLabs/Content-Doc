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
      """TimeGenerated=({time}\d{1,100})""",
      """Computer=({host}[^\s]+)""",
      """EventID=({event_code}\d{1,100})""",
      """User Name:\s{1,100}({user}.+?)\s{1,100}User ID:\s{1,100}({user_sid}.+?)\s{1,100}Service Name""",
      """Service Name:\s{1,100}\w+\/(?=\w)({domain}.+?)\s{1,100}Pre-Authentication""",
      """Failure Code:\s{1,100}({result_code}[\w]+)""",
      """Client Address:\s{1,100}(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)"""
    ]
  }
```