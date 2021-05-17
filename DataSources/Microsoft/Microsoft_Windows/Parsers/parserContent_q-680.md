#### Parser Content
```Java
{
Name = q-680
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-680"
  TimeFormat = "epoch_sec"
  Conditions = [ "EventIDCode=680" ]
  Fields = [
    """({event_name}Logon attempt)""",
             """EventID=({event_code}\d{1,100})""",
             """TimeGenerated=({time}\d{1,100})""",
             """Computer=({host}[^\s]{1,2000})""",
	     """Domain=({domain}[\w\-]{1,2000})\s{1,100}EventID=""",
             """Logon account:\s{0,100}({user}[^@]{1,2000}?)(@[^\s]{0,2000})?\s{1,100}Source Workstation:\s{0,100}(\\+)?({dest_host}[^\s.]{1,2000}).+?Error Code:\s{0,100}({result_code}[^\s]{1,2000})""",
             """Computer=[^\s.]{1,2000}(\.({domain}[^\s.]{1,2000})[^\s]{0,2000})?"""]
}
```