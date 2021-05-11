#### Parser Content
```Java
{
Name = q-672
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-672"
  TimeFormat = "epoch_sec"
  Conditions = [ "EventIDCode=672" ]
  Fields = [
             """EventID=({event_code}\d{1,100}).+?Supplied Realm Name:\s{1,100}({domain}[^\s]+)""",
             """TimeGenerated=({time}\d{1,100})""",
             """Computer=({host}[^\s]+)""",
	     """User Name:\s{1,100}({user}.+?)\s{1,100}Supplied Realm Name:.+?Result Code:\s{1,100}({result_code}.+?)\s.+Client Address:\s{1,100}({dest_ip}[a-fA-F:\d.]+)""" ]
}
```