#### Parser Content
```Java
{
Name = sysmon-windows-dns-query
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """QueryName:""", """QueryResults:""", """ProcessGuid:""", """Image:""" ]
  Fields = [
    """UtcTime:\s{0,100}({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d\.\d\d\d)\s""",
    """exabeam_host=({host}[\w.\-]+)""",
    """QueryName:\s{0,100}({query}[^\s]+)""",
    """ProcessGuid:\s{0,100}\{({process_guid}[A-F0-9a-f-]+)\}""",
    """ProcessId:\s{0,100}({pid}\d{1,100})""",
    """QueryResults:\s({response}.+?)\sImage:""",
    """Image:\s{0,100}(?:<unknown process>|({process}({directory}[^"]*[\\\/]+)?({process_name}[^"\\\/]+)))\s""",
	]
}
```