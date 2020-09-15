#### Parser Content
```Java
{
Name = xml-sysmon-file-create
  DataType = "file-operations"
  IsHVF = true
  Conditions = [ """<Provider Name='Microsoft-Windows-Sysmon'""", """<EventID>11</EventID>""" ]
  DupFields = [ "host->dest_host" ]
}
```