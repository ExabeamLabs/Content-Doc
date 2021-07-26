#### Parser Content
```Java
{
Name = cef-netapp-4663
  DataType = "windows-4663"
  Conditions = [ """CEF:""", """Skyformation|SkyFormation Cloud Apps Security|""", """EventID': 4663"""  ]
  DupFields = [ "event_name->accesses","host->dest_host" ]
}
```