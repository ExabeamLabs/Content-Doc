#### Parser Content
```Java
{
Name = cef-netapp-4624
  DataType = "windows-4624"
  Conditions = [ """CEF:""", """Skyformation|SkyFormation Cloud Apps Security|""", """EventID': 4624"""  ]
  DupFields = [ "target_user->user","target_domain->domain","host->dest_host" ]
}
}
```