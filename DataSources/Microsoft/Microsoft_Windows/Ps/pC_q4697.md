#### Parser Content
```Java
{
Name = q-4697
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-service-created"
  TimeFormat = "epoch_sec"
  Conditions = [ """EventID=4697""", """Service File Name:"""]
  Fields = [ 
    """\WComputer=({host}[\w\.\-]{1,2000})""",
    """\WEventID=({event_code}\d{1,100})""",
    """\WTimeGenerated=({time}\d{1,100})""",
    """\WSecurity ID:\s{0,100}(|({user_sid}.+?))\s{1,100}Account Name:""",
    """\WAccount Name:\s{0,100}({user}[^\s]{1,2000})""",
    """\WAccount Domain:\s{0,100}({domain}[^\s]{1,2000})""",
    """\WLogon ID:\s{0,100}({logon_id}[^\s]{1,2000})""",
    """\WService Name:\s{0,100}(|({service_name}.+?))\s{1,100}Service File Name:""",
    """\WService File Name:\s{0,100}(|({process}({directory}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({process_name}.+?)))\s{1,100}Service Type:""",
    """\WService Type:\s{0,100}(|({service_type}.+?))\s{1,100}Service Start Type:""",
    """\WService Account:\s{0,100}(({account_domain}[^\\]{1,2000})\\)?({account_name}.+?)\s{0,100}$"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```