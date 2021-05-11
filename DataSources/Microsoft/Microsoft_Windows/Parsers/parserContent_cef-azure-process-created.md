#### Parser Content
```Java
{
Name = cef-azure-process-created
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"ActionType":"ProcessCreated"""" ]
  Fields = [
    """"Timestamp":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """DeviceName":\s{0,100}"({dest_host}({host}[^"\.]+)?[^"]+)""",
    """"AccountName":"(-|system|({user}[^"\s]+))"""",
    """"AccountDomain":"({domain}[^"\s]+)"""",
    """"AccountSid":"({user_sid}[^"]+)"""",
    """"ActionType":"({outcome}[^"]+)"""",
    """"FileName":"({process_name}[^"]+)"""",
    """"MD5":"({md5}[^"]+)"""",
    """"ProcessId":({pid}\d{1,100})""",
    """"ProcessCommandLine"{1,20}:"{1,20}\s{0,100}({command_line}.+?)\s{0,100}","FolderPath":""",
    """"InitiatingProcessCommandLine"{1,20}:"{1,20}\s{0,100}({command_line}.+?)\s{0,100}","InitiatingProcessParentCreationTime":""", 
    """"FolderPath":"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+?))\s{0,100}"""",
    """"LogonId":({logon_id}[^",]+)""",
    """"DeviceId":"({device_id}[^"]+)"""",
  ]
}
```