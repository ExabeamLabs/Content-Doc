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
    """"Timestamp":"({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """"DeviceName":"({host}[\w\-.]+)"""",
    """"AccountName":"(-|system|({user}[^"\s]+))"""",
    """"AccountDomain":"({domain}[^"\s]+)"""",
    """"AccountSid":"({user_sid}[^"]+)"""",
    """"ActionType":"({outcome}[^"]+)"""",
    """"FileName":"({process_name}[^"]+)"""",
    """"MD5":"({md5}[^"]+)"""",
    """"ProcessId":({pid}\d+)""",
    """"ProcessCommandLine"+:"+\s*({command_line}.+?)\s*","FolderPath":""",
    """"InitiatingProcessCommandLine"+:"+\s*({command_line}.+?)\s*","InitiatingProcessParentCreationTime":""", 
    """"FolderPath":"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+?))\s*"""",
    """"LogonId":({logon_id}[^",]+)""",
    """"DeviceId":"({device_id}[^"]+)"""",
  ]
}
```