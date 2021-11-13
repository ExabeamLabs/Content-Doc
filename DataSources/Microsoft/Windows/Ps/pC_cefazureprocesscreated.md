#### Parser Content
```Java
{
Name = cef-azure-process-created
  Vendor = Microsoft
  Product = Windows
  Lms = ArcSight
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"ActionType":"ProcessCreated"""" ]
  Fields = [
    """"Timestamp":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """DeviceName":\s{0,100}"({dest_host}({host}[^"\.]{1,2000})?[^"]{1,2000})""",
    """"AccountName":"(-|system|({user}[^"\s]{1,2000}))"""",
    """"AccountDomain":"({domain}[^"\s]{1,2000})"""",
    """"AccountSid":"({user_sid}[^"]{1,2000})"""",
    """"ActionType":"({outcome}[^"]{1,2000})"""",
    """"FileName":"({process_name}[^"]{1,2000})"""",
    """"MD5":"({md5}[^"]{1,2000})"""",
    """"ProcessId":({pid}\d{1,100})""",
    """"ProcessCommandLine"{1,20}:"{1,20}\s{0,100}({command_line}.+?)\s{0,100}","FolderPath":""",
    """"InitiatingProcessCommandLine"{1,20}:"{1,20}\s{0,100}({command_line}.+?)\s{0,100}","InitiatingProcessParentCreationTime":""", 
    """"FolderPath":"({process}({directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000}?))\s{0,100}"""",
    """"LogonId":({logon_id}[^",]{1,2000})""",
    """"DeviceId":"({device_id}[^"]{1,2000})"""",
  ]


}
```