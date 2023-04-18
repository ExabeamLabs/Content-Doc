#### Parser Content
```Java
{
Name = cef-azure-authentication
  Vendor = Microsoft
  Product = Windows
  Lms = ArcSight
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"DeviceName":""", """"ActionType":"Logon""", """"RemoteDeviceName":""" ]
  Fields = [
    """"Timestamp":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"DeviceName":"({host}[\w\-.]{1,2000})"""",
    """"AccountName":"(-|system|({user}[^"\s]{1,2000}))"""",
    """"AccountDomain":"({domain}[^"\s]{1,2000})"""",
    """"AccountSid":"({user_sid}[^"]{1,2000})"""",
    """"RemoteIP":"({src_ip}[A-Fa-f:\d.]{1,2000})"""",
    """"RemotePort":({src_port}\d{1,100})""",
    """"Upn\\?":\\?"({user_email}[^"@\\\s]{1,2000}@[^"@\\\s]{1,2000}?)\\?"""",
    """"ActionType":"({outcome}[^"]{1,2000})"""",
    """"InitiatingProcessFileName":"({process_name}[^"]{1,2000})"""",
    """"InitiatingProcessMD5":"({md5}[^"]{1,2000})"""",
    """"InitiatingProcessId":({pid}[^",]{1,2000})""",
    """"InitiatingProcessCommandLine":"\s{0,100}({command_line}[^"]{1,2000})"""",
    """"LogonId":(null|({logon_id}[^",]{1,2000}))""",
    """"DeviceId":"({device_id}[^"]{1,2000})"""",
    """"RemoteDeviceName":"(|({src_host}[\w\-.]{1,2000}))"""",
  ]


}
```