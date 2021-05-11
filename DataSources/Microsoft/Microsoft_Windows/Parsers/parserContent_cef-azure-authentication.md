#### Parser Content
```Java
{
Name = cef-azure-authentication
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"ActionType":"Logon""", """"RemoteDeviceName":""" ]
  Fields = [
    """"Timestamp":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"DeviceName":"({host}[\w\-.]+)"""",
    """"AccountName":"(-|system|({user}[^"\s]+))"""",
    """"AccountDomain":"({domain}[^"\s]+)"""",
    """"AccountSid":"({user_sid}[^"]+)"""",
    """"RemoteIP":"({src_ip}[A-Fa-f:\d.]+)"""",
    """"RemotePort":({src_port}\d{1,100})""",
    """"Upn\\?":\\?"({user_email}[^"@\\\s]+@[^"@\\\s]+?)\\?"""",
    """"ActionType":"({outcome}[^"]+)"""",
    """"InitiatingProcessFileName":"({process_name}[^"]+)"""",
    """"InitiatingProcessMD5":"({md5}[^"]+)"""",
    """"InitiatingProcessId":({pid}[^",]+)""",
    """"InitiatingProcessCommandLine":"\s{0,100}({command_line}[^"]+)"""",
    """"LogonId":(null|({logon_id}[^",]+))""",
    """"DeviceId":"({device_id}[^"]+)"""",
    """"RemoteDeviceName":"(|({src_host}[\w\-.]+))"""",
  ]
}
```