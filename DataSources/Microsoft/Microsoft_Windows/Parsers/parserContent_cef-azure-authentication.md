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
    """"Timestamp":"({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """"DeviceName":"({host}[\w\-.]+)"""",
    """"AccountName":"(-|system|({user}[^"\s]+))"""",
    """"AccountDomain":"({domain}[^"\s]+)"""",
    """"AccountSid":"({user_sid}[^"]+)"""",
    """"RemoteIP":"({src_ip}[A-Fa-f:\d.]+)"""",
    """"RemotePort":({src_port}\d+)""",
    """"Upn\\?":\\?"({user_email}[^"@\\\s]+@[^"@\\\s]+?)\\?"""",
    """"ActionType":"({outcome}[^"]+)"""",
    """"InitiatingProcessFileName":"({process_name}[^"]+)"""",
    """"InitiatingProcessMD5":"({md5}[^"]+)"""",
    """"InitiatingProcessId":({pid}[^",]+)""",
    """"InitiatingProcessCommandLine":"\s*({command_line}[^"]+)"""",
    """"LogonId":({logon_id}[^",]+)""",
    """"DeviceId":"({device_id}[^"]+)"""",
    """"RemoteDeviceName":"(|({src_host}[\w\-.]+))"""",
  ]
}
```