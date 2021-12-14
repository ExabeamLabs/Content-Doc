#### Parser Content
```Java
{
Name = azure-event-hub-remote-logon
  DataType = "remote-logon"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"RemoteDesktopConnection""""]
  Fields = ${MSParserTemplates.azure-event-hub-network-events.Fields} [
    """"LocalIP":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"LocalPort":({src_port}\d{1,100})""",
    """"Protocol\\"{1,20}:\\"{1,20}({protocol}[^\\"]{1,2000})""",
  ]

azure-event-hub-network-events = {
    Vendor = Microsoft
    Product = Azure
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,100}Z)""",
      """\d{1,100}-\d{1,100}-\d\dT\d{1,100}:\s\d{1,100}:\d{1,100}\.\d{1,100}\+\d{1,100}\s({host}[^\s]{1,2000})""",
      """subject=({event_name}[^|\s]{1,2000})""",
      """category":"({category}[^"]{1,2000})""",
      """ActionType":"({outcome}[^"]{1,2000})""",
      """DeviceName":"({dest_host}[^"]{1,2000})""",
      """sip=({src_ip}[A-Fa-f:\d.]{1,2000})""",
      """dip=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
      """sport=({src_port}\d{1,100})""",
      """dport=({dest_port}\d{1,100})""",
      """protname=({protocol}[^|]{1,2000})""",
      """"RemoteUrl"{1,20}:"{1,20}({url}[^",]{1,2000})""",
      """domainorigin=({domain}[^|]{1,2000})""",
      """"InitiatingProcessId":({pid}\d{1,100})""",
      """"InitiatingProcessAccountName":"(system|SYSTEM|NETWORK SERVICE|local service|({user}[^"]{1,2000}))""",
      """"InitiatingProcessAccountSid"{1,20}:"{1,20}({user_sid}[^"]{1,2000})""",
    ] 
  }

 azure-ad-activity = {
   Vendor = Microsoft
   Product = Azure Active Directory
   Lms = QRadar
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
   Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z)""",
      """initiatedBy":.+?userPrincipalName":"({user_email}[^",]{1,2000})""",
      """initiatedBy":.+?id":"({user_uid}[^",]{1,2000})""",
      """callerIpAddress":"({src_ip}[^",]{1,2000})""",
      """operationName":"({activity}[^",]{1,2000})""",
      """result":"(notEnabled|notApplied|({outcome}[^",]{1,2000}))""",
      """category":"({category}[^",]{1,2000})"{0,20},correlationId"""",
      """"app":\{.*?displayName":"({app}[^",]{1,2000})""",
      """loggedByService":"({app}[^",]{1,2000})"""
   
}
```