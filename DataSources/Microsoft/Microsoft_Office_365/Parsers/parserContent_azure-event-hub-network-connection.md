#### Parser Content
```Java
{
Name = azure-event-hub-network-connection
  DataType = "network-connection"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceNetworkEvents|""", """vmid=""", """@timestamp""", """@metadata"""]
  Fields = ${MSParserTemplates.azure-event-hub-network-events.Fields} [
  ]
}
azure-event-hub-network-events = {
    Vendor = Microsoft
    Product = Microsoft Azure
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,100}Z)""",
      """\d{1,100}-\d{1,100}-\d\dT\d{1,100}:\s\d{1,100}:\d{1,100}\.\d{1,100}\+\d{1,100}\s({host}[^\s]+)""",
      """subject=({event_name}[^|\s]+)""",
      """category":"({category}[^"]+)""",
      """ActionType":"({outcome}[^"]+)""",
      """DeviceName":"({dest_host}[^"]+)""",
      """sip=({src_ip}[A-Fa-f:\d.]+)""",
      """dip=({dest_ip}[A-Fa-f:\d.]+)""",
      """sport=({src_port}\d{1,100})""",
      """dport=({dest_port}\d{1,100})""",
      """protname=({protocol}[^|]+)""",
      """"RemoteUrl"{1,20}:"{1,20}({url}[^",]+)""",
      """domainorigin=({domain}[^|]+)""",
      """"InitiatingProcessId":({pid}\d{1,100})""",
      """"InitiatingProcessAccountName":"(system|SYSTEM|NETWORK SERVICE|local service|({user}[^"]+))""",
      """"InitiatingProcessAccountSid"{1,20}:"{1,20}({user_sid}[^"]+)""",
    ] 
  }

 azure-ad-activity = {
   Vendor = Microsoft
   Product = Microsoft Azure Active Directory
   Lms = QRadar
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
   Fields = [
      """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
      """time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z)""",
      """initiatedBy":.+?userPrincipalName":"({user_email}[^",]+)""",
      """initiatedBy":.+?id":"({user_uid}[^",]+)""",
      """callerIpAddress":"({src_ip}[^",]+)""",
      """operationName":"({activity}[^",]+)""",
      """result":"(notEnabled|notApplied|({outcome}[^",]+))""",
      """category":"({category}[^",]+)"{0,20},correlationId"""",
      """"app":\{.*?displayName":"({app}[^",]+)""",
      """loggedByService":"({app}[^",]+)"""
   ]

```