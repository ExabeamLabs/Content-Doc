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
      """@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d+Z)""",
      """\d+-\d+-\d\dT\d+:\s\d+:\d+\.\d+\+\d+\s({host}[^\s]+)""",
      """subject=({event_name}[^|\s]+)""",
      """category":"({category}[^"]+)""",
      """ActionType":"({outcome}[^"]+)""",
      """DeviceName":"({dest_host}[^"]+)""",
      """sip=({src_ip}[A-Fa-f:\d.]+)""",
      """dip=({dest_ip}[A-Fa-f:\d.]+)""",
      """sport=({src_port}\d+)""",
      """dport=({dest_port}\d+)""",
      """protname=({protocol}[^|]+)""",
      """"RemoteUrl"+:"+({url}[^",]+)""",
      """domainorigin=({domain}[^|]+)""",
      """"InitiatingProcessId":({pid}\d+)""",
      """"InitiatingProcessAccountName":"(system|SYSTEM|NETWORK SERVICE|local service|({user}[^"]+))""",
      """"InitiatingProcessAccountSid"+:"+({user_sid}[^"]+)""",
    ] 
  }

 azure-ad-activity = {
   Vendor = Microsoft
   Product = Microsoft Azure Active Directory
   Lms = QRadar
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
   Fields = [
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z)""",
      """initiatedBy":.+?userPrincipalName":"({user_email}[^",]+)""",
      """initiatedBy":.+?id":"({user_uid}[^",]+)""",
      """callerIpAddress":"({src_ip}[^",]+)""",
      """operationName":"({activity}[^",]+)""",
      """result":"(notEnabled|notApplied|({outcome}[^",]+))""",
      """category":"({category}[^",]+)"*,correlationId"""",
      """"app":\{.*?displayName":"({app}[^",]+)""",
      """loggedByService":"({app}[^",]+)"""
   ]

```