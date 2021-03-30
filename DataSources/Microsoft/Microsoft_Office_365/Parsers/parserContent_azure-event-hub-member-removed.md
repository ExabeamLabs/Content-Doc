#### Parser Content
```Java
{
Name = azure-event-hub-member-removed
  DataType = "member-removed"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"UserAccountRemovedFromLocalGroup""""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
    """"AccountName"+:"+({group_name}[^"]+)""",
    """"AccountDomain"+:"+({group_domain}[^"]+)""",
    """"AccountSid"+:"+({user_sid}[^"]+)""",
    """"MemberSid\\"+:\\"+({account_id}[^"]+)""",
  ]
}
azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```