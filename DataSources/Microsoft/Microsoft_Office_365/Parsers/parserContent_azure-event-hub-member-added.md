#### Parser Content
```Java
{
Name = azure-event-hub-member-added
  DataType = "member-added"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"UserAccountAddedToLocalGroup""""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
    """"AccountName"{1,20}:"{1,20}({group_name}[^"]+)""",
    """"AccountDomain"{1,20}:"{1,20}({group_domain}[^"]+)""",
    """"AccountSid"{1,20}:"{1,20}({user_sid}[^"]+)""",
    """"MemberSid\\"{1,20}:\\"{1,20}({account_id}[^"]+)""", 
  ]
}
azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```