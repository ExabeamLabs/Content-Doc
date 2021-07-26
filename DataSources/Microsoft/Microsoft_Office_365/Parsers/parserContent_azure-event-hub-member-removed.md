#### Parser Content
```Java
{
Name = azure-event-hub-member-removed
  DataType = "member-removed"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"UserAccountRemovedFromLocalGroup""""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
    """"AccountName"{1,20}:"{1,20}({group_name}[^"]{1,2000})""",
    """"AccountDomain"{1,20}:"{1,20}({group_domain}[^"]{1,2000})""",
    """"AccountSid"{1,20}:"{1,20}({user_sid}[^"]{1,2000})""",
    """"MemberSid\\"{1,20}:\\"{1,20}({account_id}[^"]{1,2000})""",
  ]
}
azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```