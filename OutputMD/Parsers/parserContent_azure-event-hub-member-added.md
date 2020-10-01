#### Parser Content
```Java
{
Name = azure-event-hub-member-added
  DataType = "member-added"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"UserAccountAddedToLocalGroup""""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
    """"AccountName"+:"+({group_name}[^"]+)""",
    """"AccountDomain"+:"+({group_domain}[^"]+)""",
    """"AccountSid"+:"+({user_sid}[^"]+)""",
    """"MemberSid\\"+:\\"+({account_id}[^"]+)""", 
  ]
}
```