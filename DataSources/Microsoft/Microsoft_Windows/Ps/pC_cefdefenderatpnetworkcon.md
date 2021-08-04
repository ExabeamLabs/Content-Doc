#### Parser Content
```Java
{
Name = cef-defender-atp-network-con
  DataType = "network-connection"
  Conditions = ["""CEF""", """SkyFormation Cloud Apps Security""", """requestClientApplication=""", """AdvancedHunting-DeviceNetworkEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [
     """RemoteUrl":\s{0,100}"(|(\w+:\/*)?({web_domain}([^"]{1,2000}\.)?({top_domain}[^"]{1,2000}\.[^"]{1,2000})?))"""",
     """DeviceName":\s{0,100}"({dest_host}({host}[^"\.]{1,2000})?[^"]{1,2000})""",
     """"InitiatingProcessFolderPath":\s{0,100}"({process}({directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000}?))""""
     """({category}AdvancedHunting-DeviceNetworkEvents)"""
  ]
}
```