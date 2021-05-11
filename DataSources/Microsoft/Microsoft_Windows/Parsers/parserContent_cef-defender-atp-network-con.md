#### Parser Content
```Java
{
Name = cef-defender-atp-network-con
  DataType = "network-connection"
  Conditions = ["""CEF""", """SkyFormation Cloud Apps Security""", """requestClientApplication=""", """AdvancedHunting-DeviceNetworkEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [
     """RemoteUrl":\s{0,100}"(|(\w+:\/*)?({web_domain}([^"]+\.)?({top_domain}[^"]+\.[^"]+)?))"""",
     """DeviceName":\s{0,100}"({dest_host}({host}[^"\.]+)?[^"]+)""",
     """"InitiatingProcessFolderPath":\s{0,100}"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+?))""""
     """({category}AdvancedHunting-DeviceNetworkEvents)"""
  ]
}
```