#### Parser Content
```Java
{
Name = cef-defender-atp-network-con
  DataType = "network-connection"
  Conditions = ["""CEF""", """SkyFormation Cloud Apps Security""", """requestClientApplication=""", """AdvancedHunting-DeviceNetworkEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [
     """RemoteUrl":\s*"(|(\w+:\/*)?({web_domain}([^"]+\.)?({top_domain}[^"]+\.[^"]+)?))"""",
     """DeviceName":\s*"({dest_host}({host}[^"\.]+)?[^"]+)""",
     """"InitiatingProcessFolderPath":\s*"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+?))""""
     """({category}AdvancedHunting-DeviceNetworkEvents)"""
  ]
}
```