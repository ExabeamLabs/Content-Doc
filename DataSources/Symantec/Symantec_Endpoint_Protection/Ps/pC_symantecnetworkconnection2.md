#### Parser Content
```Java
{
Name = symantec-network-connection-2
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """SymantecServer""", """Remote Host Name: """, """Local Host IP: """, """Action: """ ]
  Fields = [
  """SymantecServer:\s({host}[\w\-.]{1,2000})"""
  """Local Host IP:\s{0,100}({dest_ip}[a-fA-F\d.:]{1,2000}),Local Port:\s({dest_port}\d{1,10}).{0,2000}?,Inbound,"""
  """Local Host IP:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000}),Local Port:\s({src_port}\d{1,10}).{0,2000}?,Outbound,"""
  """Remote Host IP:\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000}),Remote Host Name:\s({src_host}[\w\-.]{1,2000}),.{0,2000}?,Inbound,"""
  """Remote Host IP:\s{0,100}({dest_ip}[A-Fa-f:\d.]{1,2000}),Remote Host Name:\s({dest_host}[\w\-.]{1,2000}),.{0,2000}?,Outbound,"""
  """Action:\s({action}[^"$]{1,2000}?)\s{0,100}$"""
  """({direction}Inbound|Outbound)"""
  """Application:\s{0,100}({process}({directory}[^,]{0,2000}?[\\\/]{1,2000})({process_name}[^,\\\/]{1,2000})),"""
  ]


}
```