#### Parser Content
```Java
{
Name = paloalto-firewall-drop-1
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [""" TRAFFIC drop """]
  Fields = [
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[A-Fa-f:\d.]+)\s+\d+\s+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+)\s+\S+\s+({log_type}TRAFFIC)\s+({subtype}\S+)\s+\S+\s+\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(0.0.0.0|({src_ip}(?!::)[a-fA-F\d.:]+))\s+(0.0.0.0|({dest_ip}(?!::)[a-fA-F\d.:]+))\s+(0.0.0.0|({src_translated_ip}(?!::)[a-fA-F\d.:]+))\s+(0.0.0.0|({dest_translated_ip}(?!::)[a-fA-F\d.:]+))\s+({rule}[^\s]*?)\s+.*?\s+({src_network_zone}\S+)\s+\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+\S+\s+\d+\s+(0|({src_port}\d+))\s+(0|({dest_port}\d+))\s+(0|({src_translated_port}\d+))\s+(0|({dest_translated_port}\d+))\s+\S+\s+({protocol}\S+)\s+({action}\S+)\s+({bytes}\d+)\s+({bytes_out}\d+)\s+({bytes_in}\d+)\s+\d+\s+\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+\d+\s+({category}\S+)\s+""",
  ]
}
```