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
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[A-Fa-f:\d.]{1,2000})\s{1,100}\d{1,100}\s{1,100}({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})\s{1,100}\S+\s{1,100}({log_type}TRAFFIC)\s{1,100}({subtype}\S+)\s{1,100}\S+\s{1,100}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(0.0.0.0|({src_ip}(?!::)[a-fA-F\d.:]{1,2000}))\s{1,100}(0.0.0.0|({dest_ip}(?!::)[a-fA-F\d.:]{1,2000}))\s{1,100}(0.0.0.0|({src_translated_ip}(?!::)[a-fA-F\d.:]{1,2000}))\s{1,100}(0.0.0.0|({dest_translated_ip}(?!::)[a-fA-F\d.:]{1,2000}))\s{1,100}({rule}[^\s]{0,2000}?)\s{1,100}.*?\s{1,100}({src_network_zone}\S+)\s{1,100}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\S+\s{1,100}\d{1,100}\s{1,100}(0|({src_port}\d{1,100}))\s{1,100}(0|({dest_port}\d{1,100}))\s{1,100}(0|({src_translated_port}\d{1,100}))\s{1,100}(0|({dest_translated_port}\d{1,100}))\s{1,100}\S+\s{1,100}({protocol}\S+)\s{1,100}({action}\S+)\s{1,100}({bytes}\d{1,100})\s{1,100}({bytes_out}\d{1,100})\s{1,100}({bytes_in}\d{1,100})\s{1,100}\d{1,100}\s{1,100}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\d{1,100}\s{1,100}({category}\S+)\s{1,100}""",
  ]
}
```