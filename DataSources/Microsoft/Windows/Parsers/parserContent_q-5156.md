#### Parser Content
```Java
{
Name = q-5156
  Vendor = Microsoft
  Product = Windows
  Lms = QRadar
  DataType = "process-network"
  TimeFormat = "epoch_sec"
  Conditions = [ "EventIDCode=5156" ]
  Fields = [
    """Computer=\s*({host}[^\s]*)""",
    """EventID=({event_code}\d+)""",
    """TimeGenerated=({time}\d+)""",
    """Message=({event_name}.*?)\s*Application Information:""",
    """Process ID:\s*({pid}\d+)""",
    """Application Name:\s*({process}({directory}.+)[\\\/]({process_name}.+?))\s*Network Information:""",
    """Computer=\s*({dest_host}[^\s]*).*Direction:\s*({direction}Inbound).*Source Address:\s*({dest_ip}[^\s]*)\s*Source Port:\s*({dest_port}\d*)\s*Destination Address:\s*({src_ip}[^\s]*)\s*Destination Port:\s*({src_port}\d*)""",
    """Computer=\s*({src_host}[^\s]*).*Direction:\s*({direction}Outbound).*Source Address:\s*({src_ip}[^\s]*)\s*Source Port:\s*({src_port}\d*)\s*Destination Address:\s*({dest_ip}[^\s]*)\s*Destination Port:\s*({dest_port}\d*)""",
    """Protocol:\s*({ms_protocol_num}\d*)""",
    """Layer Name:\s*({layer_name}[^\s]*)"""]
}
```