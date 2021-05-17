#### Parser Content
```Java
{
Name = q-5156
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "process-network"
  TimeFormat = "epoch_sec"
  Conditions = [ "EventIDCode=5156" ]
  Fields = [
    """Computer=\s{0,100}({host}[^\s]{0,2000})""",
    """EventID=({event_code}\d{1,100})""",
    """TimeGenerated=({time}\d{1,100})""",
    """Message=({event_name}.*?)\s{0,100}Application Information:""",
    """Process ID:\s{0,100}({pid}\d{1,100})""",
    """Application Name:\s{0,100}({process}({directory}.+)[\\\/]({process_name}.+?))\s{0,100}Network Information:""",
    """Computer=\s{0,100}({dest_host}[^\s]{0,2000}).*Direction:\s{0,100}({direction}Inbound).*Source Address:\s{0,100}({dest_ip}[^\s]{0,2000})\s{0,100}Source Port:\s{0,100}({dest_port}\d{0,100})\s{0,100}Destination Address:\s{0,100}({src_ip}[^\s]{0,2000})\s{0,100}Destination Port:\s{0,100}({src_port}\d{0,100})""",
    """Computer=\s{0,100}({src_host}[^\s]{0,2000}).*Direction:\s{0,100}({direction}Outbound).*Source Address:\s{0,100}({src_ip}[^\s]{0,2000})\s{0,100}Source Port:\s{0,100}({src_port}\d{0,100})\s{0,100}Destination Address:\s{0,100}({dest_ip}[^\s]{0,2000})\s{0,100}Destination Port:\s{0,100}({dest_port}\d{0,100})""",
    """Protocol:\s{0,100}({ms_protocol_num}\d{0,100})""",
    """Layer Name:\s{0,100}({layer_name}[^\s]{0,2000})"""
  ]
  DupFields = ["directory->process_directory"]
}
```