#### Parser Content
```Java
{
Name = q-5158
  Vendor = Microsoft
  Product = Windows
  Lms = QRadar
  DataType = "process-network-bind"
  TimeFormat = "epoch_sec"
  Conditions = [ "EventIDCode=5158" ]
  Fields = [
    """Computer=\s*({host}[^\s]*)""",
    """EventID=({event_code}\d+)""",
    """TimeGenerated=({time}\d+)""",
    """Message=({event_name}.*?)\s*Application Information:""",
    """Process ID:\s*({pid}\d+)""",
    """Application Name:\s*({process}({directory}.+)[\\\/]({process_name}.+?))\s*Network Information:""",
    """Source Address:\s*({dest_ip}[^\s]*)\s*Source Port:\s*({dest_port}\d*)""",
    """Protocol:\s*({ms_protocol_num}\d*)""",
    """Layer Name:\s*({layer_name}.*?)\s*Layer Run-Time ID"""]
  DupFields = [ "host->dest_host" , "directory->process_directory"]
}
```