#### Parser Content
```Java
{
Name = s-windows-5157
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Exabeam
  DataType = "process-network-failed"
  TimeFormat =  "MM/dd/yyyy hh:mm:ss a"
  Conditions = [ """Code=5157""", "The Windows Filtering Platform has blocked a connection" ]
  Fields = [
    """TimeGenerated=({time}\d+)""",
    """({event_name}The Windows Filtering Platform has blocked a connection)""",
    """({time}\d\d\/\d\d\/\d{4} \d+:\d+:\d+ (am|AM|pm|PM))""",    
    """({event_code}5157)""",
    """\s*Computer(Name)?=({host}[^\s]+)\s*""",
    """\s*Process ID:\s*({pid}[^\s]+)\s*""",
    """\s*Source Address:\s*({src_ip}[a-fA-F:\d.]+)\s*""",
    """\s*Source Port:\s*({src_port}\d+)\s*""",
    """\s*Destination Address:\s*({dest_ip}[a-fA-F:\d.]+)\s*""", 
    """\s*Destination Port:\s*({dest_port}\d+)\s*""",
    """\s*Protocol:\s*({protocol}\d+)\s*""",
    """\s*Direction:\s*({direction}[^\s]+)\s*""",
    """\s*Layer Name:\s*({layer_name}[^\s]+)\s*""", 
    """\s*(TaskCategory|EventCategory)=({activity_type}.+?)\s*\w+=""",
    """\s*Application Name:\s*({process}(({directory}.+)[\\\/])?({process_name}.+?))\s*Network Information:"""    
  ]
  DupFields = [ "host->local_asset","directory->process_directory" ]
}
```