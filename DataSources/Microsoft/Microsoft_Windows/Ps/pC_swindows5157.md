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
    """TimeGenerated=({time}\d{1,100})""",
    """({event_name}The Windows Filtering Platform has blocked a connection)""",
    """({time}\d\d\/\d\d\/\d{4} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",    
    """({event_code}5157)""",
    """\s{0,100}Computer(Name)?=({host}[^\s]{1,2000})\s{0,100}""",
    """\s{0,100}Process ID:\s{0,100}({pid}[^\s]{1,2000})\s{0,100}""",
    """\s{0,100}Source Address:\s{0,100}({src_ip}[a-fA-F:\d.]{1,2000})\s{0,100}""",
    """\s{0,100}Source Port:\s{0,100}({src_port}\d{1,100})\s{0,100}""",
    """\s{0,100}Destination Address:\s{0,100}({dest_ip}[a-fA-F:\d.]{1,2000})\s{0,100}""", 
    """\s{0,100}Destination Port:\s{0,100}({dest_port}\d{1,100})\s{0,100}""",
    """\s{0,100}Protocol:\s{0,100}({protocol}\d{1,100})\s{0,100}""",
    """\s{0,100}Direction:\s{0,100}({direction}[^\s]{1,2000})\s{0,100}""",
    """\s{0,100}Layer Name:\s{0,100}({layer_name}[^\s]{1,2000})\s{0,100}""", 
    """\s{0,100}(TaskCategory|EventCategory)=({activity_type}.+?)\s{0,100}\w+=""",
    """\s{0,100}Application Name:\s{0,100}({process}(({directory}.+)[\\\/])?({process_name}.+?))\s{0,100}Network Information:"""    
  ]
  DupFields = [ "host->local_asset","directory->process_directory" ]
}
```