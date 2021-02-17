#### Parser Content
```Java
{
Name = unix-process-created
  Vendor = Centrify Infrastructure Services
  Product = Centrify Infrastructure Services
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """ MachineName: """", """ UnixName: """", """Command:""" ]
  Fields = [
    """Time:\s*"+({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d+)""",
    """MachineName:\s*"+({host}[\w\-.]+)""",
    """Command:\s*"+({command_line}[^"]+)""",
    """Command:\s*"+({process}({directory}[^\s"]*?)[\\\/]*({process_name}[^\\\/\s"]+))""",
    """UserName:\s*"+({user}[^"]+)""",
    """UnixName:\s*"+({account}[^"]+)""",
    """ClientName:\s*"+(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^"]+))""",
  ]
  DupFields = [ "host->dest_host" ]
}
```