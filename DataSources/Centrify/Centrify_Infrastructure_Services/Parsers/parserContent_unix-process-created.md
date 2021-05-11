#### Parser Content
```Java
{
Name = unix-process-created
  Vendor = Centrify
  Product = Centrify Infrastructure Services
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """ MachineName: """", """ UnixName: """", """Command:""" ]
  Fields = [
    """Time:\s{0,100}"{1,20}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """MachineName:\s{0,100}"{1,20}({host}[\w\-.]+)""",
    """Command:\s{0,100}"{1,20}({command_line}[^"]+)""",
    """Command:\s{0,100}"{1,20}({process}({directory}[^\s"]*?)[\\\/]*({process_name}[^\\\/\s"]+))""",
    """UserName:\s{0,100}"{1,20}({user}[^"]+)""",
    """UnixName:\s{0,100}"{1,20}({account}[^"]+)""",
    """ClientName:\s{0,100}"{1,20}(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^"]+))""",
  ]
  DupFields = [ "host->dest_host" ]
}
```