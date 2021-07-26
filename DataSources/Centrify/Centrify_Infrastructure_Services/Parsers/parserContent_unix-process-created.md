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
    """MachineName:\s{0,100}"{1,20}({host}[\w\-.]{1,2000})""",
    """Command:\s{0,100}"{1,20}({command_line}[^"]{1,2000})""",
    """Command:\s{0,100}"{1,20}({process}({directory}[^\s"]{0,2000}?)[\\\/]{0,2000}({process_name}[^\\\/\s"]{1,2000}))""",
    """UserName:\s{0,100}"{1,20}({user}[^"]{1,2000})""",
    """UnixName:\s{0,100}"{1,20}({account}[^"]{1,2000})""",
    """ClientName:\s{0,100}"{1,20}(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^"]{1,2000}))""",
  ]
  DupFields = [ "host->dest_host" ]
}
```