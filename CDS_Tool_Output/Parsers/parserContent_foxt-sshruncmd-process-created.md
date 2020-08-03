#### Parser Content
```Java
{
Name = foxt-sshruncmd-process-created
  Vendor = Fox BoKS ServerControl 
  Product = Fox BoKS ServerControl
  Lms = Exabeam
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "sshd - ssh_runcmd", "ssh from" ]
  Fields = [
    """clientTime="*({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)Z"*""",
    """\d\dZ\s+({host}[\w\-.]+)\s+sshd - ssh_runcmd""",
    """user="*({user}[^"]+)"""",
    """touser="*({account}[^"]+)"""",
    """ssh from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) starting:""",
    """cmd="*({command_line}({path}({directory}(\/[^\/]+)*\/)({process_name}[^\/\s]+))\s*.*?)"+\] ssh from""",
    """({event_code}ssh_runcmd)"""
  ]
  DupFields = [ "host->dest_host", "process_guid->pid", "path->process", "directory->process_directory" ]
}
```