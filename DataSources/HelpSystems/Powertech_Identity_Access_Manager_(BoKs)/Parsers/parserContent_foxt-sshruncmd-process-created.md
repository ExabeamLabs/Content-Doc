#### Parser Content
```Java
{
Name = foxt-sshruncmd-process-created
  Vendor = HelpSystems
  Product = Powertech Identity Access Manager (BoKs)
  Lms = Exabeam
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "sshd - ssh_runcmd", "ssh from" ]
  Fields = [
    """clientTime="{0,20}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)Z"{0,20}""",
    """\d\dZ\s{1,100}({host}[\w\-.]+)\s{1,100}sshd - ssh_runcmd""",
    """user="{0,20}({user}[^"]+)"""",
    """touser="{0,20}({account}[^"]+)"""",
    """ssh from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) starting:""",
    """cmd="{0,20}({command_line}({path}({directory}(\/[^\/]+)*\/)({process_name}[^\/\s]+))\s{0,100}.*?)"{1,20}\] ssh from""",
    """({event_code}ssh_runcmd)"""
  ]
  DupFields = [ "host->dest_host", "process_guid->pid", "path->process", "directory->process_directory" ]
}
```