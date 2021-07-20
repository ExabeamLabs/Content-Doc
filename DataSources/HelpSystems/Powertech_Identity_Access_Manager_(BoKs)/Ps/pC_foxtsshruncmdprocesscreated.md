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
    """\d\dZ\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}sshd - ssh_runcmd""",
    """user="{0,20}({user}[^"]{1,2000})"""",
    """touser="{0,20}({account}[^"]{1,2000})"""",
    """ssh from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) starting:""",
    """cmd="{0,20}({command_line}({path}({directory}(\/[^\/]{1,2000})*\/)({process_name}[^\/\s]{1,2000}))\s{0,100}.*?)"{1,20}\] ssh from""",
    """({event_code}ssh_runcmd)"""
  ]
  DupFields = [ "host->dest_host", "process_guid->pid", "path->process", "directory->process_directory" ]
}
```