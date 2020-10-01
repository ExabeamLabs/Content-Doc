#### Parser Content
```Java
{
Name = foxt-suexec-process-created
  Vendor = HelpSystems
  Product = Powertech Identity Access Manager (BoKs)
  Lms = Exabeam
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "suexec - suexec_ok", "Successful suexec" ]
  Fields = [
    """clientTime="*({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)Z"*""",
    """\d\dZ\s+({host}[\w\-.]+)\s+suexec - suexec_ok""",
    """user="*({user}[^"]+)"""",
    """touser="*({account}[^"]+)"""",
    """Successful suexec \(pid ({process_guid}\d+) from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """cmd="*({command_line}({path}({directory}(\/[^\/]+)*\/)({process_name}[^\/]+))\s*.*?)"+\] Successful suexec""",
    """({event_code}suexec)"""
  ]
  DupFields = [ "host->dest_host", "process_guid->pid", "path->process","directory->process_directory" ]
}
```