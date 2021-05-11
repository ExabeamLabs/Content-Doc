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
    """clientTime="{0,20}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)Z"{0,20}""",
    """\d\dZ\s{1,100}({host}[\w\-.]+)\s{1,100}suexec - suexec_ok""",
    """user="{0,20}({user}[^"]+)"""",
    """touser="{0,20}({account}[^"]+)"""",
    """Successful suexec \(pid ({process_guid}\d{1,100}) from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """cmd="{0,20}({command_line}({path}({directory}(\/[^\/]+)*\/)({process_name}[^\/]+))\s{0,100}.*?)"{1,20}\] Successful suexec""",
    """({event_code}suexec)"""
  ]
  DupFields = [ "host->dest_host", "process_guid->pid", "path->process","directory->process_directory" ]
}
```