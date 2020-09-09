#### Parser Content
```Java
{
Name = apc-remote-logon
  Vendor = APC
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """ Web user """, """ logged in from """ ]
  Fields = [
    """<\d+>(\w+\s+\d+\s+\d\d:\d\d:\d\d)\s+({host}[\w.\-]+)\s""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Web user '({user}[^']+)'""",
    """\slogged in from ({src_ip}[a-fA-F\d.:]+?)\.?\s+"""
  ]
  DupFields = [ "host->dest_host" ]
}

{
  Name = q-beyondtrust-process-created
  Vendor = BeyondTrust PowerBroker
  Lms = QRadar
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """ Message forwarded from """, """: accepted """ ]
  Fields = [
    """exabeam_endTime=({time}\d+)""",
    """\s+Message forwarded from ({host}[\w\-.]+)""",
    """accepted ({process}({proccess_directory}.+?[\\\/])?({process_name}[^\\\/]+?)) from ({user}[^\s@]+)@({src_host}[\w\-.]+) to ({account}[^\s@]+)@({dest_host}[\w\-.]+)""",
  ]
}
```