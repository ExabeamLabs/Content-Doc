#### Parser Content
```Java
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