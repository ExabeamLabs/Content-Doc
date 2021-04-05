#### Parser Content
```Java
{
Name = beyondtrust-process-created
  Vendor = BeyondTrust
  Product = BeyondTrust PowerBroker
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """EventMessage":"Application Launched""","""EventName":"28692""", """Category":"pbw""" ]
  Fields = [
    """TimeCreated":"({time}\d+\/\d+\/\d\d\d\d\s\d+:\d+:\d+\s(am|AM|pm|PM))""",
    """exabeam_host=({host}[^\s]+)""",
    """EventName":"({event_code}\d+)"""",
    """AssetName":"({dest_host}[^"]+?)"""",
    """UserName":"({domain}[^\\\/]+?)[\\\/]+({user}[^"]+?)"""",
    """Path":"({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?))"""",
    """Arguments":"({command_line}[^"]+?)"""",
    """EventDesc":"({event_name}[^"]+?)"""",
    ]
    DupFields = [ "directory->process_directory" ]
}
```