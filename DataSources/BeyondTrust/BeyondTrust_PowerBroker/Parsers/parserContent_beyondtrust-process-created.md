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
    """TimeCreated":"({time}\d{1,100}\/\d{1,100}\/\d\d\d\d\s\d{1,100}:\d{1,100}:\d{1,100}\s(am|AM|pm|PM))""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """EventName":"({event_code}\d{1,100})"""",
    """AssetName":"({dest_host}[^"]{1,2000}?)"""",
    """UserName":"({domain}[^\\\/]{1,2000}?)[\\\/]{1,2000}({user}[^"]{1,2000}?)"""",
    """Path":"({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}?))"""",
    """Arguments":"({command_line}[^"]{1,2000}?)"""",
    """EventDesc":"({event_name}[^"]{1,2000}?)"""",
    ]
    DupFields = [ "directory->process_directory" ]
}
```