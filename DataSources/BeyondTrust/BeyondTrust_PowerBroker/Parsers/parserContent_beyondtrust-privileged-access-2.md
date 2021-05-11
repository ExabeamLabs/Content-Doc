#### Parser Content
```Java
{
Name = beyondtrust-privileged-access-2
  Vendor = BeyondTrust
  Product = BeyondTrust PowerBroker
  Lms = Direct
  DataType = "privileged-access"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """EventMessage":"Application Requested Elevation""","""EventName":"28691""", """Category":"pbw""", """UserType":""" ]
  Fields = [
    """TimeCreated":"({time}\d{1,100}\/\d{1,100}\/\d\d\d\d\s\d{1,100}:\d{1,100}:\d{1,100}\s(am|AM|pm|PM))""",
    """exabeam_host=({host}[^\s]+)""",
    """EventName":"({event_code}\d{1,100})"""",
    """AssetName":"({dest_host}[^"]+?)"""",
    """UserName":"({domain}[^\\\/]+?)[\\\/]+({user}[^"]+?)"""",
    """Path":"({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?))"""",
    """UserType":"({privileges}[^"]+?)"""",
    """RuleName":"(NONE|({event_name}[^"]+?))"""",
    ]
    DupFields = [ "directory->process_directory" ]
}
```