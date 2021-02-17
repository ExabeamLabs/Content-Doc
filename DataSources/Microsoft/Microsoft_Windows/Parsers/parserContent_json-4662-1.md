#### Parser Content
```Java
{
Name = json-4662-1
  DataType = "windows-privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"EventID":"4662"""", """An operation was performed on an object""" ]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """"Computer":"({host}[^"]+)"""",
    """"TimeCreated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({event_name}An operation was performed on an object)""",
    """({event_code}4662)""",
    """"ObjectName":"({object}[^"]+)"""",
    """"ObjectServer":"({object_server}[^"]+)"""",
    """"ObjectType":"({activity_type}[^"]+)"""",
    """"LogonID":"({logon_id}[^"]+)"""",
    """"OperationType":"({activity}[^"]+)"""",
    """"AdditionalInfo":"(?:-|({additional_info}[^"]+))""""
  ]
   DupFields = ["host->dest_host"]
}
```