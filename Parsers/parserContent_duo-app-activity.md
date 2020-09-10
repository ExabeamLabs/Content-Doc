#### Parser Content
```Java
{
Name = duo-app-activity
  Vendor = Duo Security
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """"object":""", """"timestamp":""", """"event_time":""", """"username":""" ]
  Fields = [
    """object":"({object}[^"]+)"""",
    """timestamp":({time}\d+)""",
    """username":"({user}[^"]+)"""",
    """action":"({activity}[^"]+)"""",
    """exabeam_raw=({additional_info}.*?)\s*$"""
  ]
}
```