#### Parser Content
```Java
{
Name = duo-app-activity
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """"object":""", """"timestamp":""", """"event_time":""", """"username":""" ]
  Fields = [
    """object":"({object}[^"]+)"""",
    """timestamp":({time}\d{1,100})""",
    """username":"({user}[^"]+)"""",
    """action":"({activity}[^"]+)"""",
    """exabeam_raw=({additional_info}.*?)\s{0,100}$"""
  ]
}
```