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
    """object":"({object}[^"]{1,2000})"""",
    """timestamp":({time}\d{1,100})""",
    """username":"({user}[^"]{1,2000})"""",
    """action":"({activity}[^"]{1,2000})"""",
    """exabeam_raw=({additional_info}.*?)\s{0,100}$"""
  ]
}
```