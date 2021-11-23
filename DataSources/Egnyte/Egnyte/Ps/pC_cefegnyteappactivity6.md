#### Parser Content
```Java
{
Name = cef-egnyte-app-activity-6
  Conditions = [ """"action":"Disable"""", """destinationServiceName =Egnyte""", """"subject":"""", """suspended by""" ]

cef-egnyte-app-activity = {
  Vendor = Egnyte
  Product = Egnyte
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"date_and_time":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)""",
    """"date":({time}\d{1,100})""",
    """({app}Egnyte)""",
    """"subject":"({user_fullname}[^"\(\)]{1,2000}?)\s{0,100}\(\s{0,100}({user_email}[^@"\(\)]{1,2000}@({email_domain}[^\."\)]{1,2000}\.[^"\)]{1,2000}?))\s{0,100}\)""",
    """"action":"({activity}[^"]{1,2000})""",
    """actionInfo":"({additional_info}[^,]{1,2000})",""",
    """action_Info":"({additional_info}[^,]{1,2000})",""",
  
}
```