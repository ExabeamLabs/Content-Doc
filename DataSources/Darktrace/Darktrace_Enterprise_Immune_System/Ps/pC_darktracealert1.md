#### Parser Content
```Java
{
Name = darktrace-alert-1
  Product = Darktrace Enterprise Immune System
  Vendor = Darktrace
  Lms = Direct
  DataType = "alert"
  TimeFormat ="epoch"
  Conditions =[ """comparatorType""", """filterType""","""throttle""" ]
  Fields =[
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"{1,20}hostname"{1,20}:"{1,20}({src_host}[^"]{1,2000})""",
    """"{1,20}creationTime"{1,20}:({time}\d{1,100})"""
    """"{1,20}ip"{1,20}:"{1,20}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """"{1,20}breachUrl"{1,20}:"{1,20}({malware_url}[^"]{1,2000})""",
    """"{1,20}name"{1,20}:"{1,20}({alert_name}[^"]{1,2000})""",
    """macaddress"{1,20}:"{1,20}({src_mac}[^"]{1,2000})""",
    """"{1,20}time"{1,20}:({time}.*?),"{1,20}model""",
    """"priority"{1,20}:({alert_severity}\d{1,100})""",
    """"{1,20}typename"{1,20}:"{1,20}({alert_type}[^"]{1,2000})""",
    """"os"{1,20}:"{1,20}({os}[^"]{1,2000})""",
    """filterType"{1,20}:?"{1,20}Destination IP.+?value"{1,20}:"{1,20}({dest_ip}[a-fA-F\d:\.]{1,2000})"\}""",
    """"{1,20}description"{1,20}:"{1,20}({additional_info}[^"]{1,2000})"""
    ]


}
```