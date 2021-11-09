#### Parser Content
```Java
{
Name = fireeye-mps-xml-extended-body-alert
  Vendor = FireEye
  Product = FireEye Network Security (NX)
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """fenotify-""","""<src vlan=""" ]
  Fields = [
    """<occurred>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}\S+)""",  
    """ fenotify-({alert_id}\d{1,100})""",
    """<src vlan=\".+\">\s{0,100}<ip>({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """<src .+?<host>({src_host}[^<]{1,2000})""",
    """<dst>.+?<ip>({dest_ip}[^<]{1,2000})</ip""" 
  ]
}
}
```