#### Parser Content
```Java
{
Name = cc-carbonblack-process-alert-1
  Vendor = VMware
  Product = App Control
  Lms = Splunk
  DataType = "process-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"watchLists"""", """"responseSeverity"""", """"deviceName"""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"eventTime"{1,20}:\s{0,100}({time}\d{1,100})""",
    """deviceName"{1,20}:\s{0,100}"{1,20}({dest_host}[^"]{1,2000})""",
    """"email"{1,20}:\s{0,100}"{1,20}({user_email}[^@"]{1,2000}@[^"]{1,2000})"{1,20},""",
    """internalIpAddress"{1,20}:\s{0,100}"{1,20}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """md5"{1,20}:\s{0,100}"{1,20}({md5}[^"]{1,2000})""",
    """responseSeverity"{1,20}:\s{0,100}({alert_severity}\d{1,100})""",
    """"type"{1,20}:\s{0,100}"{1,20}({alert_type}[^"]{1,2000})""",  
    """watchLists"{1,20}:[^\}\]]{1,2000}?"{1,20}name":\s{0,100}"{1,20}({alert_name}[^"]{1,2000})""",
    """"threatId"{1,20}:\s{0,100}"{1,20}({alert_id}[^"]{1,2000})""",
    """"url"{1,20}:\s{0,100}"{1,20}({additional_info}[^"]{1,2000})""",
    """"processPath"{1,20}\s{0,100}:\s{0,100}"{1,20}({process}({directory}([^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}))"""",
    """iocId"{1,20}:\s{0,100}"{1,20}({ioc}[^"]{1,2000})""",
    """OS:\s{0,100}({os}[^\s]{1,2000})""",
   ]
}
```