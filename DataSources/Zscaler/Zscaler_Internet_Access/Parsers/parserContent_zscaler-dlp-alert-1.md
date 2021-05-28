#### Parser Content
```Java
{
Name = zscaler-dlp-alert-1
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Syslog
  DataType = "dlp-alert"
  TimeFormat = "EEE MMM dd HH:mm:ss yyyy"
  Conditions = [ """dlpenginenames=""", """login=""", """recordid=""", """company=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """dlpdictnames=({alert_name}[^=]{1,2000}?)\s{0,100}\w+=""",
    """lastmodtime=({time}\w+ \w+\s{0,100}\d{1,2}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{0,100}\d{1,100})""",
    """dlpdictnames=(None|({dlp_dict}[^=]{1,2000}?))\s{0,100}\w+=""",
    """dept=(-|({department}[^=]{1,2000}?))\s{0,100}\w+=""",
    """applicationname=(None|({app}[^=]{1,2000}?))\s{0,100}\w+=""",
    """filename=(None|({file_name}[^=]{1,2000}?))\s{0,100}\w+=""",
    """filesource=({additional_info}[^=]{1,2000}?)\s{0,100}\w+=""",
    """filemd5=(None|({md5}[^=]{1,2000}?))\s{0,100}\w+=""",
    """login=(({user_email}[^@]{1,2000}@[^\.]{1,2000}\.[^=]{1,2000}?)|({user}[^=]{1,2000}?))\s{0,100}\w+=""",
    """policy=(None|({policy}[^=]{1,2000}?))\s{0,100}\w+="""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```