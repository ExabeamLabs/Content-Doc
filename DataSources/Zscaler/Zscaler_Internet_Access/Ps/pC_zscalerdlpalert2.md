#### Parser Content
```Java
{
Name = zscaler-dlp-alert-2
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Syslog
  DataType = "dlp-alert"
  TimeFormat = "EEE MMM dd HH:mm:ss yyyy"
  Conditions = [ """"zscalernss-casb"""", """"dlpenginenames":""", """"login":""", """"recordid":""", """"company":""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"dlpdictnames":"((None)|({alert_name}[^"]{1,2000}))"\s{0,100}""", 
    """"dlpdictnames":"((None)|({dlp_dict}[^"]{1,2000}))"\s{0,100}""",
    """"dept":"({department}[^"]{1,2000})"\s{0,100}""",
    """"applicationname":"({app}[^"]{1,2000})"\s{0,100}""",
    """"Attachedfilename":"((None)|({file_name}[^"]{1,2000}))"\s{0,100}""",
    """"login":"({user_email}[^@]{1,2000}@[^.]{1,2000}\.[^"]{1,2000})"\s{0,100}""",
    """"policy":"((None)|({policy}[^"]{1,2000}))"\s{0,2000}"""
  ]
  DupFields = [ "alert_name->alert_type" ]


}
```