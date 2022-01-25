#### Parser Content
```Java
{
Name = raw-4742
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "ds-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """A computer account was changed""", """4742""" ]
  Fields = [
    """EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
    """({event_name}A computer account was changed)""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?(::ffff:)?({host}[\w.-]{1,2000})""",
    """<Computer>(::ffff:)?({host}[^<]{1,2000})</Computer>""",
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100})""",
    """(?i)\w+\s{0,100}\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(am|pm|({host}[\w\-.]{1,2000}))""",
    """({event_code}4742)""",
    """Subject:.+?\sAccount Name:\s{0,100}(|-|({user}[^:]{1,2000}?))\s{0,100}Account Domain:\s{0,100}(|-|({domain}[^:]{1,2000}?))\s{0,100}Logon ID:\s{0,100}(|-|({logon_id}[^\s]{1,2000}))\s{0,100}Computer Account That Was Changed:.*?\sAccount Name:\s{0,100}(|-|({target_user}[^:]{1,2000}?))\s{0,100}Account Domain:\s{0,100}(|-|({object_dn}[^:]{1,2000}?))\s{0,100}Changed Attributes:""",
    """\sComputer Account That Was Changed:.+?Account Name:\s{0,100}(::ffff:)?({src_host}[^$:]{1,2000}?)\$""",
    """\sUser Principal Name:\s{0,100}(|-|({attribute}.+?))\s{0,100}Home Directory:""",
    """(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(am|pm|({dest_host}[\w\-.]{1,2000})))"""
  ]
  DupFields = [ "host->dest_host"]


}
```