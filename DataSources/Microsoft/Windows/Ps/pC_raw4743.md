#### Parser Content
```Java
{
Name = raw-4743
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "account-deleted"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """A computer account was deleted""", """<EventID>4743</EventID>""" ]
  Fields = [
    """({event_name}A computer account was deleted)""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """({event_code}4743)""",
    """Subject:[^=]{1,2000}?\sAccount Name:\s{0,100}(|-|({user}[^=]{1,2000}?))\s{0,100}Account Domain:\s{0,100}(|-|({domain}[^=]{1,2000}?))\s{0,100}Logon ID:\s{0,100}(|-|({logon_id}[^=]{1,2000}?))\s{0,100}Target Computer:[^=]{1,2000}?\sAccount Name:\s{0,100}(|-|({target_user}[^=]{1,2000}?))\s{0,100}Account Domain:\s{0,100}(|-|({object_dn}[^"]{1,2000}?))\s{0,100}Additional Information:""",
    """\sTarget Computer:[^=]{1,2000}?Account Name:\s{0,100}({src_host}[^$:]{1,2000}?)\$""",
  ]
  DupFields = [ "host-> dest_host"]


}
```