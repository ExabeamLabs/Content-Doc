#### Parser Content
```Java
{
Name = openvms-failed-logon
  Vendor = VMS Software
  Product = OpenVMS
  Lms = Direct
  DataType = "failed-logon"
  TimeFormat = "dd-MMM-yyyy HH:mm:ss.SS"
  Conditions = [ """Auditable event:""", """Remote interactive login failure""", """Username:""" ]
  Fields = [
    """failure\s{1,100}Event time:\s{1,100}({time}\d\d-\w{1,100}-\d\d\d\d\s{1,100}\d\d:\d\d:\d\d\.\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """failure\s{1,100}[^"]{1,2000}Username:\s{1,100}({user}[^\s]{1,2000})\s{1,100}(\w{1,100}|$)""",
    """({event_name}Remote interactive login failure)""",
    """failure\s{1,100}[^"]{1,2000}PID:\s{1,100}({pid}[\w]{1,2000})\s{1,100}(\w{1,100}|$)""",
    """failure\s{1,100}[^"]{1,2000}Process name:\s{1,100}({process_name}[^\s]{1,2000})\s{1,100}(\w{1,100}|$)""",
    """failure\s{1,100}[^"]{1,2000}Status:\s{1,100}({outcome}[^"]{1,2000}?)\s{0,100}"""",
    """failure\s{1,100}[^"]{1,2000}Terminal name:\s{1,100}({additional_info}[^\s]{1,2000})\s{1,100}(\w{1,100}|$)""",
    """failure\s{1,100}[^"]{1,2000}Host:\s{1,100}({host}[A-Fa-f\d\.:]{1,2000})\s{1,100}(\w{1,100}|$)""",
    """failure\s{1,100}[^"]{1,2000}Status:\s{1,100}[^"]{1,100

}
```