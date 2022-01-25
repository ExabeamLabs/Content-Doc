#### Parser Content
```Java
{
Name = openvms-file-delete
  DataType = "file-delete"
  Conditions = [ """Auditable event:""", """Object deletion""", """Username:""" ]
  Fields = ${OpenVMSParserTemplates.openvms-file-operations.Fields}[
    """File name:\s{1,100}({file_name}[^\s]{1,2000})\s{1,100}(\w{1,100}|$)""",
    """({event_name}Object deletion)"""
  ]

openvms-file-operations = {
  Vendor = VMS Software
  Product = OpenVMS
  Lms = Direct
  TimeFormat = "dd-MMM-yyyy HH:mm:ss.SS"
  Fields = [
    """Event time:\s{1,100}({time}\d\d-\w{1,100}-\d\d\d\d\s{1,100}\d\d:\d\d:\d\d\.\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """Username:\s{1,100}({user}[^\s]{1,2000})\s{1,100}(\w{1,100}|$)""",
    """PID:\s{1,100}({pid}[\w]{1,2000})\s{1,100}(\w{1,100}|$)""",
    """Process name:\s{1,100}({process_name}[^\s]{1,2000})\s{1,100}(\w{1,100}|$)""",
    """Status:\s{1,100}({outcome}[^"]{1,2000}?)\s{0,100}"""",
    """Access requested:\s{1,100}({accesses}[^\s]{1,2000})\s{1,100}(\w{1,100}|$)""",
    """Terminal name:\s{1,100}({additional_info}[^\s]{1,2000})\s{1,100}(\w{1,100}|$)"""
  ]
  DupFields = [ "event_name->activity" 
}
```