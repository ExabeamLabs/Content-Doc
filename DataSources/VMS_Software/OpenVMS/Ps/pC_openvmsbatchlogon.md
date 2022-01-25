#### Parser Content
```Java
{
Name = openvms-batch-logon
  DataType = "batch-logon"
  Conditions = [ """Auditable event:""", """Batch process login""", """Username:""" ]
  Fields = ${OpenVMSParserTemplates.openvms-logon.Fields}[
    """({event_name}Batch process login)"""
  ]
  DupFields = [ "event_name->activity" ]


openvms-logon = {
  Vendor = VMS Software
  Product = OpenVMS
  Lms = Direct
  TimeFormat = "dd-MMM-yyyy HH:mm:ss.SS"
  Fields = [
    """Event time:\s{1,100}({time}\d\d-\w{1,100}-\d\d\d\d\s{1,100}\d\d:\d\d:\d\d\.\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """Username:\s{1,100}({user}[^\s]{1,2000})\s{1,100}(\w{1,100}|$)""",
    """PID:\s{1,100}({pid}[\w]{1,2000})\s{1,100}(\w{1,100}|$)""",
    """Process name:\s{1,100}({process_name}[^\s]{1,2000})\s{1,100}(\w{1,100}|$)"""   
  
}
```