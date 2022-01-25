#### Parser Content
```Java
{
Name = openvms-remote-login
  DataType = "remote-logon"
  Conditions = [ """Auditable event:""", """Remote interactive login""", """Username:""" ]
  Fields = ${OpenVMSParserTemplates.openvms-logon.Fields}[
    """Terminal name:\s{1,100}({additional_info}[^\s]{1,2000})\s{1,100}(\w{1,100}|$)""",
    """Host:\s{1,100}({host}[A-Fa-f\d\.:]{1,2000})\s{1,100}(\w{1,100}|$)""",
    """({event_name}Remote interactive login)"""
  ]
  DupFields = [ "event_name->activity","host->dest_ip" ]

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