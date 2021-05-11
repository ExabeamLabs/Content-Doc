#### Parser Content
```Java
{
Name = cef-windows-6416
  Lms = Splunk
  Vendor = Microsoft
  Product = Microsoft Windows
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  DataType = "usb-insert"
  Conditions = [ """eventid="6416"""", """Microsoft-Windows-Security-Auditing""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z\s{0,100}({host}[^\s]+)\s""",
    """eventid="{1,20}({event_code}\d{1,100})""",
    """providername="{1,20}({provider_name}[^"]+)""",
    """userid="(?:[^\\]+\\+)?(SYSTEM|NETWORK SERVICE|({user}[^"]+))""",
    """\stask="{1,20}({activity}[^"]+)""",
    """\Weventrecordid="{1,20}({record_id}\d{1,100})"""",
    """({event_name}A new external device was recognized by the system)""",
    """\sSecurity ID:\s{0,100}({user_sid}[^\s]+)""",
    """\sAccount Name:\s{0,100}({account}[^\s]+)""",
    """\sAccount Domain:\s{0,100}({domain}.+?)\s{0,100}Logon ID:""",
    """\sLogon ID:\s{0,100}({logon_id}[^\s]+)""",
    """\sDevice ID:\s{0,100}({device_id}[^\s]+)""",
    """\sDevice Name:\s{0,100}({device_name}.+?)\s{0,100}Class ID:""",
    """\sClass ID:\s{0,100}({class_id}.+?)\s{0,100}Class""",
    """\sClass Name:\s{0,100}({class_name}.+?)\s{0,100}Vendor IDs:""",
  ]
  DupFields = ["event_id->event_code"]
}
```