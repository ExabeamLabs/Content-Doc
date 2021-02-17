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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d+Z\s*({host}[^\s]+)\s""",
    """eventid="+({event_code}\d+)""",
    """providername="+({provider_name}[^"]+)""",
    """userid="(?:[^\\]+\\+)?(SYSTEM|NETWORK SERVICE|({user}[^"]+))""",
    """\stask="+({activity}[^"]+)""",
    """\Weventrecordid="+({record_id}\d+)"""",
    """({event_name}A new external device was recognized by the system)""",
    """\sSecurity ID:\s*({user_sid}[^\s]+)""",
    """\sAccount Name:\s*({account}[^\s]+)""",
    """\sAccount Domain:\s*({domain}.+?)\s*Logon ID:""",
    """\sLogon ID:\s*({logon_id}[^\s]+)""",
    """\sDevice ID:\s*({device_id}[^\s]+)""",
    """\sDevice Name:\s*({device_name}.+?)\s*Class ID:""",
    """\sClass ID:\s*({class_id}.+?)\s*Class""",
    """\sClass Name:\s*({class_name}.+?)\s*Vendor IDs:""",
  ]
  DupFields = ["event_id->event_code"]
}
```