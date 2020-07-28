#### Parser Content
```Java
{
Name = cef-windows-4104
  Lms = Splunk
  Vendor = Microsoft
  Product = Microsoft Windows
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  DataType = "process-created"
  Conditions = [ """eventid="4104"""", """Microsoft-Windows-PowerShell""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d+Z\s*({host}[^\s]+)\s""",
    """eventid="+({event_code}\d+)""",
    """providername="+({provider_name}[^"]+)""",
    """userid="(?:[^\\]+\\+)?(SYSTEM|NETWORK SERVICE|({user}[^"]+))""",
    """\stask="+({activity}[^"]+)""",
    """\Weventrecordid="+({record_id}\d+)"""",
    """({event_name}Creating Scriptblock text)""",
    """ScriptBlock ID:\s+({scriptblock_id}[^\s]+)""",
    """({process_name}PowerShell)""",
    """Creating Scriptblock text\s*\([^\)]+\):\s*({scriptblock_text}.+?)\s*ScriptBlock ID:""",
  ]
  DupFields = ["event_id->event_code"]
}

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

{
  Name = cef-windows-4624
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-4624"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """"eventID":"4624"""", """An account was successfully logged on""" ]
  Fields = [
    """"systemTime":"({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """"computer":"({host}[\w\-.]+)""",
    """"message":"({event_name}[^"]+?)\s*"""",
    """"eventID":"({event_code}\d+)""",
    """"eventRecordID":"({record_id}\d+)""",
    """"severityValue":"({outcome}[^"]+?)\s*"""",
    """"subjectUserSid":"({user_sid}[^"\s]+?)\s*"""",
    """"subjectUserName":"({user}[^"\s]+?)\s*"""",
    """"subjectDomainName":"({domain}[^"\s]+?)\s*"""",
    """"subjectLogonId":"({logon_id}[^"\s]+?)\s*"""",
    """"logonType":"({logon_type}[^"]+?)\s*"""",
    """"logonProcessName":"({auth_process}[^"]+?)\s*"""",
    """"authenticationPackageName":"({auth_package}[^"]+?)\s*"""",
    """"workstationName":"({src_host_windows}[^"]+?)\s*"""",
    """"processName":"(?:-|({process}({directory}[^"]*?)(\\+({process_name}[^"\\]+?))?))\s*"""",
    """"ipAddress":"({src_ip}[A-Fa-f:\d.]+)""",
    """"ipPort":"({src_port}\d+)""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```