#### Parser Content
```Java
{
Name = win-def-mal-detect
  Vendor = Microsoft
  Product = Windows Defender
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Windows Defender Antivirus""", """Detection Source:""", """Virus""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",    
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\s+Name:\s*({alert_name}.*?)\s+ID:""",
    """\s+Category:\s*({alert_type}.*?)\s+Path:""",
    """\s+Severity:\s*({alert_severity}\w+?)\s+Category:""",
    """\s+User:\s*(({domain}[^\\=]+)\\+)?({user}.+?)\s+Process Name:""",
    """\s+Process Name:\s*({process}({directory}(?:[^,]+)?[\\\/])?({process_name}[^\\\/,]+?))\s+Signature Version:""",
    """\s+Action:\s*({outcome}.*?)\s+Action Status:""",
    """\s+Path:\s*(file:_)?({file_path}.*?)\s+Detection Origin:"""
  ]
  DupFields = ["directory->process_directory"]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName","alert_severity->sourceSeverity","alert_type->malwareCategory","file_path->malwareAttackerFile"]
    NameTemplate = """Windows Defender ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="user", Name="windows_id", Fields=["user->windows_id"]}
    ]
  }
}
${WinParserTemplates.d-xml-windows-device} {
  Name = win-external-device-recog
  DataType = "usb-insert"
  Conditions = [ """A new external device was recognized by the system.""", """>6416</EventID>""" ]
  Fields = ${WinParserTemplates.d-xml-windows-device.Fields} [
    """>({event_code}6416)<\/EventID>"""
    """({event_name}A new external device was recognized by the system.)"""
  ]
  DupFields = [ "event_name->activity" ]
}
${WinParserTemplates.d-xml-windows-device} {
  Name = win-enable-device-request
  DataType = "usb-activity"
  Conditions = [ """A request was made to enable a device.""", """>6421</EventID>""" ]
  Fields = ${WinParserTemplates.d-xml-windows-device.Fields} [
    """>({event_code}6421)<\/EventID>"""
    """({event_name}A request was made to enable a device.)"""
  ]
}
${WinParserTemplates.d-xml-windows-device} {
  Name = win-enable-device
  DataType = "usb-insert"
  Conditions = [ """A device was enabled.""", """>6422</EventID>""" ]
  Fields = ${WinParserTemplates.d-xml-windows-device.Fields} [
    """>({event_code}6422)<\/EventID>"""
    """({event_name}A device was enabled.)"""
  ]
}
${WinParserTemplates.d-xml-windows-device} {
  Name = win-disable-device-request
  DataType = "usb-activity"
  Conditions = [ """A request was made to disable a device.""", """>6419</EventID>""" ]
  Fields = ${WinParserTemplates.d-xml-windows-device.Fields} [
    """>({event_code}6419)<\/EventID>"""
    """({event_name}A request was made to disable a device.)"""
  ]
}
${WinParserTemplates.d-xml-windows-device} {
  Name = win-disable-device
  DataType = "usb-activity"
  Conditions = [ """A device was disabled.""", """>6420</EventID>""" ]
  Fields = ${WinParserTemplates.d-xml-windows-device.Fields} [
    """>({event_code}6420)<\/EventID>"""
    """({event_name}A device was disabled.)"""
  ]
}
{
  Name = win-powershell-command
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """>4103</EventID>""", """CommandInvocation""", """Script Name =""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """<TimeCreated SystemTime=\'({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z)\'\/>"""
    """>({event_code}4103)<\/EventID>"""
    """<Computer>({dest_host}.*?)<\/Computer>"""
    """<Security UserID='({user_sid}[\w-]+)'"""
    """Script Name =\s+({process}({directory}([\w:]+\\)?([^\\]+?\\)*?)({process_name}[^\\]*?))\s+Command Path ="""
    """User = (({domain}[^\\]+?)\\)?({user}[^\s]+)\s+Connected User ="""
  ]

}

{
  Name = s-4740-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-account-lockout"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """EventCode=4740""", """EventType=""", """A user account was locked out""" ]
  Fields = [
    """({host}[\w\-.]+)\s+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(am|AM|pm|PM))""",
    """ComputerName=({dest_host}[\w\-.]+)""",
    """({event_code}4740)""",
    """({event_name}A user account was locked out)"""
    """RecordNumber=({record_id}[^;"]+)""",
    """Keywords=({outcome}[^;"]+)""",
    """Subject=.*?Account Name=({caller_user}[^;"\s]+)""",
    """Subject=.*?Account Domain=({caller_domain}[^;"\s]+)""",
    """Logon ID=({logon_id}[^;"\s]+)""",
    """Security ID=({user_sid}[^;"]+);Account Name=({user}[^;"\s]+);Additional Information=""",
    """Caller Computer Name=\\*({src_host}[\w\-.]+)""",
  ]
  DupFields=[ "caller_domain->domain" ]
}
```