#### Parser Content
```Java
{
Name = win-enable-device-request
  DataType = "usb-activity"
  Conditions = [ """A request was made to enable a device.""" ]
  Fields = ${WinParserTemplates.d-xml-windows-device.Fields} [
    """({event_code}6421)""",
    """>({event_code}6421)<\/EventID>"""
    """({event_name}A request was made to enable a device.)"""
  ]
}
${WinParserTemplates.d-xml-windows-device} {
  Name = win-enable-device
  DataType = "usb-insert"
  Conditions = [ """A device was enabled.""" ]
  Fields = ${WinParserTemplates.d-xml-windows-device.Fields} [
    """({event_code}6422)""",
    """>({event_code}6422)<\/EventID>"""
    """({event_name}A device was enabled.)"""
  ]
}
${WinParserTemplates.d-xml-windows-device} {
  Name = win-disable-device-request
  DataType = "usb-activity"
  Conditions = [ """A request was made to disable a device.""" ]
  Fields = ${WinParserTemplates.d-xml-windows-device.Fields} [
    """({event_code}6419)""",
    """>({event_code}6419)<\/EventID>"""
    """({event_name}A request was made to disable a device.)"""
  ]
}
${WinParserTemplates.d-xml-windows-device} {
  Name = win-disable-device
  DataType = "usb-activity"
  Conditions = [ """A device was disabled.""" ]
  Fields = ${WinParserTemplates.d-xml-windows-device.Fields} [
    """({event_code}6420)""",
    """>({event_code}6420)<\/EventID>"""
    """({event_name}A device was disabled.)"""
  ]
}
${WinParserTemplates.ibr-ad-template} {
  Name = ibr-ad-4624
  DataType = "windows-4624"
  Conditions = [ """ibr_ad""", """<custom_condition_cont-7495>""", """,4624,""" ]
  Fields = ${WinParserTemplates.ibr-ad-template.Fields} [
    """,Microsoft-Windows-Security-Auditing,[^\|]+\|(|-|({user}[^\|]+?))\|(|-|({domain}[^\|]+?))\|(|-|({logon_id}[^\|]+?))\|(|-|({target_user_sid}[^\|]+?))\|(|-|({target_user}[^\|]+?))\|(|-|({target_domain}[^\|]+?))\|(|-|({target_logon_id}[^\|]+?))\|(|-|({logon_type}[^\|]+?))\|(|-|({process}[^\|]+?))\|(|-|({auth_package}[^\|]+?))\|(|-|[^\|]+?)\|(|-|({src_host}[^\|]+?))\|(|-|({guid}[^\|]+?))\|(|-|({service}[^\|]+?))\|(|-|[^\|]+?)\|(|-|({key_length}[^\|]+?))\|(|-|({process_id}[^\|]+?))\|(|-|({src_ip}[^\|]+?))\|(({src_port}\d+)|-|)"""
  ]
}
${WinParserTemplates.ibr-ad-template} {
  Name = ibr-ad-4625
  DataType = "windows-failed-logon"
  Conditions = [ """ibr_ad""", """<custom_condition_cont-7495>""", """,4625,""" ]
  Fields = ${WinParserTemplates.ibr-ad-template.Fields} [
    """,Microsoft-Windows-Security-Auditing,[^\|]+\|(|-|({user}[^\|]+?))\|(|-|({domain}[^\|]+?))\|(|-|({logon_id}[^\|]+?))\|(|-|({target_user_sid}[^\|]+?))\|(|-|({target_user}[^\|]+?))\|(|-|({target_domain}[^\|]+?))\|(|-|({status}[^\|]+?))\|(|-|({result_code}[^\|]+?))\|(|-|({sub_status}[^\|]+?))\|(|-|({logon_type}[^\|]+?))\|(|-|({logon_process}[^\|]+?))\|(|-|({auth_package}[^\|]+?))\|(|-|({src_host}[^\|]+?))\|(|-|({services}[^\|]+?))\|(|-|[^\|]+?)\|(|-|({key_length}[^\|]+?))\|(|-|({process_id}[^\|]+?))\|(|-|({process_name}[^\|]+?))\|(|-|({src_ip}[^\|]+?))\|(({src_port}\d+)|-|)"""
  ]
}
${WinParserTemplates.ibr-ad-template} {
  Name = ibr-ad-4648
  DataType = "windows-account-switch"
  Conditions = [ """ibr_ad""", """<custom_condition_cont-7495>""", """,4648,""" ]
  Fields = ${WinParserTemplates.ibr-ad-template.Fields} [
    """,Microsoft-Windows-Security-Auditing,[^\|]+\|(|-|({user}[^\|]+?))\|(|-|({domain}[^\|]+?))\|(|-|({logon_id}[^\|]+?))\|(|-|({guid}[^\|]+?))\|(|-|({account}[^\|]+?))\|(|-|({target_domain}[^\|]+?))\|(|-|({target_guid}[^\|]+?))\|(|-|({dest_host}[^\|]+?))\|(|-|({target_info}[^\|]+?))\|(|-|({process_id}[^\|]+?))\|(|-|({process_name}[^\|]+?))\|(|-|({src_ip}[^\|]+?))\|(({src_port}\d+)|-|)"""
  ]
}
${WinParserTemplates.ibr-ad-template} {
  Name = ibr-ad-4768
  DataType = "windows-4768"
  Conditions = [ """ibr_ad""", """<custom_condition_cont-7495>""", """,4768,""" ]
  Fields = ${WinParserTemplates.ibr-ad-template.Fields} [
    """,Microsoft-Windows-Security-Auditing,[^\|]+\|(|-|({domain}[^\|]+?))\|(|-|({user_sid}[^\|]+?))\|(|-|({dest_host}[^\|]+?))\|(|-|({service_sid}[^\|]+?))\|(|-|({ticket_options}[^\|]+?))\|(|-|({result_code}[^\|]+?))\|(|-|({encryption_type}[^\|]+?))\|(|-|({auth_type}[^\|]+?))\|(|-|({dest_ip}[^\|]+?))\|(({dest_port}\d+)|-|)"""
  ]
}
${WinParserTemplates.ibr-ad-template} {
  Name = ibr-ad-4769
  DataType = "windows-4769"
  Conditions = [ """ibr_ad""", """<custom_condition_cont-7495>""", """,4769,""" ]
  Fields = ${WinParserTemplates.ibr-ad-template.Fields} [
    """,Microsoft-Windows-Security-Auditing,[^\|]+\|(|-|({domain}[^\|]+?))\|(|-|({dest_host}[^\|]+?))\|(|-|({service_sid}[^\|]+?))\|(|-|({ticket_options}[^\|]+?))\|(|-|({encryption_type}[^\|]+?))\|(|-|({src_ip}[^\|]+?))\|(|-|({src_port}[^\|]+?))\|(|-|({result_code}[^\|]+?))\|(|-|({logon_guid}[^\|]+?))\|"""
  ]
}
${WinParserTemplates.ibr-ad-template} {
  Name = ibr-ad-4770
  DataType = "windows-4770"
  Conditions = [ """ibr_ad""", """<custom_condition_cont-7495>""", """,4770,""" ]
  Fields = ${WinParserTemplates.ibr-ad-template.Fields} [
    """,Microsoft-Windows-Security-Auditing,[^\|]+\|(|-|({domain}[^\|]+?))\|(|-|({service_name}[^\|]+?))\|(|-|({service_sid}[^\|]+?))\|(|-|({ticket_options}[^\|]+?))\|(|-|({encryption_type}[^\|]+?))\|(|-|({src_ip}[^\|]+?))\|(({src_port}\d+)|-|)"""
  ]
}
${WinParserTemplates.ibr-ad-template} {
  Name = ibr-ad-4771
  DataType = "usb-activity"
  Conditions = [ """ibr_ad""", """<custom_condition_cont-7495>""", """,4771,""" ]
  Fields = ${WinParserTemplates.ibr-ad-template.Fields} [
    """,Microsoft-Windows-Security-Auditing,[^\|]+\|(|-|({user_sid}[^\|]+?))\|(|-|({service_name}[^\|]+?))\|(|-|({ticket_options}[^\|]+?))\|(|-|({result_code}[^\|]+?))\|(|-|({auth_type}[^\|]+?))\|(|-|({src_ip}[^\|]+?))\|(({src_port}\d+)|-|)"""
  ]
}

 {
   Name = win-powershell-command
   Vendor = Microsoft
   Product = Microsoft Windows
   Lms = Direct
   DataType = "process-created"
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
   Conditions = [  """>4103</EventID>""",   """CommandInvocation""",       """Script Name ="""    ]
   Fields = [
      """exabeam_host=({host}[\w\-.]+)""",
      """<TimeCreated SystemTime=\'({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z)\'\/>""",
      """>({event_code}4103)<\/EventID>""",
      """<Computer>({dest_host}.*?)<\/Computer>""",
      """<Security UserID='({user_sid}[\w-]+)'""",
      """Script Name =\s+({process}({directory}([\w:]+\\)?([^\\]+?\\)*?)({process_name}[^\\]*?))\s+Command Path =""",
      """User = (({domain}[^\\]+?)\\)?({user}[^\s]+)\s+Connected User =""",
      """CommandInvocation\(.+?\):\s*"({command_invocation}[^"]+)""",
      """value="*(?:function\s)?({command_module}[^\s"]+)"""
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