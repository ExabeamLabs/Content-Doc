#### Parser Content
```Java
{
Name = xml-1117
  Conditions = [ """<EventID>1117</EventID>""", """<Channel>Microsoft-Windows-Windows Defender/Operational</Channel>""", """<Data Name ='Product Name'>Microsoft Defender Antivirus</Data>""", """<Data Name ='Detection Time'>""" ]

microsoft-defender-av-alert = {
  Vendor = Microsoft
  Product = Defender Antivirus
  Lms = Syslog
  DataType = "security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,9}Z)'\/>""",
    """<Computer>({host}[^<]{1,2000})<\/Computer>""",
    """<EventID>({event_code}\d{1,100})<\/EventID>""",
    """<Security UserID='({user_sid}[^'>]{1,2000})'\/>""",
    """<Data Name ='Domain'>({domain}[^<]{1,2000})<\/Data>""",
    """<Data Name ='User'>({user}[^<]{1,2000})<\/Data>""",
    """<Data Name ='Detection User'>(({domain}[^\\<]{1,2000})\\)?({user}[^<]{1,2000})<\/Data>""",
    """<Data Name ='Severity ID'>({alert_severity}\d{1,100})<\/Data>""",
    """<Data Name ='Severity Name'>({alert_severity}[^<]{1,2000})<\/Data>""",
    """<Data Name ='Type Name'>({alert_type}[^<]{1,2000})<\/Data>""",
    """<Data Name ='Threat Name'>({alert_name}[^<]{1,2000})<\/Data>""",
    """<Data Name ='Threat ID'>({threat_id}\d{1,100})<\/Data>"""
  
}
```