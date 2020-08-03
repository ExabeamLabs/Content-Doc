#### Parser Content
```Java
{
Name = emc-syslog-4740
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Syslog
  DataType = "windows-account-lockout"
  TimeFormat = "epoch"
  Conditions = [ "__li_source_path=", "A user account was locked out", """eventid="4740"""" ]
  Fields = [
    """({event_name}A user account was locked out)""",
    """\W__li_source_path="({host}[\w\.-]+)"""",
    """({event_code}4740)""",
    """\Weventrecordid="({record_id}\d+)"""",
    """Subject:.+?Account Name:\s+({caller_user}.+?)\s+Account Domain:\s+(?=\w)({caller_domain}.+?)\s+Logon ID:\s+({logon_id}[^\s]+)""",  
    """Locked Out:\s+Security ID:\s+(%\{)?({user_sid}([\w\d\-]+?)|([^\s]+))\}?\s+Account Name:\s+(?=\w)({user}.+?)\s+Additional""",
    """Caller Computer Name:\s+(\\+)?({src_host}[^\#\s",]+)"""    
  ]
  DupFields=[ "host->dest_host", "caller_domain->domain" ]
}
```